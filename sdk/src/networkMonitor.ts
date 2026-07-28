import { StellarIdentityConfig } from './types';
import { Logger, LogLevel } from './logger';

export type AlertSeverity = 'info' | 'warning' | 'critical';

export type AlertChannelType = 'console' | 'webhook' | 'slack' | 'pagerduty' | 'email';

export interface AlertChannel {
  type: AlertChannelType;
  config: Record<string, string>;
  enabled: boolean;
}

export interface AlertThreshold {
  metricName: string;
  min?: number;
  max?: number;
  severity: AlertSeverity;
  cooldownMs: number;
}

export interface AlertEvent {
  id: string;
  timestamp: number;
  severity: AlertSeverity;
  channel: AlertChannelType;
  title: string;
  message: string;
  metricName: string;
  metricValue: number;
  threshold: AlertThreshold;
  acknowledged: boolean;
}

export interface TransactionMetrics {
  totalCount: number;
  successCount: number;
  failedCount: number;
  successRate: number;
  avgFee: number;
  minFee: number;
  maxFee: number;
  totalFees: number;
  avgGasUsed: number;
  totalGasUsed: number;
  periodStartMs: number;
  periodEndMs: number;
}

export interface ContractStateChange {
  contractId: string;
  functionName: string;
  timestamp: number;
  ledgerSequence: number;
  changes: Record<string, { oldValue: unknown; newValue: unknown }>;
}

export interface AnomalyResult {
  detected: boolean;
  metricName: string;
  currentValue: number;
  baselineValue: number;
  deviation: number;
  deviationThreshold: number;
  severity: AlertSeverity;
  recommendation: string;
}

export interface MonitorConfig {
  samplingIntervalMs: number;
  alertCooldownMs: number;
  anomalyWindowSize: number;
  gasCostWarningThreshold: number;
  successRateWarningThreshold: number;
  maxAnomalyDeviation: number;
  enabled: boolean;
}

export interface MonitorHealth {
  status: 'healthy' | 'degraded' | 'down';
  lastCheckMs: number;
  uptimeMs: number;
  totalAlerts: number;
  activeAlerts: number;
  metricsCollected: number;
  errors: string[];
}

const DEFAULT_MONITOR_CONFIG: MonitorConfig = {
  samplingIntervalMs: 60_000,
  alertCooldownMs: 300_000,
  anomalyWindowSize: 10,
  gasCostWarningThreshold: 100_000,
  successRateWarningThreshold: 0.95,
  maxAnomalyDeviation: 3.0,
  enabled: true,
};

export class NetworkMonitor {
  private config: StellarIdentityConfig;
  private monitorConfig: MonitorConfig;
  private logger: Logger;
  private channels: Map<AlertChannelType, AlertChannel> = new Map();
  private thresholds: AlertThreshold[] = [];
  private alertHistory: AlertEvent[] = [];
  private transactionMetrics: TransactionMetrics[] = [];
  private stateChanges: ContractStateChange[] = [];
  private baselineMetrics: Map<string, number[]> = new Map();
  private lastAlertTimestamps: Map<string, number> = new Map();
  private samplingTimer: ReturnType<typeof setInterval> | null = null;
  private startedAt: number = 0;
  private isRunning: boolean = false;
  private alertCounter: number = 0;

  constructor(config: StellarIdentityConfig, monitorConfig?: Partial<MonitorConfig>) {
    this.config = config;
    this.monitorConfig = { ...DEFAULT_MONITOR_CONFIG, ...monitorConfig };
    this.logger = new Logger('NetworkMonitor', LogLevel.INFO);

    this.addDefaultChannels();
    this.addDefaultThresholds();
  }

  private addDefaultChannels(): void {
    this.channels.set('console', {
      type: 'console',
      config: {},
      enabled: true,
    });
  }

  private addDefaultThresholds(): void {
    this.thresholds.push(
      {
        metricName: 'successRate',
        min: 0.95,
        severity: 'warning',
        cooldownMs: 300_000,
      },
      {
        metricName: 'avgGasCost',
        max: 100_000,
        severity: 'warning',
        cooldownMs: 300_000,
      },
      {
        metricName: 'failureRate',
        max: 0.05,
        severity: 'critical',
        cooldownMs: 120_000,
      },
      {
        metricName: 'totalFees',
        max: 10_000_000,
        severity: 'warning',
        cooldownMs: 600_000,
      },
    );
  }

  configureChannels(channels: AlertChannel[]): void {
    for (const channel of channels) {
      this.channels.set(channel.type, channel);
    }
  }

  configureThresholds(thresholds: AlertThreshold[]): void {
    for (const t of thresholds) {
      const existing = this.thresholds.findIndex((et) => et.metricName === t.metricName);
      if (existing >= 0) {
        this.thresholds[existing] = t;
      } else {
        this.thresholds.push(t);
      }
    }
  }

  start(): void {
    if (this.isRunning) return;
    if (!this.monitorConfig.enabled) return;

    this.isRunning = true;
    this.startedAt = Date.now();
    this.logger.info('NetworkMonitor started', { network: this.config.network });

    this.samplingTimer = setInterval(() => {
      this.collectMetrics().catch((err) => {
        this.logger.error('Metric collection failed', err);
      });
    }, this.monitorConfig.samplingIntervalMs);
  }

  stop(): void {
    this.isRunning = false;
    if (this.samplingTimer) {
      clearInterval(this.samplingTimer);
      this.samplingTimer = null;
    }
    this.logger.info('NetworkMonitor stopped');
  }

  recordTransaction(
    success: boolean,
    fee: number,
    gasUsed: number,
    contractId?: string,
    operationName?: string,
  ): void {
    const now = Date.now();
    const currentPeriod = this.getCurrentPeriod(now);

    if (
      this.transactionMetrics.length === 0 ||
      this.transactionMetrics[this.transactionMetrics.length - 1].periodEndMs < currentPeriod
    ) {
      if (
        this.transactionMetrics.length > 0 &&
        this.transactionMetrics[this.transactionMetrics.length - 1].periodEndMs >= currentPeriod - this.monitorConfig.samplingIntervalMs
      ) {
        const last = this.transactionMetrics[this.transactionMetrics.length - 1];
        this.finalizeMetricsPeriod(last, now);
      }

      this.transactionMetrics.push({
        totalCount: 0,
        successCount: 0,
        failedCount: 0,
        successRate: 1,
        avgFee: 0,
        minFee: Number.MAX_SAFE_INTEGER,
        maxFee: 0,
        totalFees: 0,
        avgGasUsed: 0,
        totalGasUsed: 0,
        periodStartMs: currentPeriod,
        periodEndMs: currentPeriod + this.monitorConfig.samplingIntervalMs,
      });
    }

    const idx = this.transactionMetrics.length - 1;
    const p = this.transactionMetrics[idx];
    p.totalCount++;
    if (success) p.successCount++;
    else p.failedCount++;
    p.totalFees += fee;
    p.totalGasUsed += gasUsed;
    p.avgFee = p.totalCount > 0 ? p.totalFees / p.totalCount : 0;
    p.avgGasUsed = p.totalCount > 0 ? p.totalGasUsed / p.totalCount : 0;
    p.minFee = Math.min(p.minFee, fee);
    p.maxFee = Math.max(p.maxFee, fee);
    p.successRate = p.totalCount > 0 ? p.successCount / p.totalCount : 1;
    p.periodEndMs = now;

    this.updateBaseline('successRate', p.successRate);
    this.updateBaseline('avgGasCost', p.avgGasUsed);
    this.updateBaseline('totalFees', p.totalFees);

    this.evaluateThresholds(
      {
        successRate: p.successRate,
        avgGasCost: p.avgGasUsed,
        failureRate: p.totalCount > 0 ? p.failedCount / p.totalCount : 0,
        totalFees: p.totalFees,
      },
      now,
    );

    if (contractId && operationName) {
      this.stateChanges.push({
        contractId,
        functionName: operationName,
        timestamp: now,
        ledgerSequence: 0,
        changes: {},
      });

      if (this.stateChanges.length > 1000) {
        this.stateChanges.splice(0, this.stateChanges.length - 1000);
      }
    }
  }

  private finalizeMetricsPeriod(metric: TransactionMetrics, now: number): void {
    metric.periodEndMs = now;
  }

  private getCurrentPeriod(now: number): number {
    return Math.floor(now / this.monitorConfig.samplingIntervalMs) * this.monitorConfig.samplingIntervalMs;
  }

  private updateBaseline(metricName: string, value: number): void {
    if (!this.baselineMetrics.has(metricName)) {
      this.baselineMetrics.set(metricName, []);
    }

    const values = this.baselineMetrics.get(metricName)!;
    values.push(value);

    if (values.length > this.monitorConfig.anomalyWindowSize) {
      values.shift();
    }
  }

  private getBaselineStats(metricName: string): { mean: number; std: number } | null {
    const values = this.baselineMetrics.get(metricName);
    if (!values || values.length < 3) return null;

    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length;
    const std = Math.sqrt(variance);

    return { mean, std };
  }

  detectAnomaly(metricName: string, currentValue: number): AnomalyResult {
    const stats = this.getBaselineStats(metricName);
    if (!stats || stats.std === 0) {
      return {
        detected: false,
        metricName,
        currentValue,
        baselineValue: stats?.mean ?? currentValue,
        deviation: 0,
        deviationThreshold: this.monitorConfig.maxAnomalyDeviation,
        severity: 'info',
        recommendation: 'Insufficient baseline data for anomaly detection.',
      };
    }

    const deviation = Math.abs(currentValue - stats.mean) / stats.std;
    const detected = deviation > this.monitorConfig.maxAnomalyDeviation;

    let severity: AlertSeverity = 'info';
    let recommendation: string;

    if (detected) {
      if (deviation > this.monitorConfig.maxAnomalyDeviation * 2) {
        severity = 'critical';
        recommendation = `Immediate investigation required: ${metricName} deviated ${deviation.toFixed(2)} sigma from baseline.`;
      } else {
        severity = 'warning';
        recommendation = `Review ${metricName} - currently ${deviation.toFixed(2)} sigma from baseline (threshold: ${this.monitorConfig.maxAnomalyDeviation}).`;
      }
    } else {
      recommendation = `Within normal range (${deviation.toFixed(2)} sigma).`;
    }

    return {
      detected,
      metricName,
      currentValue,
      baselineValue: stats.mean,
      deviation,
      deviationThreshold: this.monitorConfig.maxAnomalyDeviation,
      severity,
      recommendation,
    };
  }

  private evaluateThresholds(metrics: Record<string, number>, now: number): void {
    for (const threshold of this.thresholds) {
      const value = metrics[threshold.metricName];
      if (value === undefined) continue;

      let breached = false;
      if (threshold.min !== undefined && value < threshold.min) breached = true;
      if (threshold.max !== undefined && value > threshold.max) breached = true;

      if (!breached) continue;

      const cooldownKey = `${threshold.metricName}_${threshold.severity}`;
      const lastAlert = this.lastAlertTimestamps.get(cooldownKey) ?? 0;
      if (now - lastAlert < threshold.cooldownMs) continue;

      this.lastAlertTimestamps.set(cooldownKey, now);
      this.emitAlert(threshold, value, now);
    }
  }

  private emitAlert(threshold: AlertThreshold, value: number, timestamp: number): void {
    this.alertCounter++;
    const alertId = `alert_${this.alertCounter}_${timestamp}`;
    const anomaly = this.detectAnomaly(threshold.metricName, value);

    for (const channel of this.channels.values()) {
      if (!channel.enabled) continue;

      const alert: AlertEvent = {
        id: alertId,
        timestamp,
        severity: threshold.severity,
        channel: channel.type,
        title: `[${threshold.severity.toUpperCase()}] ${threshold.metricName} threshold breached`,
        message: `Metric "${threshold.metricName}" is ${value} (threshold: ${threshold.min ?? `> ${threshold.max}`}). ${anomaly.recommendation}`,
        metricName: threshold.metricName,
        metricValue: value,
        threshold,
        acknowledged: false,
      };

      this.alertHistory.push(alert);
      this.sendAlert(channel, alert);
    }
  }

  private async sendAlert(channel: AlertChannel, alert: AlertEvent): Promise<void> {
    switch (channel.type) {
      case 'console':
        this.logger.warn(alert.message, {
          alertId: alert.id,
          severity: alert.severity,
          metricName: alert.metricName,
          metricValue: alert.metricValue,
        });
        break;

      case 'webhook':
        try {
          await fetch(channel.config.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(alert),
          });
        } catch (err) {
          this.logger.error('Webhook alert delivery failed', err);
        }
        break;

      case 'slack':
        try {
          const slackMessage = {
            text: `*${alert.title}*\n${alert.message}\nSeverity: ${alert.severity}\nTime: ${new Date(alert.timestamp).toISOString()}`,
          };
          await fetch(channel.config.webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(slackMessage),
          });
        } catch (err) {
          this.logger.error('Slack alert delivery failed', err);
        }
        break;

      case 'pagerduty':
        try {
          const pdPayload = {
            routing_key: channel.config.routingKey,
            event_action: 'trigger',
            dedup_key: alert.id,
            payload: {
              summary: alert.title,
              severity: alert.severity === 'critical' ? 'critical' : 'warning',
              source: `stellar-network-${this.config.network}`,
              timestamp: new Date(alert.timestamp).toISOString(),
              custom_details: alert,
            },
          };
          await fetch(channel.config.url ?? 'https://events.pagerduty.com/v2/enqueue', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(pdPayload),
          });
        } catch (err) {
          this.logger.error('PagerDuty alert delivery failed', err);
        }
        break;

      case 'email':
        this.logger.info('Email alert (requires SMTP configuration)', {
          to: channel.config.to,
          subject: alert.title,
        });
        break;
    }
  }

  acknowledgeAlert(alertId: string): void {
    const alert = this.alertHistory.find((a) => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
    }
  }

  async collectMetrics(): Promise<TransactionMetrics | null> {
    if (this.transactionMetrics.length === 0) return null;
    return this.transactionMetrics[this.transactionMetrics.length - 1];
  }

  getTransactionMetrics(periodCount?: number): TransactionMetrics[] {
    if (periodCount) {
      return this.transactionMetrics.slice(-periodCount);
    }
    return [...this.transactionMetrics];
  }

  getCurrentMetrics(): TransactionMetrics | null {
    if (this.transactionMetrics.length === 0) return null;
    return this.transactionMetrics[this.transactionMetrics.length - 1];
  }

  getStateChanges(contractId?: string, limit?: number): ContractStateChange[] {
    let filtered = this.stateChanges;
    if (contractId) {
      filtered = filtered.filter((c) => c.contractId === contractId);
    }
    if (limit) {
      return filtered.slice(-limit);
    }
    return [...filtered];
  }

  getAlerts(severity?: AlertSeverity, limit?: number): AlertEvent[] {
    let filtered = this.alertHistory;
    if (severity) {
      filtered = filtered.filter((a) => a.severity === severity);
    }
    if (limit) {
      return filtered.slice(-limit);
    }
    return [...filtered];
  }

  getActiveAlerts(): AlertEvent[] {
    return this.alertHistory.filter((a) => !a.acknowledged);
  }

  getAnomalies(metricName?: string): AnomalyResult[] {
    const results: AnomalyResult[] = [];

    const metrics = this.getCurrentMetrics();
    if (!metrics) return results;

    const metricNames = metricName ? [metricName] : ['successRate', 'avgGasCost', 'totalFees'];

    for (const name of metricNames) {
      let value: number;
      switch (name) {
        case 'successRate': value = metrics.successRate; break;
        case 'avgGasCost': value = metrics.avgGasUsed; break;
        case 'totalFees': value = metrics.totalFees; break;
        default: continue;
      }

      results.push(this.detectAnomaly(name, value));
    }

    return results;
  }

  getHealth(): MonitorHealth {
    const now = Date.now();
    const uptimeMs = this.startedAt > 0 ? now - this.startedAt : 0;
    const activeAlerts = this.getActiveAlerts().length;
    const errors = [];

    if (!this.isRunning) {
      errors.push('Monitor is not running');
    }

    const status: MonitorHealth['status'] = errors.length > 0
      ? 'degraded'
      : activeAlerts > 5
        ? 'degraded'
        : 'healthy';

    return {
      status,
      lastCheckMs: now,
      uptimeMs,
      totalAlerts: this.alertHistory.length,
      activeAlerts,
      metricsCollected: this.transactionMetrics.length,
      errors,
    };
  }

  resetMetrics(): void {
    this.transactionMetrics = [];
    this.stateChanges = [];
    this.baselineMetrics.clear();
    this.alertHistory = [];
    this.lastAlertTimestamps.clear();
    this.logger.info('NetworkMonitor metrics reset');
  }

  getMonitorConfig(): MonitorConfig {
    return { ...this.monitorConfig };
  }

  updateMonitorConfig(updates: Partial<MonitorConfig>): void {
    this.monitorConfig = { ...this.monitorConfig, ...updates };
    this.logger.info('Monitor config updated', { updates });
  }
}

export default NetworkMonitor;
