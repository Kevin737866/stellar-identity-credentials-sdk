/**
 * regulatoryReporting.ts — Regulatory Reporting SDK layer
 *
 * Covers:
 *   - Report template management (CRUD)
 *   - Transaction reporting for financial regulators
 *   - Suspicious Activity Report (SAR) generation
 *   - Report scheduling and automation
 *   - Audit trail export (JSON, CSV)
 *   - Report export with content hashing for integrity
 *
 * Regional: FATF, MiCA, FINCEN, GDPR
 */

import {
  SorobanRpc,
  TransactionBuilder,
  Networks,
  Keypair,
  Contract,
  Address,
  xdr,
  nativeToScVal,
  scValToNative,
} from 'stellar-sdk';
import { StellarIdentityConfig } from './types';
import { StellarIdentityError, ComplianceError, ErrorCode } from './errors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TemplateSection {
  title: string;
  description: string;
  fields: string[];
  required: boolean;
  order: number;
}

export interface ReportTemplate {
  id: string;
  name: string;
  jurisdiction: string;
  version: number;
  sections: TemplateSection[];
  tags: string[];
  active: boolean;
  created: number;
  updated: number;
}

export interface ReportField {
  name: string;
  value: string;
}

export interface ReportSection {
  title: string;
  fields: ReportField[];
}

export interface RegulatoryReport {
  id: string;
  templateId: string;
  subject: string;
  reporter: string;
  sections: ReportSection[];
  riskScore: number;
  status: string;
  generatedAt: number;
  ledgerSequence: number;
  tags: string[];
}

export interface SARReport {
  id: string;
  subject: string;
  filer: string;
  activityType: string;
  description: string;
  relatedTransactions: string[];
  estimatedValue: string;
  currency: string;
  status: 'draft' | 'filed' | 'acknowledged' | 'closed';
  notifyRegulators: string[];
  evidenceHashes: string[];
  filedAt: number;
  activityTimestamp: number;
  ledgerSequence: number;
}

export interface ReportSchedule {
  id: string;
  templateId: string;
  subject: string | null;
  intervalSeconds: number;
  nextRunAt: number;
  lastRunAt: number | null;
  exportFormats: string[];
  active: boolean;
  createdBy: string;
  createdAt: number;
}

export interface TransactionReport {
  id: string;
  subject: string;
  transactionCount: number;
  totalVolume: number;
  periodStart: number;
  periodEnd: number;
  asset: string;
  avgTransactionSize: number;
  maxTransactionSize: number;
  suspiciousCount: number;
  exceedsThreshold: boolean;
  generatedAt: number;
  ledgerSequence: number;
}

export interface ExportSnapshot {
  subject: string;
  snapshotAt: number;
  format: 'json' | 'csv' | 'pdf';
  contentHash: string;
  entryCount: number;
  ledgerSequence: number;
}

export interface PaginatedReports {
  data: RegulatoryReport[];
  page: number;
  total: number;
  hasMore: boolean;
}

export interface PaginatedSARs {
  data: SARReport[];
  page: number;
  total: number;
  hasMore: boolean;
}

export interface ReportStatistics {
  templates: number;
  reports: number;
  sars: number;
}

/** Supported export formats */
export type ExportFormat = 'json' | 'csv' | 'pdf';

// ---------------------------------------------------------------------------
// Default report templates (pre-defined for key jurisdictions)
// ---------------------------------------------------------------------------

export const DEFAULT_TEMPLATES: Omit<ReportTemplate, 'version' | 'active' | 'created' | 'updated'>[] = [
  {
    id: 'FATF_TRAVEL_RULE',
    name: 'FATF Travel Rule Report',
    jurisdiction: 'FATF',
    sections: [
      {
        title: 'Transfer Details',
        description: 'Core transfer information',
        fields: ['amount', 'asset', 'timestamp', 'transactionRef'],
        required: true,
        order: 0,
      },
      {
        title: 'Originator Information',
        description: 'Originator identity details',
        fields: ['originatorName', 'originatorAccount', 'originatorVASP'],
        required: true,
        order: 1,
      },
      {
        title: 'Beneficiary Information',
        description: 'Beneficiary identity details',
        fields: ['beneficiaryName', 'beneficiaryAccount', 'beneficiaryVASP'],
        required: true,
        order: 2,
      },
      {
        title: 'Risk Assessment',
        description: 'Sanctions screening and risk analysis',
        fields: ['senderRiskScore', 'receiverRiskScore', 'sanctionsMatches', 'riskFlags'],
        required: true,
        order: 3,
      },
    ],
    tags: ['travel-rule', 'fatf', 'vasp-transfer'],
  },
  {
    id: 'MICA_QUARTERLY',
    name: 'MiCA Quarterly Compliance Report',
    jurisdiction: 'MiCA',
    sections: [
      {
        title: 'Trading Summary',
        description: 'Quarterly trading activity summary',
        fields: ['totalTransactions', 'totalVolume', 'uniqueCounterparties', 'avgTradeSize'],
        required: true,
        order: 0,
      },
      {
        title: 'Customer Due Diligence',
        description: 'CDD/KYC statistics',
        fields: ['totalCustomers', 'kycVerified', 'highRiskCustomers', 'pepIdentified'],
        required: true,
        order: 1,
      },
      {
        title: 'Incident Report',
        description: 'Security and compliance incidents',
        fields: ['securityIncidents', 'dataBreaches', 'suspiciousActivitiesReported', 'regulatoryInquiries'],
        required: true,
        order: 2,
      },
    ],
    tags: ['mica', 'quarterly', 'eu-regulation'],
  },
  {
    id: 'FINCEN_SAR',
    name: 'FINCEN Suspicious Activity Report',
    jurisdiction: 'FINCEN',
    sections: [
      {
        title: 'Subject Information',
        description: 'Subject of the suspicious activity',
        fields: ['subjectName', 'subjectAddress', 'subjectAccountType', 'identificationDocument'],
        required: true,
        order: 0,
      },
      {
        title: 'Suspicious Activity',
        description: 'Detailed description of suspicious activity',
        fields: ['activityType', 'activityDescription', 'dateFirstDetected', 'amountInvolved', 'currency'],
        required: true,
        order: 1,
      },
      {
        title: 'Filing Institution',
        description: 'Filing financial institution details',
        fields: ['institutionName', 'institutionAddress', 'contactOfficer', 'filingDate'],
        required: true,
        order: 2,
      },
      {
        title: 'Law Enforcement',
        description: 'Law enforcement contact information',
        fields: ['agencyNotified', 'caseNumber', 'supportingDocuments'],
        required: false,
        order: 3,
      },
    ],
    tags: ['suspicious-activity', 'fincen', 'law-enforcement'],
  },
  {
    id: 'GDPR_COMPLIANCE',
    name: 'GDPR Data Protection Report',
    jurisdiction: 'GDPR',
    sections: [
      {
        title: 'Data Processing',
        description: 'Personal data processing activities',
        fields: ['dataCategories', 'processingPurposes', 'dataSubjects', 'retentionPeriod'],
        required: true,
        order: 0,
      },
      {
        title: 'Data Subject Requests',
        description: 'DSAR and right-to-erasure requests',
        fields: ['accessRequests', 'erasureRequests', 'rectificationRequests', 'portabilityRequests'],
        required: true,
        order: 1,
      },
      {
        title: 'Data Breaches',
        description: 'Data breach notifications',
        fields: ['breachesReported', 'breachesResolved', 'supervisoryAuthorityNotified', 'affectedDataSubjects'],
        required: true,
        order: 2,
      },
    ],
    tags: ['gdpr', 'data-protection', 'privacy'],
  },
  {
    id: 'TXN_RPT',
    name: 'Transaction Activity Report',
    jurisdiction: 'GENERAL',
    sections: [
      {
        title: 'Transaction Report',
        description: 'Transaction activity for regulatory reporting',
        fields: ['transactionCount', 'totalVolume', 'periodStart', 'periodEnd', 'asset', 'avgTransactionSize', 'maxTransactionSize', 'suspiciousCount', 'exceedsThreshold'],
        required: true,
        order: 0,
      },
    ],
    tags: ['transaction', 'reporting'],
  },
];

// ---------------------------------------------------------------------------
// RegulatoryReportingClient
// ---------------------------------------------------------------------------

export class RegulatoryReportingClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private contract: Contract;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl ?? this.defaultRpcUrl());
    this.contract = new Contract(config.contracts.complianceFilter);
  }

  // -------------------------------------------------------------------------
  // Template management
  // -------------------------------------------------------------------------

  /**
   * Register a new report template on-chain.
   */
  async registerTemplate(
    adminKeypair: Keypair,
    id: string,
    name: string,
    jurisdiction: string,
    sections: TemplateSection[],
    tags: string[],
  ): Promise<void> {
    const account = await this.rpc.getAccount(adminKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'register_template',
          xdr.ScVal.scvAddress(new Address(adminKeypair.publicKey()).toScAddress()),
          nativeToScVal(enc(id), { type: 'bytes' }),
          nativeToScVal(enc(name), { type: 'bytes' }),
          nativeToScVal(enc(jurisdiction), { type: 'bytes' }),
          nativeToScVal(this.sectionsToScVal(sections), { type: 'vec' }),
          nativeToScVal(tags.map(t => enc(t)), { type: 'vec' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(adminKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`register_template failed: ${result.errorResult}`);
  }

  /**
   * Get a template by ID from on-chain or fall back to defaults.
   */
  async getTemplate(id: string): Promise<ReportTemplate | null> {
    // Try on-chain first
    try {
      const val = await this.simulateRead('get_template', [
        nativeToScVal(enc(id), { type: 'bytes' }),
      ]);
      const raw = scValToNative(val) as Record<string, unknown> | null;
      if (raw) return this.parseTemplate(raw);
    } catch {
      // Fall through to defaults
    }

    // Fallback: return default template
    const def = DEFAULT_TEMPLATES.find(t => t.id === id);
    if (!def) return null;
    return {
      ...def,
      version: 1,
      active: true,
      created: Date.now(),
      updated: Date.now(),
    };
  }

  /**
   * Get all available report templates.
   */
  async getAllTemplates(): Promise<ReportTemplate[]> {
    try {
      const val = await this.simulateRead('get_all_template_ids', []);
      const ids = scValToNative(val) as string[];
      if (!Array.isArray(ids)) return DEFAULT_TEMPLATES.map(t => ({ ...t, version: 1, active: true, created: 0, updated: 0 }));
      const templates = await Promise.all(ids.map(id => this.getTemplate(id)));
      return templates.filter(Boolean) as ReportTemplate[];
    } catch {
      return DEFAULT_TEMPLATES.map(t => ({ ...t, version: 1, active: true, created: 0, updated: 0 }));
    }
  }

  // -------------------------------------------------------------------------
  // Report generation
  // -------------------------------------------------------------------------

  /**
   * Generate a regulatory report using a template.
   */
  async generateReport(
    reporterKeypair: Keypair,
    templateId: string,
    subject: string,
    sections: ReportSection[],
    riskScore: number,
    tags: string[],
  ): Promise<string> {
    const account = await this.rpc.getAccount(reporterKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'generate_report',
          xdr.ScVal.scvAddress(new Address(reporterKeypair.publicKey()).toScAddress()),
          nativeToScVal(enc(templateId), { type: 'bytes' }),
          xdr.ScVal.scvAddress(new Address(subject).toScAddress()),
          nativeToScVal(this.reportSectionsToScVal(sections), { type: 'vec' }),
          nativeToScVal(BigInt(riskScore), { type: 'u32' }),
          nativeToScVal(tags.map(t => enc(t)), { type: 'vec' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(reporterKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`generate_report failed: ${result.errorResult}`);

    return `RPT:${templateId}:${subject}:${Date.now()}`;
  }

  /**
   * Get reports for a subject, paginated.
   */
  async getReports(subject: string, page = 0, pageSize = 10): Promise<PaginatedReports> {
    try {
      const val = await this.simulateRead('get_reports_paginated', [
        xdr.ScVal.scvAddress(new Address(subject).toScAddress()),
        nativeToScVal(BigInt(page), { type: 'u32' }),
        nativeToScVal(BigInt(pageSize), { type: 'u32' }),
      ]);
      const raw = scValToNative(val) as Record<string, unknown>;
      return {
        data: Array.isArray(raw.data)
          ? (raw.data as unknown[]).map(r => this.parseReport(r as Record<string, unknown>))
          : [],
        page: Number(raw.page ?? page),
        total: Number(raw.total ?? 0),
        hasMore: Boolean(raw.has_more),
      };
    } catch {
      return { data: [], page, total: 0, hasMore: false };
    }
  }

  // -------------------------------------------------------------------------
  // Transaction reporting
  // -------------------------------------------------------------------------

  /**
   * File a transaction report for financial regulators.
   */
  async fileTransactionReport(
    reporterKeypair: Keypair,
    subject: string,
    transactionCount: number,
    totalVolume: number,
    periodStart: number,
    periodEnd: number,
    asset: string,
    avgTransactionSize: number,
    maxTransactionSize: number,
    suspiciousCount: number,
  ): Promise<TransactionReport> {
    const account = await this.rpc.getAccount(reporterKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'file_transaction_report',
          xdr.ScVal.scvAddress(new Address(reporterKeypair.publicKey()).toScAddress()),
          xdr.ScVal.scvAddress(new Address(subject).toScAddress()),
          nativeToScVal(BigInt(transactionCount), { type: 'u32' }),
          nativeToScVal(BigInt(totalVolume), { type: 'u64' }),
          nativeToScVal(BigInt(periodStart), { type: 'u64' }),
          nativeToScVal(BigInt(periodEnd), { type: 'u64' }),
          nativeToScVal(enc(asset), { type: 'bytes' }),
          nativeToScVal(BigInt(avgTransactionSize), { type: 'u64' }),
          nativeToScVal(BigInt(maxTransactionSize), { type: 'u64' }),
          nativeToScVal(BigInt(suspiciousCount), { type: 'u32' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(reporterKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`file_transaction_report failed: ${result.errorResult}`);

    return {
      id: `TXN_RPT:${subject}:${Date.now()}`,
      subject,
      transactionCount,
      totalVolume,
      periodStart,
      periodEnd,
      asset,
      avgTransactionSize,
      maxTransactionSize,
      suspiciousCount,
      exceedsThreshold: totalVolume >= 10_000_000_000,
      generatedAt: Date.now(),
      ledgerSequence: 0,
    };
  }

  // -------------------------------------------------------------------------
  // SAR (Suspicious Activity Report)
  // -------------------------------------------------------------------------

  /**
   * File a Suspicious Activity Report (SAR).
   */
  async fileSAR(
    filerKeypair: Keypair,
    params: {
      subject: string;
      activityType: string;
      description: string;
      relatedTransactions: string[];
      estimatedValue: string;
      currency: string;
      notifyRegulators: string[];
      evidenceHashes: string[];
      activityTimestamp: number;
    },
  ): Promise<SARReport> {
    const account = await this.rpc.getAccount(filerKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'file_sar',
          xdr.ScVal.scvAddress(new Address(filerKeypair.publicKey()).toScAddress()),
          xdr.ScVal.scvAddress(new Address(params.subject).toScAddress()),
          nativeToScVal(enc(params.activityType), { type: 'bytes' }),
          nativeToScVal(enc(params.description), { type: 'bytes' }),
          nativeToScVal(params.relatedTransactions.map(t => enc(t)), { type: 'vec' }),
          nativeToScVal(enc(params.estimatedValue), { type: 'bytes' }),
          nativeToScVal(enc(params.currency), { type: 'bytes' }),
          nativeToScVal(params.notifyRegulators.map(r => enc(r)), { type: 'vec' }),
          nativeToScVal(params.evidenceHashes.map(h => Buffer.from(h, 'hex')), { type: 'vec' }),
          nativeToScVal(BigInt(params.activityTimestamp), { type: 'u64' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(filerKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`file_sar failed: ${result.errorResult}`);

    return {
      id: `SAR:${params.subject}:${Date.now()}`,
      subject: params.subject,
      filer: filerKeypair.publicKey(),
      activityType: params.activityType,
      description: params.description,
      relatedTransactions: params.relatedTransactions,
      estimatedValue: params.estimatedValue,
      currency: params.currency,
      status: 'filed',
      notifyRegulators: params.notifyRegulators,
      evidenceHashes: params.evidenceHashes,
      filedAt: Date.now(),
      activityTimestamp: params.activityTimestamp,
      ledgerSequence: 0,
    };
  }

  /**
   * Get a SAR by ID.
   */
  async getSAR(sarId: string): Promise<SARReport | null> {
    try {
      const val = await this.simulateRead('get_sar', [
        nativeToScVal(enc(sarId), { type: 'bytes' }),
      ]);
      const raw = scValToNative(val) as Record<string, unknown> | null;
      if (!raw) return null;
      return this.parseSAR(raw);
    } catch {
      return null;
    }
  }

  /**
   * Get paginated SARs.
   */
  async getSARs(page = 0, pageSize = 10): Promise<PaginatedSARs> {
    try {
      const val = await this.simulateRead('get_sars_paginated', [
        nativeToScVal(BigInt(page), { type: 'u32' }),
        nativeToScVal(BigInt(pageSize), { type: 'u32' }),
      ]);
      const raw = scValToNative(val) as Record<string, unknown>;
      return {
        data: Array.isArray(raw.data)
          ? (raw.data as unknown[]).map(r => this.parseSAR(r as Record<string, unknown>))
          : [],
        page: Number(raw.page ?? page),
        total: Number(raw.total ?? 0),
        hasMore: Boolean(raw.has_more),
      };
    } catch {
      return { data: [], page, total: 0, hasMore: false };
    }
  }

  // -------------------------------------------------------------------------
  // Report scheduling
  // -------------------------------------------------------------------------

  /**
   * Schedule automated report generation.
   */
  async scheduleReport(
    creatorKeypair: Keypair,
    scheduleId: string,
    templateId: string,
    subject: string | null,
    intervalSeconds: number,
    exportFormats: ExportFormat[],
  ): Promise<void> {
    const account = await this.rpc.getAccount(creatorKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'schedule_report',
          xdr.ScVal.scvAddress(new Address(creatorKeypair.publicKey()).toScAddress()),
          nativeToScVal(enc(scheduleId), { type: 'bytes' }),
          nativeToScVal(enc(templateId), { type: 'bytes' }),
          subject
            ? xdr.ScVal.scvAddress(new Address(subject).toScAddress())
            : xdr.ScVal.scvVoid(),
          nativeToScVal(BigInt(intervalSeconds), { type: 'u64' }),
          nativeToScVal(exportFormats.map(f => enc(f)), { type: 'vec' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(creatorKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`schedule_report failed: ${result.errorResult}`);
  }

  /**
   * Cancel a scheduled report.
   */
  async cancelSchedule(callerKeypair: Keypair, scheduleId: string): Promise<void> {
    const account = await this.rpc.getAccount(callerKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'cancel_schedule',
          xdr.ScVal.scvAddress(new Address(callerKeypair.publicKey()).toScAddress()),
          nativeToScVal(enc(scheduleId), { type: 'bytes' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(callerKeypair);
    await this.rpc.sendTransaction(prepared);
  }

  /**
   * Get all scheduled reports.
   */
  async getSchedules(): Promise<string[]> {
    try {
      const val = await this.simulateRead('get_all_schedule_ids', []);
      const raw = scValToNative(val);
      return Array.isArray(raw) ? (raw as unknown[]).map(dec) : [];
    } catch {
      return [];
    }
  }

  // -------------------------------------------------------------------------
  // Export
  // -------------------------------------------------------------------------

  /**
   * Export a report to the specified format.
   * Returns the export content as a string and records the hash on-chain.
   */
  async exportReport(
    reporterKeypair: Keypair,
    subject: string,
    report: RegulatoryReport | SARReport | TransactionReport,
    format: ExportFormat,
  ): Promise<{ content: string; hash: string }> {
    let content: string;
    switch (format) {
      case 'json':
        content = JSON.stringify(report, null, 2);
        break;
      case 'csv':
        content = this.toCSV(report);
        break;
      case 'pdf':
        // PDF generation requires a library; return JSON wrapped for now
        content = JSON.stringify({ pdf_payload: report, generated_at: new Date().toISOString() }, null, 2);
        break;
      default:
        throw this.err(`Unsupported format: ${format}`);
    }

    const hash = await sha256Hex(content);

    // Record export snapshot on-chain for integrity
    try {
      const account = await this.rpc.getAccount(reporterKeypair.publicKey());
      const hashBytes = Buffer.from(hash, 'hex');
      const tx = new TransactionBuilder(account, {
        fee: '100',
        networkPassphrase: this.networkPassphrase(),
      })
        .addOperation(
          this.contract.call(
            'record_export_snapshot',
            xdr.ScVal.scvAddress(new Address(reporterKeypair.publicKey()).toScAddress()),
            xdr.ScVal.scvAddress(new Address(subject).toScAddress()),
            nativeToScVal(enc(format), { type: 'bytes' }),
            nativeToScVal(hashBytes, { type: 'bytes' }),
            nativeToScVal(BigInt(1), { type: 'u32' }),
          ),
        )
        .setTimeout(30)
        .build();
      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(reporterKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch {
      // On-chain recording is best-effort
    }

    return { content, hash };
  }

  /**
   * Export the full audit trail for a subject.
   */
  async exportAuditTrail(
    subject: string,
    auditEntries: Array<{ action: string; timestamp: number; detail: string; ledgerSequence?: number }>,
    format: ExportFormat = 'json',
  ): Promise<string> {
    const exportData = {
      subject,
      exportedAt: new Date().toISOString(),
      totalEntries: auditEntries.length,
      entries: auditEntries.map(entry => ({
        action: entry.action,
        timestamp: new Date(entry.timestamp * 1000).toISOString(),
        detail: entry.detail,
        ledgerSequence: entry.ledgerSequence ?? null,
      })),
    };

    switch (format) {
      case 'json':
        return JSON.stringify(exportData, null, 2);
      case 'csv': {
        const header = 'Action,Timestamp,Detail,LedgerSequence\n';
        const rows = auditEntries.map(e =>
          `"${e.action}","${new Date(e.timestamp * 1000).toISOString()}","${e.detail}",${e.ledgerSequence ?? ''}`
        ).join('\n');
        return header + rows;
      }
      case 'pdf':
        return JSON.stringify({ pdf_payload: exportData, generated_at: new Date().toISOString() }, null, 2);
      default:
        return JSON.stringify(exportData, null, 2);
    }
  }

  /**
   * Get export snapshots for a subject.
   */
  async getExportSnapshots(subject: string): Promise<ExportSnapshot[]> {
    try {
      const val = await this.simulateRead('get_export_snapshots', [
        xdr.ScVal.scvAddress(new Address(subject).toScAddress()),
      ]);
      const raw = scValToNative(val);
      if (!Array.isArray(raw)) return [];
      return (raw as unknown[]).map((ts: unknown) => ({
        subject,
        snapshotAt: Number(ts),
        format: 'json' as const,
        contentHash: '',
        entryCount: 0,
        ledgerSequence: 0,
      }));
    } catch {
      return [];
    }
  }

  // -------------------------------------------------------------------------
  // Statistics
  // -------------------------------------------------------------------------

  /**
   * Get reporting statistics.
   */
  async getStatistics(): Promise<ReportStatistics> {
    try {
      const val = await this.simulateRead('get_statistics', []);
      const raw = scValToNative(val) as Map<string, number> | Record<string, unknown> | null;
      if (!raw) return { templates: DEFAULT_TEMPLATES.length, reports: 0, sars: 0 };

      // Handle Soroban Map response
      const obj = raw as Record<string, unknown>;
      return {
        templates: Number(obj.templates ?? DEFAULT_TEMPLATES.length),
        reports: Number(obj.reports ?? 0),
        sars: Number(obj.sars ?? 0),
      };
    } catch {
      return { templates: DEFAULT_TEMPLATES.length, reports: 0, sars: 0 };
    }
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private sectionsToScVal(sections: TemplateSection[]): unknown[] {
    return sections.map(s => ({
      title: enc(s.title),
      description: enc(s.description),
      fields: s.fields.map(f => enc(f)),
      required: s.required,
      order: s.order,
    }));
  }

  private reportSectionsToScVal(sections: ReportSection[]): unknown[] {
    return sections.map(s => ({
      title: enc(s.title),
      fields: s.fields.map(f => ({
        name: enc(f.name),
        value: enc(f.value),
      })),
    }));
  }

  private parseTemplate(raw: Record<string, unknown>): ReportTemplate {
    return {
      id: dec(raw.id),
      name: dec(raw.name),
      jurisdiction: dec(raw.jurisdiction),
      version: Number(raw.version ?? 1),
      sections: Array.isArray(raw.sections)
        ? (raw.sections as unknown[]).map((s: unknown) => {
            const sec = s as Record<string, unknown>;
            return {
              title: dec(sec.title),
              description: dec(sec.description),
              fields: Array.isArray(sec.fields) ? (sec.fields as unknown[]).map(dec) : [],
              required: Boolean(sec.required),
              order: Number(sec.order ?? 0),
            };
          })
        : [],
      tags: Array.isArray(raw.tags) ? (raw.tags as unknown[]).map(dec) : [],
      active: Boolean(raw.active),
      created: Number(raw.created ?? 0),
      updated: Number(raw.updated ?? 0),
    };
  }

  private parseReport(raw: Record<string, unknown>): RegulatoryReport {
    return {
      id: dec(raw.id),
      templateId: dec(raw.template_id),
      subject: String(raw.subject ?? ''),
      reporter: String(raw.reporter ?? ''),
      sections: Array.isArray(raw.sections)
        ? (raw.sections as unknown[]).map((s: unknown) => {
            const sec = s as Record<string, unknown>;
            return {
              title: dec(sec.title),
              fields: Array.isArray(sec.fields)
                ? (sec.fields as unknown[]).map((f: unknown) => {
                    const field = f as Record<string, unknown>;
                    return { name: dec(field.name), value: dec(field.value) };
                  })
                : [],
            };
          })
        : [],
      riskScore: Number(raw.risk_score ?? 0),
      status: dec(raw.status),
      generatedAt: Number(raw.generated_at ?? 0),
      ledgerSequence: Number(raw.ledger_sequence ?? 0),
      tags: Array.isArray(raw.tags) ? (raw.tags as unknown[]).map(dec) : [],
    };
  }

  private parseSAR(raw: Record<string, unknown>): SARReport {
    return {
      id: dec(raw.id),
      subject: String(raw.subject ?? ''),
      filer: String(raw.filer ?? ''),
      activityType: dec(raw.activity_type),
      description: dec(raw.description),
      relatedTransactions: Array.isArray(raw.related_transactions)
        ? (raw.related_transactions as unknown[]).map(dec)
        : [],
      estimatedValue: dec(raw.estimated_value),
      currency: dec(raw.currency),
      status: (dec(raw.status) as SARReport['status']) || 'filed',
      notifyRegulators: Array.isArray(raw.notify_regulators)
        ? (raw.notify_regulators as unknown[]).map(dec)
        : [],
      evidenceHashes: Array.isArray(raw.evidence_hashes)
        ? (raw.evidence_hashes as unknown[]).map(h => {
            if (h instanceof Uint8Array) return Buffer.from(h).toString('hex');
            return String(h);
          })
        : [],
      filedAt: Number(raw.filed_at ?? 0),
      activityTimestamp: Number(raw.activity_timestamp ?? 0),
      ledgerSequence: Number(raw.ledger_sequence ?? 0),
    };
  }

  private toCSV(report: RegulatoryReport | SARReport | TransactionReport): string {
    // Generic: flatten the report object to CSV
    const flatten = (obj: unknown, prefix = ''): Record<string, string> => {
      const result: Record<string, string> = {};
      if (obj === null || obj === undefined) return result;
      if (typeof obj !== 'object') {
        result[prefix] = String(obj);
        return result;
      }
      const record = obj as Record<string, unknown>;
      for (const [k, v] of Object.entries(record)) {
        const key = prefix ? `${prefix}.${k}` : k;
        if (Array.isArray(v)) {
          result[key] = JSON.stringify(v);
        } else if (typeof v === 'object' && v !== null) {
          Object.assign(result, flatten(v, key));
        } else {
          result[key] = String(v ?? '');
        }
      }
      return result;
    };

    const flat = flatten(report);
    const keys = Object.keys(flat);
    const header = keys.join(',');
    const values = keys.map(k => `"${String(flat[k]).replace(/"/g, '""')}"`).join(',');
    return `${header}\n${values}`;
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account = { accountId: () => dummy.publicKey(), sequenceNumber: () => '0', incrementSequenceNumber: () => {} } as any;
    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: this.networkPassphrase() })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(30)
      .build();
    const sim = await this.rpc.simulateTransaction(tx);
    if (SorobanRpc.Api.isSimulationError(sim)) {
      throw new Error((sim as SorobanRpc.Api.SimulateTransactionErrorResponse).error);
    }
    const retval = (sim as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
    if (!retval) throw new Error('No return value');
    return retval;
  }

  private defaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }

  private networkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet': return Networks.PUBLIC;
      case 'futurenet': return Networks.FUTURENET;
      default: return Networks.TESTNET;
    }
  }

  private err(msg: string): StellarIdentityError {
    return new ComplianceError(ErrorCode.ComplianceNotFound, msg);
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function enc(s: string): Uint8Array { return new TextEncoder().encode(s); }

function dec(v: unknown): string {
  if (v instanceof Uint8Array) return new TextDecoder().decode(v);
  return String(v ?? '');
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
