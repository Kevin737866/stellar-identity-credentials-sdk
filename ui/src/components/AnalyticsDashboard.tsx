import React, { useCallback, useMemo, useRef, useState } from 'react';
import {
  AnalyticsDataset,
  DATE_RANGE_PRESETS,
  DateRange,
  DateRangePreset,
  TimeSeriesPoint,
  filterSeriesByRange,
  formatDateLabel,
  formatNumber,
  formatPercent,
  getDateRangeBounds,
  presetLabel,
  successRate,
  summariseSeries,
} from '../types/analytics';
import { exportSeriesToCsv, exportSvgElementToPng } from '../utils/analyticsExport';
import { BarChart } from './charts/BarChart';
import { ChartPoint } from './charts/chartUtils';
import { DonutChart } from './charts/DonutChart';
import { LineChart } from './charts/LineChart';
import { MetricCard } from './MetricCard';
import { Button } from './ui/button';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

export interface AnalyticsExportPayload {
  format: 'csv' | 'png';
  range: DateRange;
  data: AnalyticsDataset;
}

export interface AnalyticsDashboardProps {
  data: AnalyticsDataset;
  title?: string;
  defaultRange?: DateRangePreset;
  onRangeChange?: (range: DateRange) => void;
  /**
   * Replaces the built-in download behaviour, e.g. to upload the export or to
   * test without touching the DOM download APIs.
   */
  onExport?: (payload: AnalyticsExportPayload) => void;
  /** Clock override, useful for deterministic snapshots and tests. */
  now?: number;
  emptyMessage?: string;
}

/** Auto-fitting grid: a single column on phones, several when space allows. */
const gridStyle = (minColumnWidth: number): React.CSSProperties => ({
  display: 'grid',
  gap: 'var(--space-4)',
  gridTemplateColumns: `repeat(auto-fit, minmax(${minColumnWidth}px, 1fr))`,
});

function toChartPoints(series: TimeSeriesPoint[]): ChartPoint[] {
  return series.map((point) => ({
    label: formatDateLabel(point.timestamp),
    value: point.value,
    timestamp: point.timestamp,
  }));
}

/**
 * Identity analytics dashboard: headline metrics, issuance and reputation
 * charts, verification outcomes, date-range filtering and CSV/PNG export.
 * Charts are dependency-free inline SVG to avoid a charting runtime.
 */
export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({
  data,
  title = 'Identity analytics',
  defaultRange = '30d',
  onRangeChange,
  onExport,
  now,
  emptyMessage,
}) => {
  const [preset, setPreset] = useState<DateRangePreset>(defaultRange);
  const [exportError, setExportError] = useState<string | null>(null);
  const issuanceChartRef = useRef<HTMLDivElement>(null);

  const range = useMemo(() => getDateRangeBounds(preset, now), [preset, now]);

  const issuanceSeries = useMemo(
    () => filterSeriesByRange(data.issuance, range),
    [data.issuance, range]
  );
  const reputationSeries = useMemo(
    () => filterSeriesByRange(data.reputation, range),
    [data.reputation, range]
  );

  const issuanceSummary = useMemo(() => summariseSeries(issuanceSeries), [issuanceSeries]);
  const reputationSummary = useMemo(() => summariseSeries(reputationSeries), [reputationSeries]);
  const verificationRate = successRate(data.verification);

  const selectPreset = useCallback(
    (next: DateRangePreset) => {
      setPreset(next);
      onRangeChange?.(getDateRangeBounds(next, now));
    },
    [now, onRangeChange]
  );

  const handleExportCsv = useCallback(() => {
    if (onExport) {
      onExport({ format: 'csv', range, data });
      return;
    }
    exportSeriesToCsv(toChartPoints(issuanceSeries), `credential-issuance-${range.preset}.csv`);
  }, [data, issuanceSeries, onExport, range]);

  const handleExportPng = useCallback(async () => {
    if (onExport) {
      onExport({ format: 'png', range, data });
      return;
    }

    const svg = issuanceChartRef.current?.querySelector('svg');
    if (!svg) {
      setExportError('The chart is not ready to export yet.');
      return;
    }

    try {
      await exportSvgElementToPng(
        svg as SVGSVGElement,
        `credential-issuance-${range.preset}.png`
      );
      setExportError(null);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : 'Unable to export the chart.');
    }
  }, [data, onExport, range]);

  const numberFormatter = (value: number) => formatNumber(value);

  return (
    <section
      aria-label={title}
      style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}
    >
      <header
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 'var(--space-3)',
        }}
      >
        <div>
          <h2
            style={{
              margin: 0,
              fontSize: 'var(--font-size-xl)',
              fontWeight: 'var(--font-weight-semibold)' as never,
            }}
          >
            {title}
          </h2>
          <p
            style={{
              margin: 'var(--space-1) 0 0',
              fontSize: 'var(--font-size-sm)',
              color: 'var(--color-text-secondary)',
            }}
          >
            {`Showing the last ${presetLabel(preset).toLowerCase()}`}
          </p>
        </div>

        <div
          role="group"
          aria-label="Date range"
          style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}
        >
          {DATE_RANGE_PRESETS.map((entry) => (
            <Button
              key={entry.preset}
              size="sm"
              variant={entry.preset === preset ? 'default' : 'outline'}
              aria-pressed={entry.preset === preset}
              onClick={() => selectPreset(entry.preset)}
            >
              {entry.label}
            </Button>
          ))}
        </div>
      </header>

      <div style={gridStyle(160)}>
        <MetricCard
          label="Credentials issued"
          value={numberFormatter(issuanceSummary.total)}
          changePct={issuanceSummary.changePct}
          caption={`over ${presetLabel(preset).toLowerCase()}`}
        />
        <MetricCard
          label="Average reputation"
          value={numberFormatter(reputationSummary.average)}
          changePct={reputationSummary.changePct}
          caption={`latest ${numberFormatter(reputationSummary.latest)}`}
        />
        <MetricCard
          label="Verification success"
          value={formatPercent(verificationRate)}
          caption={`${numberFormatter(data.verification.successful)} of ${numberFormatter(
            data.verification.successful + data.verification.failed
          )} attempts`}
        />
        <MetricCard
          label="Verification failures"
          value={numberFormatter(data.verification.failed)}
          tone={data.verification.failed > 0 ? 'negative' : 'neutral'}
          caption="in selected period"
        />
      </div>

      <div style={gridStyle(320)}>
        <Card>
          <CardHeader>
            <CardTitle>Credential issuance</CardTitle>
          </CardHeader>
          <CardContent>
            <div ref={issuanceChartRef}>
              <BarChart
                data={toChartPoints(issuanceSeries)}
                ariaLabel={`Credential issuance over the last ${presetLabel(preset).toLowerCase()}`}
                valueFormatter={numberFormatter}
                emptyMessage={emptyMessage}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Reputation trend</CardTitle>
          </CardHeader>
          <CardContent>
            <LineChart
              data={toChartPoints(reputationSeries)}
              ariaLabel={`Reputation trend over the last ${presetLabel(preset).toLowerCase()}`}
              color="var(--color-warning-600)"
              valueFormatter={numberFormatter}
              emptyMessage={emptyMessage}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Verification outcomes</CardTitle>
          </CardHeader>
          <CardContent>
            <DonutChart
              ariaLabel="Verification outcomes"
              centerLabel={formatPercent(verificationRate, 0)}
              centerCaption="verified"
              segments={[
                {
                  label: 'Successful',
                  value: data.verification.successful,
                  color: 'var(--color-success-600)',
                },
                {
                  label: 'Failed',
                  value: data.verification.failed,
                  color: 'var(--color-danger-600)',
                },
              ]}
              emptyMessage={emptyMessage}
            />
          </CardContent>
        </Card>
      </div>

      <footer
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: 'var(--space-3)',
        }}
      >
        <Button size="sm" variant="outline" onClick={handleExportCsv}>
          Export CSV
        </Button>
        <Button size="sm" variant="outline" onClick={handleExportPng}>
          Export PNG
        </Button>
        {exportError ? (
          <span role="alert" style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-danger-600)' }}>
            {exportError}
          </span>
        ) : null}
      </footer>
    </section>
  );
};
