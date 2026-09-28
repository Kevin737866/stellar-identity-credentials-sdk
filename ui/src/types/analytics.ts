export type DateRangePreset = '7d' | '30d' | '90d';

export interface DateRange {
  /** Inclusive lower bound, epoch milliseconds. */
  from: number;
  /** Inclusive upper bound, epoch milliseconds. */
  to: number;
  preset: DateRangePreset;
}

export interface TimeSeriesPoint {
  /** Epoch milliseconds for the bucket. */
  timestamp: number;
  value: number;
}

export interface VerificationBreakdown {
  successful: number;
  failed: number;
}

/** Everything the analytics dashboard needs to render. */
export interface AnalyticsDataset {
  issuance: TimeSeriesPoint[];
  reputation: TimeSeriesPoint[];
  verification: VerificationBreakdown;
}

export interface SeriesSummary {
  total: number;
  average: number;
  latest: number;
  /** Change between the first and last point, as a percentage. */
  changePct: number;
}

export const DATE_RANGE_PRESETS: Array<{ preset: DateRangePreset; label: string }> = [
  { preset: '7d', label: '7 days' },
  { preset: '30d', label: '30 days' },
  { preset: '90d', label: '90 days' },
];

const PRESET_DAYS: Record<DateRangePreset, number> = {
  '7d': 7,
  '30d': 30,
  '90d': 90,
};

export const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** Resolve a preset into concrete bounds ending at `now`. */
export function getDateRangeBounds(
  preset: DateRangePreset,
  now: number = Date.now()
): DateRange {
  const days = PRESET_DAYS[preset];
  return {
    from: now - days * MS_PER_DAY,
    to: now,
    preset,
  };
}

/** Keep only the points that fall inside the range. */
export function filterSeriesByRange(
  points: TimeSeriesPoint[],
  range: DateRange
): TimeSeriesPoint[] {
  return points.filter(
    (point) => point.timestamp >= range.from && point.timestamp <= range.to
  );
}

/** Aggregate a series into the numbers shown on the metric cards. */
export function summariseSeries(points: TimeSeriesPoint[]): SeriesSummary {
  if (points.length === 0) {
    return { total: 0, average: 0, latest: 0, changePct: 0 };
  }

  const first = points[0].value;
  const latest = points[points.length - 1].value;
  const total = points.reduce((sum, point) => sum + point.value, 0);

  return {
    total,
    average: total / points.length,
    latest,
    changePct: first === 0 ? (latest === 0 ? 0 : 100) : ((latest - first) / first) * 100,
  };
}

/** Share of successful verifications, as a percentage in `[0, 100]`. */
export function successRate(breakdown: VerificationBreakdown): number {
  const attempts = breakdown.successful + breakdown.failed;
  if (attempts <= 0) {
    return 0;
  }
  return (breakdown.successful / attempts) * 100;
}

export function formatPercent(value: number, fractionDigits = 1): string {
  return `${value.toFixed(fractionDigits)}%`;
}

export function formatNumber(value: number, fractionDigits = 0): string {
  return value.toLocaleString('en-US', {
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  });
}

/** Short axis label, e.g. `12 Mar`. */
export function formatDateLabel(timestamp: number): string {
  return new Date(timestamp).toLocaleDateString('en-US', {
    day: 'numeric',
    month: 'short',
  });
}

/** Human-readable preset label. */
export function presetLabel(preset: DateRangePreset): string {
  return DATE_RANGE_PRESETS.find((entry) => entry.preset === preset)?.label ?? preset;
}
