import {
  DATE_RANGE_PRESETS,
  MS_PER_DAY,
  TimeSeriesPoint,
  filterSeriesByRange,
  formatDateLabel,
  formatNumber,
  formatPercent,
  getDateRangeBounds,
  presetLabel,
  successRate,
  summariseSeries,
} from '../analytics';

const NOW = Date.UTC(2026, 2, 15, 12, 0, 0);

function series(values: number[]): TimeSeriesPoint[] {
  return values.map((value, index) => ({
    timestamp: NOW - (values.length - 1 - index) * MS_PER_DAY,
    value,
  }));
}

describe('getDateRangeBounds', () => {
  it.each([
    ['7d', 7],
    ['30d', 30],
    ['90d', 90],
  ] as const)('resolves %s to a %i day window ending at now', (preset, days) => {
    const range = getDateRangeBounds(preset, NOW);

    expect(range.to).toBe(NOW);
    expect(range.from).toBe(NOW - days * MS_PER_DAY);
    expect(range.preset).toBe(preset);
  });

  it('exposes a label for every preset', () => {
    DATE_RANGE_PRESETS.forEach((entry) => {
      expect(presetLabel(entry.preset)).toBe(entry.label);
    });
  });
});

describe('filterSeriesByRange', () => {
  it('keeps only points inside the range, inclusive of both bounds', () => {
    const points: TimeSeriesPoint[] = [
      { timestamp: NOW - 10 * MS_PER_DAY, value: 1 },
      { timestamp: NOW - 5 * MS_PER_DAY, value: 2 },
      { timestamp: NOW, value: 3 },
    ];

    const filtered = filterSeriesByRange(points, getDateRangeBounds('7d', NOW));

    expect(filtered.map((point) => point.value)).toEqual([2, 3]);
  });

  it('returns an empty array when nothing falls inside', () => {
    const points: TimeSeriesPoint[] = [{ timestamp: NOW - 200 * MS_PER_DAY, value: 9 }];

    expect(filterSeriesByRange(points, getDateRangeBounds('7d', NOW))).toEqual([]);
  });
});

describe('summariseSeries', () => {
  it('totals, averages and reports the change across the window', () => {
    const summary = summariseSeries(series([10, 20, 30]));

    expect(summary.total).toBe(60);
    expect(summary.average).toBe(20);
    expect(summary.latest).toBe(30);
    expect(summary.changePct).toBeCloseTo(200, 5);
  });

  it('reports a negative change when the series declines', () => {
    expect(summariseSeries(series([40, 30, 20])).changePct).toBeCloseTo(-50, 5);
  });

  it('reports no change for a flat series', () => {
    expect(summariseSeries(series([7, 7, 7])).changePct).toBe(0);
  });

  it('handles a series that starts at zero', () => {
    expect(summariseSeries(series([0, 0])).changePct).toBe(0);
    expect(summariseSeries(series([0, 5])).changePct).toBe(100);
  });

  it('returns zeros for an empty series', () => {
    expect(summariseSeries([])).toEqual({ total: 0, average: 0, latest: 0, changePct: 0 });
  });
});

describe('successRate', () => {
  it('computes the share of successful verifications', () => {
    expect(successRate({ successful: 92, failed: 8 })).toBeCloseTo(92, 5);
  });

  it('returns 0 when there were no attempts', () => {
    expect(successRate({ successful: 0, failed: 0 })).toBe(0);
  });

  it('handles a complete failure', () => {
    expect(successRate({ successful: 0, failed: 5 })).toBe(0);
  });
});

describe('formatters', () => {
  it('formats percentages with a configurable precision', () => {
    expect(formatPercent(92.345)).toBe('92.3%');
    expect(formatPercent(92.345, 0)).toBe('92%');
  });

  it('groups thousands in numbers', () => {
    expect(formatNumber(1284)).toBe('1,284');
  });

  it('renders a short axis label', () => {
    expect(formatDateLabel(Date.UTC(2026, 2, 12))).toBe('Mar 12');
  });
});
