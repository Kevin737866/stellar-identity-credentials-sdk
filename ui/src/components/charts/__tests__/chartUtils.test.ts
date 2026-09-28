import {
  CHART_VIEWBOX_WIDTH,
  ChartPoint,
  DEFAULT_CHART_PADDING,
  axisTicks,
  computeScale,
  labelIndexes,
  niceMax,
  peakValue,
  toAreaPath,
  toPolylinePoints,
} from '../chartUtils';

const points: ChartPoint[] = [
  { label: '1 Mar', value: 0 },
  { label: '2 Mar', value: 50 },
  { label: '3 Mar', value: 100 },
];

describe('niceMax', () => {
  it.each([
    [0, 1],
    [-5, 1],
    [Number.NaN, 1],
    [1, 1],
    [1.2, 2],
    [12, 20],
    [84, 100],
    [230, 500],
  ])('rounds %s up to %s', (input, expected) => {
    expect(niceMax(input)).toBe(expected);
  });
});

describe('peakValue', () => {
  it('finds the largest value', () => {
    expect(peakValue(points)).toBe(100);
  });

  it('never goes below zero', () => {
    expect(peakValue([])).toBe(0);
    expect(peakValue([{ label: 'a', value: -10 }])).toBe(0);
  });
});

describe('computeScale', () => {
  it('positions the first and last points on the plot edges', () => {
    const scale = computeScale(3, 200, 100);
    const left = DEFAULT_CHART_PADDING.left;
    const right = CHART_VIEWBOX_WIDTH - DEFAULT_CHART_PADDING.right;

    expect(scale.x(0)).toBeCloseTo(left, 5);
    expect(scale.x(2)).toBeCloseTo(right, 5);
    expect(scale.x(1)).toBeCloseTo((left + right) / 2, 5);
  });

  it('maps the axis maximum to the top of the plot and zero to the baseline', () => {
    const height = 200;
    const scale = computeScale(3, height, 100);

    expect(scale.y(0)).toBeCloseTo(height - DEFAULT_CHART_PADDING.bottom, 5);
    expect(scale.y(scale.maxValue)).toBeCloseTo(DEFAULT_CHART_PADDING.top, 5);
  });

  it('centres a single point', () => {
    const scale = computeScale(1, 200, 10);

    expect(scale.x(0)).toBeCloseTo(
      DEFAULT_CHART_PADDING.left + scale.plotWidth / 2,
      5
    );
  });
});

describe('toPolylinePoints', () => {
  it('emits one x,y pair per point', () => {
    const scale = computeScale(points.length, 200, peakValue(points));
    const pairs = toPolylinePoints(points, scale).split(' ');

    expect(pairs).toHaveLength(points.length);
    pairs.forEach((pair) => expect(pair).toMatch(/^-?\d+(\.\d+)?,-?\d+(\.\d+)?$/));
  });
});

describe('toAreaPath', () => {
  it('closes the path back along the baseline', () => {
    // Values exclude 0 so the baseline does not coincide with a data point.
    const offsetPoints: ChartPoint[] = [
      { label: '1 Mar', value: 10 },
      { label: '2 Mar', value: 50 },
      { label: '3 Mar', value: 100 },
    ];
    const baseline = 172;
    const scale = computeScale(offsetPoints.length, 200, peakValue(offsetPoints));
    const path = toAreaPath(offsetPoints, scale, baseline);

    expect(path.startsWith('M ')).toBe(true);
    expect(path.endsWith('Z')).toBe(true);
    // Both baseline corners are closed back to the start of the series.
    expect(path.split(String(baseline))).toHaveLength(3);
  });

  it('returns an empty string for an empty series', () => {
    expect(toAreaPath([], computeScale(1, 200, 1), 172)).toBe('');
  });
});

describe('axisTicks', () => {
  it('spans zero to the axis maximum', () => {
    expect(axisTicks(100, 4)).toEqual([0, 25, 50, 75, 100]);
  });
});

describe('labelIndexes', () => {
  it('labels every point when there is room', () => {
    expect(labelIndexes(3)).toEqual([0, 1, 2]);
  });

  it('thins out dense series while keeping the first and last labels', () => {
    const indexes = labelIndexes(30, 5);

    expect(indexes[0]).toBe(0);
    expect(indexes[indexes.length - 1]).toBe(29);
    expect(indexes.length).toBeLessThanOrEqual(6);
  });
});
