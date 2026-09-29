export interface ChartPoint {
  /** Axis label for the bucket, e.g. `12 Mar`. */
  label: string;
  value: number;
  /** Epoch milliseconds, used for tooltips and exports. */
  timestamp?: number;
}

export interface ChartPadding {
  top: number;
  right: number;
  bottom: number;
  left: number;
}

/** Fixed viewBox width; the rendered width follows the container. */
export const CHART_VIEWBOX_WIDTH = 600;

export const DEFAULT_CHART_PADDING: ChartPadding = {
  top: 12,
  right: 12,
  bottom: 28,
  left: 44,
};

export interface ChartScale {
  plotWidth: number;
  plotHeight: number;
  maxValue: number;
  /** Horizontal position for data point `index`. */
  x: (index: number) => number;
  /** Vertical position for a value. */
  y: (value: number) => number;
}

/** Round a maximum up to a readable axis bound (1, 2, 5 or 10 × 10ⁿ). */
export function niceMax(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return 1;
  }

  const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
  const normalised = value / magnitude;
  const nice = normalised <= 1 ? 1 : normalised <= 2 ? 2 : normalised <= 5 ? 5 : 10;

  return nice * magnitude;
}

/** Map data points onto SVG coordinates inside `height`. */
export function computeScale(
  count: number,
  height: number,
  peak: number,
  padding: ChartPadding = DEFAULT_CHART_PADDING,
  width: number = CHART_VIEWBOX_WIDTH
): ChartScale {
  const plotWidth = Math.max(1, width - padding.left - padding.right);
  const plotHeight = Math.max(1, height - padding.top - padding.bottom);
  const maxValue = niceMax(peak);

  return {
    plotWidth,
    plotHeight,
    maxValue,
    x: (index: number) =>
      padding.left + (count <= 1 ? plotWidth / 2 : (index / (count - 1)) * plotWidth),
    y: (value: number) => padding.top + plotHeight - (value / maxValue) * plotHeight,
  };
}

/** Largest value in a series, never below 0. */
export function peakValue(points: ChartPoint[]): number {
  return points.reduce((peak, point) => (point.value > peak ? point.value : peak), 0);
}

/** Build the `points` attribute for a `<polyline>`. */
export function toPolylinePoints(points: ChartPoint[], scale: ChartScale): string {
  return points.map((point, index) => `${scale.x(index)},${scale.y(point.value)}`).join(' ');
}

/** Build a closed path that fills the area under a series. */
export function toAreaPath(points: ChartPoint[], scale: ChartScale, baselineY: number): string {
  if (points.length === 0) {
    return '';
  }

  const line = points
    .map((point, index) => `${index === 0 ? 'M' : 'L'} ${scale.x(index)} ${scale.y(point.value)}`)
    .join(' ');

  const first = scale.x(0);
  const last = scale.x(points.length - 1);

  return `${line} L ${last} ${baselineY} L ${first} ${baselineY} Z`;
}

/** Evenly spaced tick values from 0 to the axis maximum. */
export function axisTicks(maxValue: number, count = 4): number[] {
  return Array.from({ length: count + 1 }, (_, index) => (maxValue / count) * index);
}

/** Indexes worth labelling on the x axis, avoiding clutter on dense series. */
export function labelIndexes(count: number, maxLabels = 5): number[] {
  if (count <= maxLabels) {
    return Array.from({ length: count }, (_, index) => index);
  }

  const step = Math.ceil((count - 1) / (maxLabels - 1));
  const indexes: number[] = [];

  for (let index = 0; index < count; index += step) {
    indexes.push(index);
  }

  if (indexes[indexes.length - 1] !== count - 1) {
    indexes.push(count - 1);
  }

  return indexes;
}
