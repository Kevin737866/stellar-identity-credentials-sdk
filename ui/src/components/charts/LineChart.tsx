import React, { useId, useState } from 'react';
import {
  CHART_VIEWBOX_WIDTH,
  ChartPoint,
  DEFAULT_CHART_PADDING,
  axisTicks,
  computeScale,
  labelIndexes,
  peakValue,
  toAreaPath,
  toPolylinePoints,
} from './chartUtils';

export interface LineChartProps {
  data: ChartPoint[];
  /** Accessible name describing what the chart shows. */
  ariaLabel: string;
  height?: number;
  color?: string;
  /** Formats values in the tooltip and axis. Defaults to the raw number. */
  valueFormatter?: (value: number) => string;
  /** Fill the area beneath the line. Default `true`. */
  showArea?: boolean;
  emptyMessage?: string;
}

const AXIS_FONT_SIZE = 11;

/**
 * Dependency-free line chart rendered as inline SVG.
 *
 * The SVG scales with its container, each point exposes a native `<title>`
 * tooltip, and hovering a point raises a value callout so the series can be
 * read without a separate legend.
 */
export const LineChart: React.FC<LineChartProps> = ({
  data,
  ariaLabel,
  height = 220,
  color = 'var(--color-primary-600)',
  valueFormatter = (value) => String(value),
  showArea = true,
  emptyMessage = 'No data for the selected period',
}) => {
  const gradientId = useId();
  const [activeIndex, setActiveIndex] = useState<number | null>(null);

  if (data.length === 0) {
    return (
      <p
        role="status"
        style={{
          margin: 0,
          padding: 'var(--space-8) 0',
          textAlign: 'center',
          fontSize: 'var(--font-size-sm)',
          color: 'var(--color-text-secondary)',
        }}
      >
        {emptyMessage}
      </p>
    );
  }

  const scale = computeScale(data.length, height, peakValue(data));
  const baselineY = height - DEFAULT_CHART_PADDING.bottom;
  const ticks = axisTicks(scale.maxValue);
  const labelled = labelIndexes(data.length);

  const active = activeIndex === null ? null : data[activeIndex];
  const activeX = activeIndex === null ? 0 : scale.x(activeIndex);
  const activeY = active === null ? 0 : scale.y(active.value);
  const tooltipWidth = 92;
  const tooltipX = Math.min(
    Math.max(activeX - tooltipWidth / 2, DEFAULT_CHART_PADDING.left),
    CHART_VIEWBOX_WIDTH - DEFAULT_CHART_PADDING.right - tooltipWidth
  );

  return (
    <svg
      viewBox={`0 0 ${CHART_VIEWBOX_WIDTH} ${height}`}
      role="img"
      aria-label={ariaLabel}
      data-testid="line-chart"
      style={{ display: 'block', width: '100%', height: 'auto', overflow: 'visible' }}
    >
      <title>{ariaLabel}</title>

      {showArea ? (
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.28} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
      ) : null}

      {/* Gridlines and y-axis labels */}
      {ticks.map((tick) => (
        <g key={`tick-${tick}`}>
          <line
            x1={DEFAULT_CHART_PADDING.left}
            x2={CHART_VIEWBOX_WIDTH - DEFAULT_CHART_PADDING.right}
            y1={scale.y(tick)}
            y2={scale.y(tick)}
            stroke="var(--color-border)"
            strokeWidth={1}
            strokeDasharray={tick === 0 ? undefined : '3 3'}
          />
          <text
            x={DEFAULT_CHART_PADDING.left - 6}
            y={scale.y(tick) + AXIS_FONT_SIZE / 3}
            textAnchor="end"
            fontSize={AXIS_FONT_SIZE}
            fill="var(--color-text-secondary)"
          >
            {valueFormatter(tick)}
          </text>
        </g>
      ))}

      {showArea ? (
        <path d={toAreaPath(data, scale, baselineY)} fill={`url(#${gradientId})`} stroke="none" />
      ) : null}

      <polyline
        points={toPolylinePoints(data, scale)}
        fill="none"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {data.map((point, index) => (
        <circle
          key={`${point.label}-${index}`}
          cx={scale.x(index)}
          cy={scale.y(point.value)}
          r={activeIndex === index ? 5 : 3}
          fill="var(--color-bg)"
          stroke={color}
          strokeWidth={2}
          onMouseEnter={() => setActiveIndex(index)}
          onMouseLeave={() => setActiveIndex(null)}
          onFocus={() => setActiveIndex(index)}
          onBlur={() => setActiveIndex(null)}
          tabIndex={0}
          style={{ cursor: 'pointer' }}
        >
          <title>{`${point.label}: ${valueFormatter(point.value)}`}</title>
        </circle>
      ))}

      {active && activeIndex !== null ? (
        <g data-testid="line-chart-tooltip" pointerEvents="none">
          <line
            x1={activeX}
            x2={activeX}
            y1={activeY}
            y2={baselineY}
            stroke={color}
            strokeWidth={1}
            strokeDasharray="2 2"
          />
          <rect
            x={tooltipX}
            y={Math.max(activeY - 34, 0)}
            width={tooltipWidth}
            height={26}
            rx={4}
            fill="var(--color-bg)"
            stroke="var(--color-border)"
          />
          <text
            x={tooltipX + tooltipWidth / 2}
            y={Math.max(activeY - 34, 0) + 17}
            textAnchor="middle"
            fontSize={AXIS_FONT_SIZE}
            fill="var(--color-text)"
          >
            {`${active.label}: ${valueFormatter(active.value)}`}
          </text>
        </g>
      ) : null}

      {/* X-axis labels */}
      {labelled.map((index) => (
        <text
          key={`label-${index}`}
          x={scale.x(index)}
          y={height - 8}
          textAnchor="middle"
          fontSize={AXIS_FONT_SIZE}
          fill="var(--color-text-secondary)"
        >
          {data[index].label}
        </text>
      ))}
    </svg>
  );
};
