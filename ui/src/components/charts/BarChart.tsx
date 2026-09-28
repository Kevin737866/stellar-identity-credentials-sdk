import React, { useState } from 'react';
import {
  CHART_VIEWBOX_WIDTH,
  ChartPoint,
  DEFAULT_CHART_PADDING,
  axisTicks,
  niceMax,
  peakValue,
} from './chartUtils';

export interface BarChartProps {
  data: ChartPoint[];
  /** Accessible name describing what the chart shows. */
  ariaLabel: string;
  height?: number;
  color?: string;
  /** Formats values in tooltips and data labels. Defaults to the raw number. */
  valueFormatter?: (value: number) => string;
  /** Render the value above each bar. Defaults to `true` for up to 12 bars. */
  showValues?: boolean;
  emptyMessage?: string;
}

const AXIS_FONT_SIZE = 11;
/** Beyond this many bars, per-bar value labels become unreadable. */
const VALUE_LABEL_LIMIT = 12;
const MAX_BAR_WIDTH = 48;

/**
 * Dependency-free bar chart rendered as inline SVG.
 *
 * Bars are laid out in equal bands so the chart stays readable at 320px, and
 * every bar carries a native `<title>` tooltip for pointer and screen-reader
 * users alike.
 */
export const BarChart: React.FC<BarChartProps> = ({
  data,
  ariaLabel,
  height = 220,
  color = 'var(--color-primary-500)',
  valueFormatter = (value) => String(value),
  showValues,
  emptyMessage = 'No data for the selected period',
}) => {
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

  const plotWidth = CHART_VIEWBOX_WIDTH - DEFAULT_CHART_PADDING.left - DEFAULT_CHART_PADDING.right;
  const plotHeight = height - DEFAULT_CHART_PADDING.top - DEFAULT_CHART_PADDING.bottom;
  const maxValue = niceMax(peakValue(data));
  const baselineY = height - DEFAULT_CHART_PADDING.bottom;

  const bandWidth = plotWidth / data.length;
  const barWidth = Math.min(bandWidth * 0.6, MAX_BAR_WIDTH);

  const barY = (value: number) => DEFAULT_CHART_PADDING.top + plotHeight - (value / maxValue) * plotHeight;
  const barX = (index: number) => DEFAULT_CHART_PADDING.left + bandWidth * index + (bandWidth - barWidth) / 2;

  const withValues = showValues ?? data.length <= VALUE_LABEL_LIMIT;
  const ticks = axisTicks(maxValue);

  return (
    <svg
      viewBox={`0 0 ${CHART_VIEWBOX_WIDTH} ${height}`}
      role="img"
      aria-label={ariaLabel}
      data-testid="bar-chart"
      style={{ display: 'block', width: '100%', height: 'auto', overflow: 'visible' }}
    >
      <title>{ariaLabel}</title>

      {ticks.map((tick) => (
        <g key={`tick-${tick}`}>
          <line
            x1={DEFAULT_CHART_PADDING.left}
            x2={CHART_VIEWBOX_WIDTH - DEFAULT_CHART_PADDING.right}
            y1={DEFAULT_CHART_PADDING.top + plotHeight - (tick / maxValue) * plotHeight}
            y2={DEFAULT_CHART_PADDING.top + plotHeight - (tick / maxValue) * plotHeight}
            stroke="var(--color-border)"
            strokeWidth={1}
            strokeDasharray={tick === 0 ? undefined : '3 3'}
          />
          <text
            x={DEFAULT_CHART_PADDING.left - 6}
            y={DEFAULT_CHART_PADDING.top + plotHeight - (tick / maxValue) * plotHeight + AXIS_FONT_SIZE / 3}
            textAnchor="end"
            fontSize={AXIS_FONT_SIZE}
            fill="var(--color-text-secondary)"
          >
            {valueFormatter(tick)}
          </text>
        </g>
      ))}

      {data.map((point, index) => {
        const x = barX(index);
        const y = barY(point.value);
        const isActive = activeIndex === index;

        return (
          <g
            key={`${point.label}-${index}`}
            onMouseEnter={() => setActiveIndex(index)}
            onMouseLeave={() => setActiveIndex(null)}
            onFocus={() => setActiveIndex(index)}
            onBlur={() => setActiveIndex(null)}
            tabIndex={0}
            style={{ cursor: 'pointer' }}
          >
            <rect
              x={x}
              y={y}
              width={barWidth}
              height={Math.max(baselineY - y, 0)}
              rx={4}
              fill={color}
              fillOpacity={isActive ? 1 : 0.85}
            >
              <title>{`${point.label}: ${valueFormatter(point.value)}`}</title>
            </rect>
            {withValues ? (
              <text
                data-testid="bar-value"
                x={x + barWidth / 2}
                y={y - 5}
                textAnchor="middle"
                fontSize={AXIS_FONT_SIZE}
                fill="var(--color-text-secondary)"
              >
                {valueFormatter(point.value)}
              </text>
            ) : null}
            <text
              x={x + barWidth / 2}
              y={height - 8}
              textAnchor="middle"
              fontSize={AXIS_FONT_SIZE}
              fill="var(--color-text-secondary)"
            >
              {point.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
};
