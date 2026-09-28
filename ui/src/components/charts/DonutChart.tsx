import React from 'react';

export interface DonutSegment {
  label: string;
  value: number;
  color: string;
}

export interface DonutChartProps {
  segments: DonutSegment[];
  /** Accessible name describing what the chart shows. */
  ariaLabel: string;
  /** Large value rendered in the middle of the ring. */
  centerLabel?: string;
  /** Caption beneath `centerLabel`. */
  centerCaption?: string;
  /** Rendered pixel size of the ring. Default `180`. */
  size?: number;
  emptyMessage?: string;
}

const STROKE_WIDTH = 18;

/**
 * Dependency-free ring chart used for share-of-total metrics such as the
 * verification success rate. Each arc carries a native `<title>` tooltip and
 * the legend doubles as the accessible data table.
 */
export const DonutChart: React.FC<DonutChartProps> = ({
  segments,
  ariaLabel,
  centerLabel,
  centerCaption,
  size = 180,
  emptyMessage = 'No data for the selected period',
}) => {
  const total = segments.reduce((sum, segment) => sum + Math.max(segment.value, 0), 0);

  if (segments.length === 0 || total <= 0) {
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

  const radius = (size - STROKE_WIDTH) / 2;
  const circumference = 2 * Math.PI * radius;
  const center = size / 2;

  let offset = 0;

  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 'var(--space-4)',
        fontFamily: 'var(--font-family)',
      }}
    >
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        role="img"
        aria-label={ariaLabel}
        data-testid="donut-chart"
        style={{ flexShrink: 0 }}
      >
        <title>{ariaLabel}</title>
        <g transform={`rotate(-90 ${center} ${center})`}>
          {segments.map((segment) => {
            const share = Math.max(segment.value, 0) / total;
            const dash = share * circumference;
            const dashOffset = -offset;
            offset += dash;

            return (
              <circle
                key={segment.label}
                cx={center}
                cy={center}
                r={radius}
                fill="none"
                stroke={segment.color}
                strokeWidth={STROKE_WIDTH}
                strokeDasharray={`${dash} ${circumference - dash}`}
                strokeDashoffset={dashOffset}
                strokeLinecap="butt"
              >
                <title>{`${segment.label}: ${segment.value} (${(share * 100).toFixed(1)}%)`}</title>
              </circle>
            );
          })}
        </g>

        {centerLabel ? (
          <text
            x={center}
            y={center + 4}
            textAnchor="middle"
            fontSize={size * 0.19}
            fontWeight="bold"
            fill="var(--color-text)"
          >
            {centerLabel}
          </text>
        ) : null}

        {centerCaption ? (
          <text
            x={center}
            y={center + size * 0.17}
            textAnchor="middle"
            fontSize={size * 0.085}
            fill="var(--color-text-secondary)"
          >
            {centerCaption}
          </text>
        ) : null}
      </svg>

      <ul style={{ listStyle: 'none', margin: 0, padding: 0, minWidth: 0 }}>
        {segments.map((segment) => (
          <li
            key={segment.label}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              fontSize: 'var(--font-size-sm)',
              color: 'var(--color-text-secondary)',
              marginBottom: 'var(--space-1)',
            }}
          >
            <span
              aria-hidden="true"
              style={{
                width: '10px',
                height: '10px',
                borderRadius: 'var(--radius-full)',
                backgroundColor: segment.color,
                flexShrink: 0,
              }}
            />
            <span>{segment.label}</span>
            <span
              style={{
                marginLeft: 'auto',
                color: 'var(--color-text)',
                fontWeight: 'var(--font-weight-medium)' as never,
              }}
            >
              {segment.value}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
};
