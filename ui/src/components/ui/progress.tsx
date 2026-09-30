import React from 'react';

export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number;
  max?: number;
  /** Accessible name, e.g. "Setup progress". Required when no visible label exists. */
  'aria-label'?: string;
  /** Text alternative announced instead of the raw number. */
  'aria-valuetext'?: string;
}

export const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
  ({ value = 0, max = 100, style, ...props }, ref) => {
    const clamped = Math.min(max, Math.max(0, value));
    const percentage = max === 0 ? 0 : (clamped / max) * 100;

    return (
      <div
        ref={ref}
        role="progressbar"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={max}
        style={{
          height: '8px',
          width: '100%',
          borderRadius: 'var(--radius-full)',
          backgroundColor: 'var(--color-bg-tertiary)',
          overflow: 'hidden',
          ...style,
        }}
        {...props}
      >
        <div
          style={{
            height: '100%',
            width: `${percentage}%`,
            backgroundColor: 'var(--color-primary-600)',
            borderRadius: 'var(--radius-full)',
            transition: 'width var(--transition-slow)',
          }}
        />
      </div>
    );
  }
);
Progress.displayName = 'Progress';

/**
 * Determinate progress with a visible percentage.
 *
 * The number is rendered as text as well as exposed via ARIA, because a bare
 * bar communicates nothing to a screen reader user and is hard to read at a
 * glance for everyone else.
 */
export const ProgressWithLabel: React.FC<
  ProgressProps & { label?: string; showValue?: boolean }
> = ({ label, showValue = true, value = 0, max = 100, ...props }) => {
  const clamped = Math.min(max, Math.max(0, value));
  const percentage = max === 0 ? 0 : Math.round((clamped / max) * 100);

  return (
    <div style={{ width: '100%' }}>
      {(label || showValue) && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 'var(--space-2)',
            fontSize: 'var(--font-size-xs)',
            color: 'var(--color-text-secondary)',
          }}
        >
          <span>{label}</span>
          {showValue && <span aria-hidden="true">{percentage}%</span>}
        </div>
      )}
      <Progress
        value={clamped}
        max={max}
        aria-valuetext={`${percentage} percent`}
        {...props}
      />
    </div>
  );
};
ProgressWithLabel.displayName = 'ProgressWithLabel';
