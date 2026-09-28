import React from 'react';
import { Card, CardContent } from './ui/card';

export interface MetricCardProps {
  label: string;
  /** Pre-formatted value, e.g. `1,284` or `82.4%`. */
  value: string;
  /** Change across the selected range, as a percentage. */
  changePct?: number;
  caption?: string;
  /** Overrides the tone inferred from `changePct`. */
  tone?: 'positive' | 'negative' | 'neutral';
}

const TONE_COLORS: Record<'positive' | 'negative' | 'neutral', string> = {
  positive: 'var(--color-success-600)',
  negative: 'var(--color-danger-600)',
  neutral: 'var(--color-text-secondary)',
};

const TONE_GLYPHS: Record<'positive' | 'negative' | 'neutral', string> = {
  positive: '▲',
  negative: '▼',
  neutral: '•',
};

/** Resolve a tone from the direction of change, treating 0 as neutral. */
export function inferTone(changePct: number): 'positive' | 'negative' | 'neutral' {
  if (changePct > 0) {
    return 'positive';
  }
  if (changePct < 0) {
    return 'negative';
  }
  return 'neutral';
}

/** Format a signed percentage, e.g. `+4.2%`. */
export function formatChange(changePct: number): string {
  const sign = changePct > 0 ? '+' : '';
  return `${sign}${changePct.toFixed(1)}%`;
}

/**
 * A single headline metric: its value, the movement across the selected range
 * and an optional caption explaining the number.
 */
export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  changePct,
  caption,
  tone,
}) => {
  const resolvedTone = tone ?? (changePct === undefined ? 'neutral' : inferTone(changePct));
  const color = TONE_COLORS[resolvedTone];

  return (
    <Card>
      <CardContent style={{ padding: 'var(--space-4)' }}>
        <p
          style={{
            margin: 0,
            fontSize: 'var(--font-size-xs)',
            color: 'var(--color-text-secondary)',
          }}
        >
          {label}
        </p>

        <p
          style={{
            margin: 'var(--space-2) 0 0',
            fontSize: 'var(--font-size-2xl)',
            fontWeight: 'var(--font-weight-bold)' as never,
            lineHeight: 'var(--line-height-tight)',
            color: 'var(--color-text)',
          }}
        >
          {value}
        </p>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-2)',
            marginTop: 'var(--space-2)',
            fontSize: 'var(--font-size-xs)',
          }}
        >
          {changePct === undefined ? null : (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
                color,
                fontWeight: 'var(--font-weight-medium)' as never,
              }}
            >
              <span aria-hidden="true">{TONE_GLYPHS[resolvedTone]}</span>
              {formatChange(changePct)}
            </span>
          )}
          {caption ? (
            <span style={{ color: 'var(--color-text-secondary)' }}>{caption}</span>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
};
