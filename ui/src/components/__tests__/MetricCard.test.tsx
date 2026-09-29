import React from 'react';
import { render, screen } from '@testing-library/react';
import { MetricCard, formatChange, inferTone } from '../MetricCard';

describe('inferTone', () => {
  it.each([
    [4.2, 'positive'],
    [-4.2, 'negative'],
    [0, 'neutral'],
  ] as const)('maps %s to %s', (change, tone) => {
    expect(inferTone(change)).toBe(tone);
  });
});

describe('formatChange', () => {
  it('adds a plus sign to gains', () => {
    expect(formatChange(4.25)).toBe('+4.3%');
  });

  it('keeps the minus sign on losses', () => {
    expect(formatChange(-9)).toBe('-9.0%');
  });
});

describe('MetricCard', () => {
  it('renders the label, value and caption', () => {
    render(<MetricCard label="Credentials issued" value="1,284" caption="last 30 days" />);

    expect(screen.getByText('Credentials issued')).toBeInTheDocument();
    expect(screen.getByText('1,284')).toBeInTheDocument();
    expect(screen.getByText('last 30 days')).toBeInTheDocument();
  });

  it('shows the direction of travel for a gain', () => {
    render(<MetricCard label="Issued" value="10" changePct={12.5} />);

    expect(screen.getByText('▲')).toBeInTheDocument();
    expect(screen.getByText('+12.5%')).toBeInTheDocument();
  });

  it('shows the direction of travel for a loss', () => {
    render(<MetricCard label="Issued" value="10" changePct={-3} />);

    expect(screen.getByText('▼')).toBeInTheDocument();
    expect(screen.getByText('-3.0%')).toBeInTheDocument();
  });

  it('omits the change indicator when no change is supplied', () => {
    render(<MetricCard label="Issued" value="10" />);

    expect(screen.queryByText('▲')).not.toBeInTheDocument();
    expect(screen.queryByText('▼')).not.toBeInTheDocument();
  });

  it('lets an explicit tone override the inferred one', () => {
    render(<MetricCard label="Failures" value="8" tone="negative" />);

    // No change is rendered, but the tone must not throw or leak into the DOM as a glyph.
    expect(screen.queryByText('▼')).not.toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument();
  });
});
