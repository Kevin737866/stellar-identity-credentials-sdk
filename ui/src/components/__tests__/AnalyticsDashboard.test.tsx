import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { AnalyticsDataset, MS_PER_DAY } from '../../types/analytics';
import { AnalyticsDashboard } from '../AnalyticsDashboard';

const NOW = Date.UTC(2026, 2, 15, 12, 0, 0);

const dataset: AnalyticsDataset = {
  issuance: [
    { timestamp: NOW - MS_PER_DAY, value: 10 },
    { timestamp: NOW - 10 * MS_PER_DAY, value: 20 },
    { timestamp: NOW - 40 * MS_PER_DAY, value: 100 },
  ],
  reputation: [
    { timestamp: NOW - 2 * MS_PER_DAY, value: 70 },
    { timestamp: NOW - 1 * MS_PER_DAY, value: 82 },
  ],
  verification: { successful: 92, failed: 8 },
};

/** Read the rendered body of the card carrying `label`. */
function metricCardText(label: string): string {
  return screen.getByText(label).parentElement?.textContent ?? '';
}

function renderDashboard(props: Partial<React.ComponentProps<typeof AnalyticsDashboard>> = {}) {
  return render(<AnalyticsDashboard data={dataset} now={NOW} {...props} />);
}

describe('AnalyticsDashboard', () => {
  it('renders the headline metrics for the default range', () => {
    renderDashboard();

    // 30 day window keeps the 1 day and 10 day points, not the 40 day one.
    expect(metricCardText('Credentials issued')).toContain('30');
    expect(metricCardText('Average reputation')).toContain('76');
    expect(metricCardText('Verification success')).toContain('92.0%');
    expect(metricCardText('Verification failures')).toContain('8');
  });

  it('renders the issuance, reputation and verification charts', () => {
    renderDashboard();

    expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    expect(screen.getByTestId('donut-chart')).toBeInTheDocument();
  });

  it('describes the active window', () => {
    renderDashboard();

    expect(screen.getByText('Showing the last 30 days')).toBeInTheDocument();
  });

  it('narrows the window when a shorter range is selected', () => {
    renderDashboard();

    fireEvent.click(screen.getByRole('button', { name: '7 days' }));

    // Only the 1 day old point remains inside a 7 day window.
    expect(metricCardText('Credentials issued')).toContain('10');
    expect(screen.getByText('Showing the last 7 days')).toBeInTheDocument();
  });

  it('marks the selected range for assistive technology', () => {
    renderDashboard();

    expect(screen.getByRole('button', { name: '30 days' })).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    expect(screen.getByRole('button', { name: '7 days' })).toHaveAttribute(
      'aria-pressed',
      'false'
    );

    fireEvent.click(screen.getByRole('button', { name: '90 days' }));

    expect(screen.getByRole('button', { name: '90 days' })).toHaveAttribute(
      'aria-pressed',
      'true'
    );
  });

  it('honours a different default range', () => {
    renderDashboard({ defaultRange: '7d' });

    expect(screen.getByText('Showing the last 7 days')).toBeInTheDocument();
  });

  it('reports the resolved range to the parent', () => {
    const onRangeChange = jest.fn();
    renderDashboard({ onRangeChange });

    fireEvent.click(screen.getByRole('button', { name: '7 days' }));

    expect(onRangeChange).toHaveBeenCalledWith({
      from: NOW - 7 * MS_PER_DAY,
      to: NOW,
      preset: '7d',
    });
  });

  it('wider ranges include older data points', () => {
    renderDashboard();

    fireEvent.click(screen.getByRole('button', { name: '90 days' }));

    // 10 + 20 + 100 across the full 90 day window.
    expect(metricCardText('Credentials issued')).toContain('130');
  });

  it('delegates CSV export to the caller when a handler is supplied', () => {
    const onExport = jest.fn();
    renderDashboard({ onExport });

    fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));

    expect(onExport).toHaveBeenCalledTimes(1);
    expect(onExport.mock.calls[0][0]).toMatchObject({ format: 'csv', data: dataset });
    expect(onExport.mock.calls[0][0].range.preset).toBe('30d');
  });

  it('delegates PNG export to the caller when a handler is supplied', () => {
    const onExport = jest.fn();
    renderDashboard({ onExport });

    fireEvent.click(screen.getByRole('button', { name: 'Export PNG' }));

    expect(onExport).toHaveBeenCalledTimes(1);
    expect(onExport.mock.calls[0][0].format).toBe('png');
  });

  it('exports the range that is currently selected', () => {
    const onExport = jest.fn();
    renderDashboard({ onExport });

    fireEvent.click(screen.getByRole('button', { name: '7 days' }));
    fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));

    expect(onExport.mock.calls[0][0].range).toEqual({
      from: NOW - 7 * MS_PER_DAY,
      to: NOW,
      preset: '7d',
    });
  });

  it('renders empty states for a period with no activity', () => {
    renderDashboard({
      data: {
        issuance: [],
        reputation: [],
        verification: { successful: 0, failed: 0 },
      },
      emptyMessage: 'Nothing recorded',
    });

    expect(screen.queryByTestId('bar-chart')).not.toBeInTheDocument();
    expect(screen.queryByTestId('line-chart')).not.toBeInTheDocument();
    expect(screen.getAllByRole('status').length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText('Nothing recorded')).toHaveLength(3);
  });

  it('keeps the charts usable on narrow viewports by stacking them', () => {
    renderDashboard();

    const charts = [screen.getByTestId('bar-chart'), screen.getByTestId('line-chart')];

    charts.forEach((chart) => {
      // No fixed pixel width: the SVG scales with its container.
      expect(chart.getAttribute('width')).toBeNull();
      expect(chart.style.width).toBe('100%');
    });
  });
});
