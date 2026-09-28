import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { BarChart } from '../BarChart';
import { ChartPoint } from '../chartUtils';
import { DonutChart } from '../DonutChart';
import { LineChart } from '../LineChart';

const points: ChartPoint[] = [
  { label: '1 Mar', value: 12, timestamp: 1 },
  { label: '2 Mar', value: 30, timestamp: 2 },
  { label: '3 Mar', value: 18, timestamp: 3 },
];

describe('LineChart', () => {
  it('renders an accessible image with a polyline per series', () => {
    render(<LineChart data={points} ariaLabel="Credential issuance" />);

    const chart = screen.getByTestId('line-chart');
    expect(chart).toHaveAttribute('role', 'img');
    expect(chart).toHaveAccessibleName('Credential issuance');
    expect(chart.querySelector('polyline')).not.toBeNull();
    expect(chart.querySelectorAll('circle')).toHaveLength(points.length);
  });

  it('exposes a native tooltip on every point', () => {
    render(<LineChart data={points} ariaLabel="Issuance" valueFormatter={(v) => `${v} creds`} />);

    expect(screen.getByText('2 Mar: 30 creds')).toBeInTheDocument();
  });

  it('raises a value callout when a point is hovered', () => {
    render(<LineChart data={points} ariaLabel="Issuance" valueFormatter={(v) => `${v} creds`} />);

    expect(screen.queryByTestId('line-chart-tooltip')).not.toBeInTheDocument();

    fireEvent.mouseOver(screen.getByTestId('line-chart').querySelectorAll('circle')[1]);

    expect(screen.getByTestId('line-chart-tooltip')).toBeInTheDocument();
    expect(screen.getByTestId('line-chart-tooltip')).toHaveTextContent('2 Mar: 30 creds');
  });

  it('renders the area fill only when requested', () => {
    const { unmount } = render(<LineChart data={points} ariaLabel="Issuance" />);
    expect(screen.getByTestId('line-chart').querySelector('path')).not.toBeNull();
    unmount();

    render(<LineChart data={points} ariaLabel="Issuance" showArea={false} />);
    expect(screen.getByTestId('line-chart').querySelector('path')).toBeNull();
  });

  it('shows an empty state instead of an axis for an empty series', () => {
    render(<LineChart data={[]} ariaLabel="Issuance" emptyMessage="Nothing yet" />);

    expect(screen.queryByTestId('line-chart')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Nothing yet');
  });
});

describe('BarChart', () => {
  it('renders one bar per data point', () => {
    render(<BarChart data={points} ariaLabel="Credential issuance" />);

    const chart = screen.getByTestId('bar-chart');
    expect(chart).toHaveAccessibleName('Credential issuance');
    expect(chart.querySelectorAll('rect')).toHaveLength(points.length);
  });

  it('labels bars with their value', () => {
    render(<BarChart data={points} ariaLabel="Issuance" />);

    const labels = screen.getAllByTestId('bar-value').map((node) => node.textContent);
    expect(labels).toEqual(['12', '30', '18']);
  });

  it('hides value labels when the series is dense', () => {
    const dense: ChartPoint[] = Array.from({ length: 20 }, (_, index) => ({
      label: `d${index}`,
      value: index + 1,
    }));

    render(<BarChart data={dense} ariaLabel="Dense" />);

    expect(screen.queryAllByTestId('bar-value')).toHaveLength(0);
  });

  it('can hide value labels explicitly', () => {
    render(<BarChart data={points} ariaLabel="Issuance" showValues={false} />);

    expect(screen.queryAllByTestId('bar-value')).toHaveLength(0);
  });

  it('highlights the hovered bar', () => {
    render(<BarChart data={points} ariaLabel="Issuance" />);
    const bars = screen.getByTestId('bar-chart').querySelectorAll('rect');

    expect(bars[1].getAttribute('fill-opacity')).toBe('0.85');

    fireEvent.mouseOver(bars[1]);

    expect(bars[1].getAttribute('fill-opacity')).toBe('1');
  });

  it('shows an empty state for an empty series', () => {
    render(<BarChart data={[]} ariaLabel="Issuance" />);

    expect(screen.getByRole('status')).toBeInTheDocument();
  });
});

describe('DonutChart', () => {
  const segments = [
    { label: 'Successful', value: 92, color: 'green' },
    { label: 'Failed', value: 8, color: 'red' },
  ];

  it('renders one arc per segment plus a legend', () => {
    render(<DonutChart segments={segments} ariaLabel="Verification outcomes" />);

    expect(screen.getByTestId('donut-chart').querySelectorAll('circle')).toHaveLength(2);
    expect(screen.getByText('Successful')).toBeInTheDocument();
    expect(screen.getByText('Failed')).toBeInTheDocument();
  });

  it('describes each arc with its share of the total', () => {
    render(<DonutChart segments={segments} ariaLabel="Verification outcomes" />);

    expect(screen.getByText('Successful: 92 (92.0%)')).toBeInTheDocument();
  });

  it('renders the centred headline value', () => {
    render(
      <DonutChart
        segments={segments}
        ariaLabel="Verification outcomes"
        centerLabel="92%"
        centerCaption="verified"
      />
    );

    const chart = screen.getByTestId('donut-chart');
    expect(chart).toHaveTextContent('92%');
    expect(chart).toHaveTextContent('verified');
  });

  it('shows an empty state when there is nothing to plot', () => {
    const { unmount } = render(<DonutChart segments={[]} ariaLabel="Outcomes" />);
    expect(screen.getByRole('status')).toBeInTheDocument();
    unmount();

    render(
      <DonutChart
        segments={[{ label: 'Failed', value: 0, color: 'red' }]}
        ariaLabel="Outcomes"
      />
    );
    expect(screen.getByRole('status')).toBeInTheDocument();
  });
});
