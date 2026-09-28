import React from 'react';
import { render, screen } from '@testing-library/react';
import { axe } from 'jest-axe';
import {
  Skeleton,
  SkeletonText,
  SkeletonAvatar,
  SkeletonList,
  SkeletonCard,
  SkeletonDetail,
  SkeletonTable,
} from '@/components/ui/skeleton';

describe('Skeleton', () => {
  it('renders a single block', () => {
    render(<Skeleton width={100} height={20} />);
    expect(screen.getAllByTestId('skeleton')).toHaveLength(1);
  });

  it('renders count blocks', () => {
    render(<Skeleton count={4} />);
    expect(screen.getAllByTestId('skeleton')).toHaveLength(4);
  });

  it('wraps multiple blocks in a group', () => {
    render(<Skeleton count={3} />);
    expect(screen.getByTestId('skeleton-group')).toBeInTheDocument();
  });

  it('does not wrap a single block in a group', () => {
    render(<Skeleton />);
    expect(screen.queryByTestId('skeleton-group')).not.toBeInTheDocument();
  });

  it('resolves a 1-12 width shorthand to a percentage', () => {
    const { container } = render(<Skeleton width={6} />);
    expect((container.querySelector('[data-skeleton]') as HTMLElement).style.width).toBe('50%');
  });

  it('treats an out-of-range number width as pixels', () => {
    const { container } = render(<Skeleton width={200} />);
    expect((container.querySelector('[data-skeleton]') as HTMLElement).style.width).toBe('200px');
  });

  it('passes a string width through', () => {
    const { container } = render(<Skeleton width="10rem" />);
    expect((container.querySelector('[data-skeleton]') as HTMLElement).style.width).toBe('10rem');
  });

  it('renders a number height as pixels', () => {
    const { container } = render(<Skeleton height={24} />);
    expect((container.querySelector('[data-skeleton]') as HTMLElement).style.height).toBe('24px');
  });

  it('applies the circular shape', () => {
    const { container } = render(<Skeleton shape="circle" width={40} height={40} />);
    expect((container.querySelector('[data-skeleton]') as HTMLElement).style.borderRadius).toBe('50%');
  });

  it('applies the text shape', () => {
    const { container } = render(<Skeleton shape="text" height={12} />);
    const style = (container.querySelector('[data-skeleton]') as HTMLElement).style;
    expect(style.borderRadius).toContain('radius-sm');
  });

  it('is hidden from assistive technology', () => {
    const { container } = render(<Skeleton />);
    expect(container.querySelector('[data-skeleton]')).toHaveAttribute('aria-hidden', 'true');
  });

  it('carries the shimmer class', () => {
    const { container } = render(<Skeleton />);
    expect(container.querySelector('[data-skeleton]')).toHaveClass('skeleton');
  });

  it('shortens the final line of a group', () => {
    const { container } = render(<Skeleton count={3} width={12} />);
    const blocks = container.querySelectorAll('[data-skeleton]');

    expect((blocks[0] as HTMLElement).style.width).toBe('100%');
    expect((blocks[2] as HTMLElement).style.width).toBe('60%');
  });
});

describe('Skeleton composites', () => {
  it('SkeletonText renders a busy status region', () => {
    render(<SkeletonText lines={4} />);
    expect(screen.getByRole('status')).toHaveAttribute('aria-busy', 'true');
    expect(screen.getAllByTestId('skeleton')).toHaveLength(4);
  });

  it('SkeletonAvatar renders a circle', () => {
    render(<SkeletonAvatar size={64} />);
    expect(screen.getByTestId('skeleton-avatar')).toHaveAttribute('data-skeleton', 'true');
  });

  it('SkeletonList renders the requested number of rows', () => {
    render(<SkeletonList rows={5} />);
    expect(screen.getAllByTestId('skeleton-row')).toHaveLength(5);
    expect(screen.getByRole('status')).toHaveAccessibleName('Loading list');
  });

  it('SkeletonCard renders a card placeholder', () => {
    render(<SkeletonCard />);
    expect(screen.getByTestId('skeleton-card')).toBeInTheDocument();
  });

  it('SkeletonDetail renders the requested number of fields', () => {
    render(<SkeletonDetail fields={8} />);
    expect(screen.getByTestId('skeleton-detail')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveAccessibleName('Loading details');
  });

  it('SkeletonTable renders rows and columns', () => {
    render(<SkeletonTable rows={3} columns={5} />);

    const rows = screen.getAllByTestId('skeleton-table-row');
    expect(rows).toHaveLength(3);
    rows.forEach(row => {
      expect(row.querySelectorAll('[data-skeleton]')).toHaveLength(5);
    });
  });

  it('has no accessibility violations', async () => {
    const { container } = render(
      <div>
        <SkeletonText />
        <SkeletonAvatar />
        <SkeletonList />
        <SkeletonCard />
        <SkeletonDetail />
        <SkeletonTable />
      </div>,
    );

    expect(await axe(container)).toHaveNoViolations();
  });
});
