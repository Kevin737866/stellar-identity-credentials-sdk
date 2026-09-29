import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MOBILE_NAV_MORE_ID, MobileNav, MobileNavItem } from '../MobileNav';

const items: MobileNavItem[] = [
  { id: 'credentials', label: 'Credentials', icon: <span>1</span> },
  { id: 'proofs', label: 'Proofs' },
  { id: 'compliance', label: 'Compliance', badge: 3 },
];

describe('MobileNav', () => {
  it('renders one touch target per destination', () => {
    render(<MobileNav items={items} />);

    expect(screen.getAllByRole('button')).toHaveLength(items.length);
    items.forEach((item) => {
      expect(screen.getByRole('button', { name: new RegExp(item.label) })).toBeInTheDocument();
    });
  });

  it('exposes the navigation landmark with an accessible name', () => {
    render(<MobileNav items={items} label="Main navigation" />);

    expect(screen.getByRole('navigation', { name: 'Main navigation' })).toHaveClass('si-bottom-nav');
  });

  it('marks the active destination with aria-current', () => {
    render(<MobileNav items={items} activeId="proofs" />);

    expect(screen.getByRole('button', { name: /proofs/i })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('button', { name: /compliance/i })).not.toHaveAttribute('aria-current');
  });

  it('notifies the parent when a destination is selected', () => {
    const onSelect = jest.fn();
    render(<MobileNav items={items} onSelect={onSelect} />);

    fireEvent.click(screen.getByRole('button', { name: /compliance/i }));

    expect(onSelect).toHaveBeenCalledWith('compliance');
  });

  it('renders an optional badge on a destination', () => {
    render(<MobileNav items={items} />);

    expect(screen.getByText('3')).toHaveAttribute('aria-hidden', 'true');
  });

  it('collapses destinations beyond maxItems into a More entry', () => {
    const many: MobileNavItem[] = Array.from({ length: 8 }, (_, index) => ({
      id: `item-${index}`,
      label: `Item ${index}`,
    }));

    render(<MobileNav items={many} onSelect={jest.fn()} maxItems={4} />);

    expect(screen.getAllByRole('button')).toHaveLength(4);
    expect(screen.getByRole('button', { name: /more/i })).toBeInTheDocument();
  });

  it('does not add a More entry when every destination fits', () => {
    render(<MobileNav items={items} maxItems={5} />);

    expect(screen.queryByRole('button', { name: /more/i })).not.toBeInTheDocument();
  });

  it('reports the overflow destination id when More is selected', () => {
    const onSelect = jest.fn();
    const many: MobileNavItem[] = Array.from({ length: 7 }, (_, index) => ({
      id: `item-${index}`,
      label: `Item ${index}`,
    }));

    render(<MobileNav items={many} onSelect={onSelect} maxItems={3} />);
    fireEvent.click(screen.getByRole('button', { name: /more/i }));

    expect(onSelect).toHaveBeenCalledWith(MOBILE_NAV_MORE_ID);
  });
});
