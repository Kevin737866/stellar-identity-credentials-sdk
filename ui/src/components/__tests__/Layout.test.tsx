import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { Layout, NavItem } from '../Layout';

const navItems: NavItem[] = [
  { id: 'credentials', label: 'Credentials' },
  { id: 'proofs', label: 'Proofs' },
  { id: 'compliance', label: 'Compliance' },
];

function setViewportWidth(width: number) {
  Object.defineProperty(window, 'innerWidth', {
    writable: true,
    configurable: true,
    value: width,
  });
}

function renderLayout(props: Partial<React.ComponentProps<typeof Layout>> = {}) {
  return render(
    <Layout navItems={navItems} activeItem="credentials" {...props}>
      <p>Page content</p>
    </Layout>
  );
}

afterEach(() => {
  setViewportWidth(1024);
});

describe('Layout on mobile (320px)', () => {
  beforeEach(() => setViewportWidth(320));

  it('offers a hamburger instead of a persistent sidebar', () => {
    renderLayout();

    expect(screen.getByRole('button', { name: /open navigation/i })).toBeInTheDocument();
    expect(screen.getByLabelText('Sidebar')).toHaveAttribute('aria-hidden', 'true');
  });

  it('opens the drawer and shows a dismissible backdrop', () => {
    renderLayout();

    expect(screen.queryByTestId('layout-backdrop')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }));

    expect(screen.getByTestId('layout-backdrop')).toBeInTheDocument();
    expect(screen.getByLabelText('Sidebar')).not.toHaveAttribute('aria-hidden');
  });

  it('closes the drawer when the backdrop is pressed', () => {
    renderLayout();

    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }));
    fireEvent.click(screen.getByTestId('layout-backdrop'));

    expect(screen.queryByTestId('layout-backdrop')).not.toBeInTheDocument();
  });

  it('closes the drawer on Escape', () => {
    renderLayout();

    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }));
    fireEvent.keyDown(window, { key: 'Escape' });

    expect(screen.queryByTestId('layout-backdrop')).not.toBeInTheDocument();
  });

  it('renders a bottom navigation bar for thumb reach', () => {
    renderLayout();

    const bottomNav = screen.getByRole('navigation', { name: 'Mobile' });
    expect(bottomNav).toHaveClass('si-bottom-nav');
    expect(bottomNav.querySelectorAll('button')).toHaveLength(navItems.length);
  });

  it('reserves space below the content for the bottom bar', () => {
    renderLayout();

    expect(screen.getByRole('main')).toHaveClass('si-has-bottom-nav');
  });

  it('navigates from the bottom bar and dismisses the drawer in one action', () => {
    const onNavChange = jest.fn();
    renderLayout({ onNavChange });

    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }));
    const bottomNav = screen.getByRole('navigation', { name: 'Mobile' });
    fireEvent.click(within(bottomNav).getByRole('button', { name: 'Proofs' }));

    expect(onNavChange).toHaveBeenCalledWith('proofs');
    expect(screen.queryByTestId('layout-backdrop')).not.toBeInTheDocument();
  });

  it('navigates from the drawer for destinations beyond the bottom bar', () => {
    const onNavChange = jest.fn();
    renderLayout({ onNavChange });

    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }));
    const sidebar = screen.getByLabelText('Sidebar');
    fireEvent.click(within(sidebar).getByRole('button', { name: 'Compliance' }));

    expect(onNavChange).toHaveBeenCalledWith('compliance');
    expect(screen.queryByTestId('layout-backdrop')).not.toBeInTheDocument();
  });

  it('closes the drawer when the viewport grows to desktop', () => {
    renderLayout();

    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }));
    expect(screen.getByTestId('layout-backdrop')).toBeInTheDocument();

    act(() => {
      setViewportWidth(1280);
      window.dispatchEvent(new Event('resize'));
    });

    expect(screen.queryByTestId('layout-backdrop')).not.toBeInTheDocument();
  });
});

describe('Layout on desktop (1280px)', () => {
  beforeEach(() => setViewportWidth(1280));

  it('hides the hamburger once the sidebar is persistent', () => {
    renderLayout();

    expect(screen.queryByRole('button', { name: /open navigation/i })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Sidebar')).not.toHaveAttribute('aria-hidden');
  });

  it('does not reserve space for a bottom bar', () => {
    renderLayout();

    expect(screen.getByRole('main')).not.toHaveClass('si-has-bottom-nav');
  });

  it('collapses and expands the sidebar', () => {
    renderLayout();

    fireEvent.click(screen.getByRole('button', { name: /collapse sidebar/i }));

    const expand = screen.getByRole('button', { name: /expand sidebar/i });
    expect(expand).toHaveAttribute('aria-expanded', 'false');
  });
});
