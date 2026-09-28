import React, { useCallback, useEffect, useState } from 'react';
import { useBreakpoint } from '../hooks/useBreakpoint';
import { Button } from './ui/button';
import { MobileNav } from './MobileNav';

export interface NavItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
  /** Optional decoration such as an unread count. */
  badge?: React.ReactNode;
}

export interface LayoutProps {
  navItems?: NavItem[];
  activeItem?: string;
  onNavChange?: (id: string) => void;
  header?: React.ReactNode;
  children: React.ReactNode;
}

const navItemStyle = (isActive: boolean, collapsed: boolean): React.CSSProperties => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: collapsed ? 'center' : 'flex-start',
  gap: 'var(--space-3)',
  width: '100%',
  minHeight: 'var(--touch-target-min)',
  padding: 'var(--space-2) var(--space-3)',
  borderRadius: 'var(--radius-md)',
  border: 'none',
  backgroundColor: isActive ? 'var(--color-primary-50)' : 'transparent',
  color: isActive ? 'var(--color-primary-700)' : 'var(--color-text-secondary)',
  fontWeight: (isActive ? 'var(--font-weight-medium)' : 'var(--font-weight-normal)') as never,
  fontSize: 'var(--font-size-sm)',
  fontFamily: 'var(--font-family)',
  cursor: 'pointer',
  marginBottom: 'var(--space-1)',
  textAlign: 'left',
  transition: 'background-color var(--transition-fast)',
});

const navBadgeStyle: React.CSSProperties = {
  marginLeft: 'auto',
  minWidth: '18px',
  padding: '0 var(--space-1)',
  borderRadius: 'var(--radius-full)',
  backgroundColor: 'var(--color-primary-100)',
  color: 'var(--color-primary-700)',
  fontSize: 'var(--font-size-xs)',
  textAlign: 'center',
};

interface SidebarNavProps {
  navItems: NavItem[];
  activeItem?: string;
  collapsed: boolean;
  onNavChange?: (id: string) => void;
}

const SidebarNav: React.FC<SidebarNavProps> = ({
  navItems,
  activeItem,
  collapsed,
  onNavChange,
}) => (
  <nav aria-label="Primary" style={{ flex: 1, padding: 'var(--space-2)', overflowY: 'auto' }}>
    {navItems.map((item) => {
      const isActive = activeItem === item.id;
      return (
        <button
          key={item.id}
          type="button"
          onClick={() => onNavChange?.(item.id)}
          aria-current={isActive ? 'page' : undefined}
          style={navItemStyle(isActive, collapsed)}
        >
          {item.icon ? <span style={{ flexShrink: 0, display: 'flex' }}>{item.icon}</span> : null}
          {!collapsed ? <span>{item.label}</span> : null}
          {!collapsed && item.badge ? <span style={navBadgeStyle}>{item.badge}</span> : null}
        </button>
      );
    })}
  </nav>
);

/**
 * Application shell.
 *
 * Mobile-first: below the tablet breakpoint the sidebar becomes an off-canvas
 * drawer opened from the header, plus a thumb-reachable bottom navigation bar.
 * From the tablet breakpoint up it is a persistent (collapsible) sidebar and the
 * bottom bar is hidden by CSS.
 */
export const Layout: React.FC<LayoutProps> = ({
  navItems = [],
  activeItem,
  onNavChange,
  header,
  children,
}) => {
  const { isMobile } = useBreakpoint();
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Never leave the mobile drawer open when the viewport grows.
  useEffect(() => {
    if (!isMobile) {
      setDrawerOpen(false);
    }
  }, [isMobile]);

  useEffect(() => {
    if (!isMobile || !drawerOpen) {
      return undefined;
    }
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setDrawerOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isMobile, drawerOpen]);

  const handleNavChange = useCallback(
    (id: string) => {
      onNavChange?.(id);
      setDrawerOpen(false);
    },
    [onNavChange]
  );

  const sidebarWidth = collapsed
    ? 'var(--sidebar-width-collapsed)'
    : 'var(--sidebar-width)';
  const sidebarOffset = isMobile ? '100%' : sidebarWidth;
  const showSidebar = !isMobile || drawerOpen;

  return (
    <div
      style={{
        display: 'flex',
        minHeight: '100vh',
        fontFamily: 'var(--font-family)',
        backgroundColor: 'var(--color-bg-secondary)',
        color: 'var(--color-text)',
      }}
    >
      {/* Mobile drawer backdrop */}
      {isMobile && drawerOpen ? (
        <div
          data-testid="layout-backdrop"
          onClick={() => setDrawerOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 39,
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
          }}
        />
      ) : null}

      {/* Sidebar / drawer */}
      <aside
        id="layout-sidebar"
        aria-label="Sidebar"
        aria-hidden={isMobile && !drawerOpen ? true : undefined}
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          bottom: 0,
          zIndex: 40,
          width: isMobile ? 'var(--sidebar-width)' : sidebarWidth,
          display: 'flex',
          flexDirection: 'column',
          backgroundColor: 'var(--color-bg)',
          borderRight: '1px solid var(--color-border)',
          transform: showSidebar ? 'translateX(0)' : `translateX(-${sidebarOffset})`,
          transition: 'transform var(--transition-slow), width var(--transition-slow)',
        }}
      >
        <div
          style={{
            minHeight: 'var(--header-height)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 'var(--space-2)',
            padding: '0 var(--space-3)',
            borderBottom: '1px solid var(--color-border)',
          }}
        >
          {(!collapsed || isMobile) && (
            <span
              style={{
                fontSize: 'var(--font-size-lg)',
                fontWeight: 'var(--font-weight-bold)' as never,
                color: 'var(--color-primary-600)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
              }}
            >
              Stellar ID
            </span>
          )}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => (isMobile ? setDrawerOpen(false) : setCollapsed(!collapsed))}
            aria-label={
              isMobile
                ? 'Close navigation'
                : collapsed
                  ? 'Expand sidebar'
                  : 'Collapse sidebar'
            }
            aria-expanded={isMobile ? drawerOpen : !collapsed}
          >
            {isMobile ? '×' : collapsed ? '→' : '←'}
          </Button>
        </div>

        <SidebarNav
          navItems={navItems}
          activeItem={activeItem}
          collapsed={collapsed && !isMobile}
          onNavChange={handleNavChange}
        />
      </aside>

      {/* Main column */}
      <div
        style={{
          flex: 1,
          minWidth: 0,
          display: 'flex',
          flexDirection: 'column',
          marginLeft: isMobile ? 0 : sidebarWidth,
          transition: 'margin-left var(--transition-slow)',
        }}
      >
        <header
          style={{
            minHeight: 'var(--header-height)',
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-3)',
            padding: '0 var(--space-4)',
            backgroundColor: 'var(--color-bg)',
            borderBottom: '1px solid var(--color-border)',
            position: 'sticky',
            top: 0,
            zIndex: 30,
          }}
        >
          {isMobile ? (
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setDrawerOpen(true)}
              aria-label="Open navigation"
              aria-expanded={drawerOpen}
              aria-controls="layout-sidebar"
            >
              ☰
            </Button>
          ) : null}
          {header}
        </header>

        <main
          className={isMobile && navItems.length > 0 ? 'si-has-bottom-nav' : undefined}
          style={{
            flex: 1,
            width: '100%',
            maxWidth: 'var(--content-max-width)',
            margin: '0 auto',
            padding: isMobile ? 'var(--space-4)' : 'var(--space-6)',
            boxSizing: 'border-box',
          }}
        >
          {children}
        </main>
      </div>

      {navItems.length > 0 ? (
        <MobileNav
          items={navItems}
          activeId={activeItem}
          onSelect={handleNavChange}
          label="Mobile"
        />
      ) : null}
    </div>
  );
};
