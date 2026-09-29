import React from 'react';

/** Item id used for the overflow entry when `items` exceeds `maxItems`. */
export const MOBILE_NAV_MORE_ID = 'more';

export interface MobileNavItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
  /** Optional decoration such as an unread count. */
  badge?: React.ReactNode;
}

export interface MobileNavProps {
  items: MobileNavItem[];
  activeId?: string;
  onSelect?: (id: string) => void;
  /** Accessible name for the navigation landmark. */
  label?: string;
  /**
   * Maximum destinations rendered. Thumb-reachable bottom bars stay usable up
   * to five entries; anything beyond that collapses into a "More" entry.
   */
  maxItems?: number;
}

const badgeStyle: React.CSSProperties = {
  position: 'absolute',
  top: '2px',
  right: '25%',
  minWidth: '16px',
  height: '16px',
  padding: '0 4px',
  borderRadius: 'var(--radius-full)',
  backgroundColor: 'var(--color-danger-600)',
  color: '#ffffff',
  fontSize: '10px',
  lineHeight: '16px',
  fontWeight: 'var(--font-weight-semibold)' as unknown as number,
};

/** Trim the list to `maxItems`, replacing the last slot with a "More" entry. */
function withOverflow(items: MobileNavItem[], maxItems: number): MobileNavItem[] {
  if (items.length <= maxItems) {
    return items;
  }
  const visible = items.slice(0, Math.max(1, maxItems - 1));
  return [
    ...visible,
    { id: MOBILE_NAV_MORE_ID, label: 'More' },
  ];
}

/**
 * Thumb-reachable bottom navigation for small viewports.
 *
 * Hidden at and above the tablet breakpoint by `styles/responsive.css`, so the
 * desktop sidebar remains the single navigation surface on large screens. Pair
 * it with `si-has-bottom-nav` on the scroll container to reserve space.
 */
export const MobileNav: React.FC<MobileNavProps> = ({
  items,
  activeId,
  onSelect,
  label = 'Primary',
  maxItems = 5,
}) => {
  const visibleItems = withOverflow(items, maxItems);

  return (
    <nav className="si-bottom-nav" aria-label={label}>
      {visibleItems.map((item) => {
        const isActive = activeId === item.id;
        return (
          <button
            key={item.id}
            type="button"
            className="si-bottom-nav__item"
            aria-current={isActive ? 'page' : undefined}
            onClick={() => onSelect?.(item.id)}
            style={{ position: 'relative' }}
          >
            {item.icon}
            <span className="si-bottom-nav__label">{item.label}</span>
            {item.badge ? (
              <span style={badgeStyle} aria-hidden="true">
                {item.badge}
              </span>
            ) : null}
          </button>
        );
      })}
    </nav>
  );
};
