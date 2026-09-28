import React, { createContext, useContext, useId, useMemo, useRef, useState } from 'react';

interface TabsContextValue {
  value: string;
  setValue: (value: string) => void;
  /** Trigger id for a given tab value, used to wire aria-controls. */
  triggerId: (value: string) => string;
  panelId: (value: string) => string;
  baseId: string;
}

const TabsContext = createContext<TabsContextValue | null>(null);

function useTabsContext(component: string): TabsContextValue {
  const context = useContext(TabsContext);
  if (!context) {
    throw new Error(`${component} must be rendered inside a <Tabs>`);
  }
  return context;
}

export interface TabsProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'onChange'> {
  defaultValue?: string;
  value?: string;
  onValueChange?: (value: string) => void;
}

export const Tabs: React.FC<TabsProps> = ({
  defaultValue = '',
  value: controlledValue,
  onValueChange,
  children,
  ...props
}) => {
  const [internalValue, setInternalValue] = useState(defaultValue);
  const value = controlledValue ?? internalValue;
  const baseId = useId();

  const context = useMemo<TabsContextValue>(
    () => ({
      value,
      setValue: (next: string) => {
        if (controlledValue === undefined) {
          setInternalValue(next);
        }
        onValueChange?.(next);
      },
      triggerId: (tabValue: string) => `${baseId}-tab-${tabValue}`,
      panelId: (tabValue: string) => `${baseId}-panel-${tabValue}`,
      baseId,
    }),
    [value, controlledValue, onValueChange, baseId],
  );

  return (
    <TabsContext.Provider value={context}>
      <div {...props}>{children}</div>
    </TabsContext.Provider>
  );
};

export interface TabsListProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Roving-focus direction. `horizontal` by default, matching the visual layout. */
  orientation?: 'horizontal' | 'vertical';
}

/**
 * Container for a set of tab triggers.
 *
 * Keyboard handling lives here rather than on each trigger so that every
 * existing `Tabs` usage gains arrow-key navigation without call-site changes:
 * Left/Right (or Up/Down) move between tabs, Home/End jump to the ends.
 */
export const TabsList = React.forwardRef<HTMLDivElement, TabsListProps>(
  ({ style, children, orientation = 'horizontal', onKeyDown, ...props }, ref) => {
    const { value, setValue } = useTabsContext('TabsList');
    const localRef = useRef<HTMLDivElement | null>(null);

    const setListRef = (node: HTMLDivElement | null) => {
      localRef.current = node;
      if (typeof ref === 'function') ref(node);
      else if (ref) (ref as React.MutableRefObject<HTMLDivElement | null>).current = node;
    };

    const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
      onKeyDown?.(event);
      if (event.defaultPrevented) return;

      const list = localRef.current;
      if (!list) return;

      const tabs = Array.from(list.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
      if (tabs.length === 0) return;

      const currentIndex = tabs.findIndex(tab => tab.getAttribute('data-value') === value);
      const startIndex = currentIndex === -1 ? 0 : currentIndex;

      const nextKey = orientation === 'horizontal' ? 'ArrowRight' : 'ArrowDown';
      const prevKey = orientation === 'horizontal' ? 'ArrowLeft' : 'ArrowUp';

      let nextIndex: number;
      if (event.key === nextKey) nextIndex = (startIndex + 1) % tabs.length;
      else if (event.key === prevKey) nextIndex = (startIndex - 1 + tabs.length) % tabs.length;
      else if (event.key === 'Home') nextIndex = 0;
      else if (event.key === 'End') nextIndex = tabs.length - 1;
      else return;

      event.preventDefault();
      const nextTab = tabs[nextIndex];
      // Selecting moves the roving tabIndex; focusing follows it.
      nextTab?.focus();
      nextTab?.click();
    };

    return (
      <div
        ref={setListRef}
        role="tablist"
        aria-orientation={orientation}
        onKeyDown={handleKeyDown}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          backgroundColor: 'var(--color-bg-tertiary)',
          borderRadius: 'var(--radius-md)',
          padding: 'var(--space-1)',
          gap: 'var(--space-1)',
          ...style,
        }}
        {...props}
      >
        {children}
      </div>
    );
  }
);
TabsList.displayName = 'TabsList';

export interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
}

export const TabsTrigger = React.forwardRef<HTMLButtonElement, TabsTriggerProps>(
  ({ value: tabValue, style, children, ...props }, ref) => {
    const { value, setValue, triggerId, panelId } = useTabsContext('TabsTrigger');
    const isActive = value === tabValue;
    const triggerRef = useRef<HTMLButtonElement | null>(null);

    // Tabs are presentational, so the name comes from the label. When there is
    // no visible text (icon-only tab), require the caller to supply one.
    if (process.env.NODE_ENV !== 'production' && !children && !props['aria-label']) {
      // eslint-disable-next-line no-console
      console.warn(`TabsTrigger value="${tabValue}" has no label; pass aria-label.`);
    }

    return (
      <button
        ref={node => {
          triggerRef.current = node;
          if (typeof ref === 'function') ref(node);
          else if (ref) (ref as React.MutableRefObject<HTMLButtonElement | null>).current = node;
        }}
        id={triggerId(tabValue)}
        role="tab"
        type="button"
        aria-selected={isActive}
        aria-controls={panelId(tabValue)}
        // Lets TabsList find the active tab without tracking state itself.
        data-value={tabValue}
        // Only the selected tab is in the tab order; arrows move within the list.
        tabIndex={isActive ? 0 : -1}
        data-state={isActive ? 'active' : 'inactive'}
        onClick={() => setValue(tabValue)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 'var(--space-2) var(--space-3)',
          borderRadius: 'var(--radius-sm)',
          border: 'none',
          fontSize: 'var(--font-size-sm)',
          fontWeight: 'var(--font-weight-medium)' as any,
          fontFamily: 'var(--font-family)',
          cursor: 'pointer',
          backgroundColor: isActive ? 'var(--color-bg)' : 'transparent',
          color: isActive ? 'var(--color-text)' : 'var(--color-text-secondary)',
          boxShadow: isActive ? 'var(--shadow-sm)' : 'none',
          transition: 'all var(--transition-fast)',
          ...style,
        }}
        {...props}
      >
        {children}
      </button>
    );
  }
);
TabsTrigger.displayName = 'TabsTrigger';

export interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
  /** Keep the panel mounted while inactive, with `hidden` set. */
  forceMount?: boolean;
}

export const TabsContent = React.forwardRef<HTMLDivElement, TabsContentProps>(
  ({ value: tabValue, style, children, forceMount, ...props }, ref) => {
    const { value, triggerId, panelId } = useTabsContext('TabsContent');
    const isActive = value === tabValue;

    if (!isActive && !forceMount) return null;

    return (
      <div
        ref={ref}
        id={panelId(tabValue)}
        role="tabpanel"
        aria-labelledby={triggerId(tabValue)}
        hidden={!isActive}
        tabIndex={0}
        data-state={isActive ? 'active' : 'inactive'}
        style={{
          marginTop: 'var(--space-4)',
          ...(isActive ? {} : { display: 'none' }),
          ...style,
        }}
        {...props}
      >
        {children}
      </div>
    );
  }
);
TabsContent.displayName = 'TabsContent';
