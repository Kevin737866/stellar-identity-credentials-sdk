import React, { useCallback, useEffect, useId, useRef, useState } from 'react';

export interface SelectProps {
  value?: string;
  onValueChange?: (value: string) => void;
  children: React.ReactNode;
  /** Accessible name for the trigger when there is no visible label. */
  'aria-label'?: string;
  disabled?: boolean;
}

interface SelectContextValue {
  value?: string;
  onValueChange?: (value: string) => void;
  open: boolean;
  setOpen: (open: boolean) => void;
  /** Move DOM focus to the trigger, e.g. after Escape closes the list. */
  focusTrigger: () => void;
  registerItem: (value: string, node: HTMLElement | null) => void;
  activeItemValue: string | null;
  setActiveItemValue: (value: string | null) => void;
  triggerId: string;
  listboxId: string;
}

const SelectContext = React.createContext<SelectContextValue | null>(null);

function useSelectContext(component: string): SelectContextValue {
  const context = React.useContext(SelectContext);
  if (!context) {
    throw new Error(`${component} must be rendered inside a <Select>`);
  }
  return context;
}

export const Select: React.FC<SelectProps> = ({
  value,
  onValueChange,
  children,
  disabled,
  ...rest
}) => {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const itemsRef = useRef<Map<string, HTMLElement>>(new Map());
  const [activeItemValue, setActiveItemValue] = useState<string | null>(null);
  const baseId = useId();

  const focusTrigger = useCallback(() => {
    triggerRef.current?.focus();
  }, []);

  const registerItem = useCallback((itemValue: string, node: HTMLElement | null) => {
    if (node) {
      itemsRef.current.set(itemValue, node);
    } else {
      itemsRef.current.delete(itemValue);
    }
  }, []);

  return (
    <SelectContext.Provider
      value={{
        value,
        onValueChange,
        open,
        setOpen,
        focusTrigger,
        registerItem,
        activeItemValue,
        setActiveItemValue,
        triggerId: `${baseId}-trigger`,
        listboxId: `${baseId}-listbox`,
      }}
    >
      <div style={{ position: 'relative' }} data-disabled={disabled || undefined}>
        {React.Children.map(children, child => {
          // The trigger needs the ref and generated id, which are internal
          // plumbing the caller should not have to wire up.
          if (React.isValidElement(child) && (child.type as any)?.displayName === 'SelectTrigger') {
            const props = child.props as Record<string, unknown>;
            if (props['aria-label'] || rest['aria-label']) return child;
            return React.cloneElement(child as React.ReactElement<any>, {
              'aria-label': rest['aria-label'] ?? 'Select an option',
            });
          }
          return child;
        })}
      </div>
    </SelectContext.Provider>
  );
};
Select.displayName = 'Select';

export interface SelectTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
}

export const SelectTrigger = React.forwardRef<HTMLButtonElement, SelectTriggerProps>(
  ({ style, children, onKeyDown, ...props }, forwardedRef) => {
    const { open, setOpen, focusTrigger, triggerId, listboxId } = useSelectContext('SelectTrigger');
    const localRef = useRef<HTMLButtonElement | null>(null);

    const setRef = (node: HTMLButtonElement | null) => {
      localRef.current = node;
      if (typeof forwardedRef === 'function') forwardedRef(node);
      else if (forwardedRef) {
        (forwardedRef as React.MutableRefObject<HTMLButtonElement | null>).current = node;
      }
    };

    const handleKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>) => {
      onKeyDown?.(event);
      if (event.defaultPrevented) return;

      switch (event.key) {
        case 'ArrowDown':
        case 'ArrowUp':
        case 'Enter':
        case ' ':
          event.preventDefault();
          setOpen(true);
          break;
        case 'Escape':
          if (open) {
            event.preventDefault();
            setOpen(false);
          }
          break;
        default:
          break;
      }
    };

    return (
      <button
        ref={setRef}
        id={triggerId}
        type="button"
        role="combobox"
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={open ? listboxId : undefined}
        // A closed combobox is a single tab stop; arrows open it rather than
        // moving focus between options.
        aria-activedescendant={undefined}
        onClick={() => setOpen(!open)}
        onKeyDown={handleKeyDown}
        style={{
          display: 'flex',
          width: '100%',
          height: '40px',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-bg)',
          padding: 'var(--space-2) var(--space-3)',
          fontSize: 'var(--font-size-sm)',
          fontFamily: 'var(--font-family)',
          color: 'var(--color-text)',
          cursor: 'pointer',
          ...style,
        }}
        {...props}
      >
        {children}
      </button>
    );
  }
);
SelectTrigger.displayName = 'SelectTrigger';

export interface SelectValueProps {
  placeholder?: string;
}

export const SelectValue: React.FC<SelectValueProps> = ({ placeholder }) => {
  const { value } = useSelectContext('SelectValue');
  return (
    <span style={{ color: value ? 'var(--color-text)' : 'var(--color-text-tertiary)' }}>
      {value || placeholder}
    </span>
  );
};
SelectValue.displayName = 'SelectValue';

export interface SelectContentProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const SelectContent = React.forwardRef<HTMLDivElement, SelectContentProps>(
  ({ style, children, ...props }, forwardedRef) => {
    const { open, setOpen, focusTrigger, registerItem, activeItemValue, setActiveItemValue, listboxId } =
      useSelectContext('SelectContent');
    const contentRef = useRef<HTMLDivElement | null>(null);
    const [items, setItems] = useState<Array<{ value: string; node: HTMLElement }>>([]);

    const setRef = (node: HTMLDivElement | null) => {
      contentRef.current = node;
      if (typeof forwardedRef === 'function') forwardedRef(node);
      else if (forwardedRef) {
        (forwardedRef as React.MutableRefObject<HTMLDivElement | null>).current = node;
      }
    };

    // Collect the rendered options so arrow keys can move between them.
    useEffect(() => {
      if (!open || !contentRef.current) {
        setItems([]);
        return;
      }
      const options = Array.from(contentRef.current.querySelectorAll<HTMLElement>('[role="option"]'));
      setItems(options.map(node => ({ value: node.getAttribute('data-value') ?? '', node })));
    }, [open, children]);

    // Start on the selected option, or the first one.
    useEffect(() => {
      if (!open || items.length === 0) return;
      const preferred = items.find(item => item.value === activeItemValue) ?? items[0];
      setActiveItemValue(preferred.value);
      preferred.node.scrollIntoView?.({ block: 'nearest' });
    }, [open, items]);

    const moveActive = (delta: number) => {
      if (items.length === 0) return;
      const currentIndex = items.findIndex(item => item.value === activeItemValue);
      const nextIndex = (currentIndex + delta + items.length) % items.length;
      const next = items[nextIndex];
      setActiveItemValue(next.value);
      next.node.scrollIntoView?.({ block: 'nearest' });
    };

    const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
      switch (event.key) {
        case 'ArrowDown':
          event.preventDefault();
          moveActive(1);
          break;
        case 'ArrowUp':
          event.preventDefault();
          moveActive(-1);
          break;
        case 'Home':
          event.preventDefault();
          if (items[0]) setActiveItemValue(items[0].value);
          break;
        case 'End':
          event.preventDefault();
          if (items.length > 0) setActiveItemValue(items[items.length - 1].value);
          break;
        case 'Enter':
        case ' ': {
          event.preventDefault();
          const active = items.find(item => item.value === activeItemValue);
          if (active) {
            active.node.click();
          }
          break;
        }
        case 'Tab':
          // Tabbing out commits the active option and closes, matching native
          // <select> behaviour.
          if (activeItemValue) {
            items.find(item => item.value === activeItemValue)?.node.click();
          }
          setOpen(false);
          break;
        case 'Escape':
          event.preventDefault();
          setOpen(false);
          focusTrigger();
          break;
        default:
          break;
      }
    };

    useEffect(() => {
      if (!open) return;

      const handleClickOutside = (e: MouseEvent) => {
        if (contentRef.current && !contentRef.current.contains(e.target as Node)) {
          const trigger = contentRef.current.closest('div')?.querySelector('[role="combobox"]');
          if (trigger && !trigger.contains(e.target as Node)) {
            setOpen(false);
          }
        }
      };

      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [open, setOpen]);

    if (!open) return null;

    return (
      <div
        ref={setRef}
        id={listboxId}
        role="listbox"
        aria-labelledby="undefined"
        onKeyDown={handleKeyDown}
        style={{
          position: 'absolute',
          top: '100%',
          left: 0,
          right: 0,
          zIndex: 50,
          marginTop: 'var(--space-1)',
          backgroundColor: 'var(--color-bg)',
          border: '1px solid var(--color-border)',
          borderRadius: 'var(--radius-md)',
          boxShadow: 'var(--shadow-md)',
          padding: 'var(--space-1)',
          maxHeight: '200px',
          overflowY: 'auto',
          ...style,
        }}
        {...props}
      >
        {children}
      </div>
    );
  }
);
SelectContent.displayName = 'SelectContent';

export interface SelectItemProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
  children: React.ReactNode;
}

export const SelectItem = React.forwardRef<HTMLDivElement, SelectItemProps>(
  ({ value: itemValue, style, children, onKeyDown, onClick, ...props }, forwardedRef) => {
    const { value, onValueChange, setOpen, activeItemValue, registerItem } =
      useSelectContext('SelectItem');
    const isSelected = value === itemValue;
    const isActive = activeItemValue === itemValue;
    const localRef = useRef<HTMLDivElement | null>(null);

    const setRef = (node: HTMLDivElement | null) => {
      localRef.current = node;
      registerItem(itemValue, node);
      if (typeof forwardedRef === 'function') forwardedRef(node);
      else if (forwardedRef) {
        (forwardedRef as React.MutableRefObject<HTMLDivElement | null>).current = node;
      }
    };

    const handleClick = (event: React.MouseEvent) => {
      onClick?.(event);
      onValueChange?.(itemValue);
      setOpen(false);
    };

    const handleKeyDown = (event: React.KeyboardEvent) => {
      onKeyDown?.(event);
      if (event.defaultPrevented) return;
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        handleClick(event as unknown as React.MouseEvent);
      }
    };

    return (
      <div
        ref={setRef}
        role="option"
        id={`option-${itemValue}`}
        data-value={itemValue}
        aria-selected={isSelected}
        // The active option is the one the keyboard is currently on, which is
        // distinct from the selected one.
        data-active={isActive || undefined}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
        style={{
          display: 'flex',
          alignItems: 'center',
          padding: 'var(--space-2) var(--space-3)',
          borderRadius: 'var(--radius-sm)',
          fontSize: 'var(--font-size-sm)',
          fontFamily: 'var(--font-family)',
          cursor: 'pointer',
          backgroundColor: isActive
            ? 'var(--color-bg-tertiary)'
            : isSelected
              ? 'var(--color-bg-secondary)'
              : 'transparent',
          color: 'var(--color-text)',
          ...style,
        }}
        {...props}
      >
        {children}
      </div>
    );
  }
);
SelectItem.displayName = 'SelectItem';
