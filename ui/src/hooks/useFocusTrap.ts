import React, { useCallback, useEffect, useRef, useState } from 'react';

/** Elements that can hold focus, in DOM order. */
const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

/**
 * Collect the focusable descendants of `container`, skipping anything hidden.
 *
 * `offsetParent` is the check because an element inside a `display: none`
 * ancestor reports `null` there but is still matched by the selector, which
 * would otherwise put an invisible element in the tab order.
 */
export function getFocusableElements(container: HTMLElement | null): HTMLElement[] {
  if (!container) return [];

  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    element =>
      !element.hasAttribute('disabled') &&
      element.getAttribute('aria-hidden') !== 'true' &&
      (element.offsetParent !== null || element.getClientRects().length > 0),
  );
}

export interface FocusTrapOptions {
  /** Trap Tab and Shift+Tab inside the container. Default true. */
  trapTab?: boolean;
  /** Close on Escape and invoke this callback. */
  onEscape?: () => void;
  /** Focus this element on activation instead of the first focusable one. */
  initialFocus?: React.RefObject<HTMLElement>;
  /** Return focus to this element on deactivation. */
  returnFocus?: boolean;
  /** Turn the trap off without unmounting, e.g. while a confirmation renders. */
  enabled?: boolean;
}

/**
 * Trap keyboard focus inside a container and restore it on unmount.
 *
 * Focus is moved into the container on activation and returned to whatever was
 * focused before on deactivation, so a keyboard user is never dropped at the
 * top of the document after closing a dialog. Escape is handled here because
 * every overlay in the design system needs it.
 *
 * @param isActive - Whether the container is currently showing.
 * @returns A ref to attach to the container element.
 */
export function useFocusTrap<T extends HTMLElement = HTMLElement>(
  isActive: boolean,
  options: FocusTrapOptions = {},
): React.RefObject<T> {
  const { trapTab = true, onEscape, initialFocus, returnFocus = true, enabled = true } = options;
  const containerRef = useRef<T>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);

  const active = isActive && enabled;

  useEffect(() => {
    if (!active) return;

    const container = containerRef.current;
    if (!container) return;

    previouslyFocusedRef.current = document.activeElement as HTMLElement | null;

    // Move focus in. Prefer an explicit target, else the first focusable, else
    // the container itself so focus never stays behind the overlay.
    const focusInitial = () => {
      if (initialFocus?.current) {
        initialFocus.current.focus();
        return;
      }
      const [first] = getFocusableElements(container);
      if (first) {
        first.focus();
      } else {
        if (!container.hasAttribute('tabindex')) {
          container.setAttribute('tabindex', '-1');
        }
        container.focus();
      }
    };
    focusInitial();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onEscape?.();
        return;
      }
      if (!trapTab || (event.key !== 'Tab' && event.key !== 'Shift')) return;
      if (event.key === 'Shift' && !event.shiftKey) return;

      const focusable = getFocusableElements(containerRef.current);
      if (focusable.length === 0) {
        // Nothing to move to; keep focus on the container.
        event.preventDefault();
        containerRef.current?.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const activeElement = document.activeElement as HTMLElement | null;

      if (event.shiftKey) {
        if (activeElement === first || !containerRef.current?.contains(activeElement)) {
          event.preventDefault();
          last.focus();
        }
        return;
      }

      if (activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      if (returnFocus) {
        const previous = previouslyFocusedRef.current;
        // Only restore if the element is still in the document; React may have
        // unmounted the trigger along with the dialog.
        if (previous && document.body.contains(previous)) {
          previous.focus();
        }
      }
    };
    // `initialFocus` and `onEscape` are intentionally excluded: re-running the
    // effect on every render would steal focus back mid-interaction.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, trapTab, returnFocus, initialFocus]);

  return containerRef;
}

/**
 * Return focus to a specific element when it becomes active.
 *
 * Use for focus management on view switches (list → detail), where the new
 * view should receive focus but there is no overlay to trap.
 */
export function useFocusOnMount<T extends HTMLElement = HTMLElement>(
  isActive: boolean,
): React.RefObject<T> {
  const ref = useRef<T>(null);

  useEffect(() => {
    if (!isActive) return;
    const target = ref.current;
    if (!target) return;

    if (!target.hasAttribute('tabindex')) {
      target.setAttribute('tabindex', '-1');
    }
    target.focus();
  }, [isActive]);

  return ref;
}

/**
 * Handle roving-tabindex keyboard navigation across a horizontal collection
 * such as a tab list or a toolbar.
 *
 * Implements the WAI-ARIA authoring practice: arrow keys move between items,
 * Home/End jump to the ends, and only the active item is in the tab order so
 * Tab itself moves past the whole group.
 *
 * @param count - Number of items in the collection.
 * @param orientation - `horizontal` for Left/Right, `vertical` for Up/Down.
 * @returns The active index plus prop builders to spread onto each item.
 */
export function useRovingIndex(
  count: number,
  orientation: 'horizontal' | 'vertical' = 'horizontal',
): {
  activeIndex: number;
  setActiveIndex: (index: number) => void;
  getItemProps: (index: number) => {
    ref: (node: HTMLElement | null) => void;
    tabIndex: 0 | -1;
    onKeyDown: (event: React.KeyboardEvent) => void;
    onFocus: () => void;
  };
} {
  const [activeIndex, setActiveIndex] = useState(0);
  const itemRefs = useRef<Array<HTMLElement | null>>([]);

  // Clamp when the collection shrinks, so the index cannot point past the end.
  useEffect(() => {
    if (count > 0 && activeIndex > count - 1) {
      setActiveIndex(Math.max(0, count - 1));
    }
  }, [count, activeIndex]);

  const focusItem = useCallback((index: number) => {
    setActiveIndex(index);
    // Focus after React has committed the new tabIndex.
    requestAnimationFrame(() => itemRefs.current[index]?.focus());
  }, []);

  const getItemProps = useCallback(
    (index: number) => ({
      ref: (node: HTMLElement | null) => {
        itemRefs.current[index] = node;
      },
      tabIndex: (index === activeIndex ? 0 : -1) as 0 | -1,
      onFocus: () => setActiveIndex(index),
      onKeyDown: (event: React.KeyboardEvent) => {
        if (count === 0) return;

        const nextKey = orientation === 'horizontal' ? 'ArrowRight' : 'ArrowDown';
        const prevKey = orientation === 'horizontal' ? 'ArrowLeft' : 'ArrowUp';

        let next = index;
        if (event.key === nextKey) next = (index + 1) % count;
        else if (event.key === prevKey) next = (index - 1 + count) % count;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = count - 1;
        else return;

        event.preventDefault();
        focusItem(next);
      },
    }),
    [activeIndex, count, focusItem, orientation],
  );

  return { activeIndex, setActiveIndex, getItemProps };
}
