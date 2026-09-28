import { useEffect, useState } from 'react';

/**
 * Layout breakpoints, mirroring the values in `styles/responsive.css`.
 * `mobile` covers the smallest supported viewport (320px).
 */
export const BREAKPOINTS = {
  tablet: 768,
  desktop: 1024,
} as const;

export type Breakpoint = 'mobile' | 'tablet' | 'desktop';

export interface BreakpointInfo {
  /** The active breakpoint name. */
  breakpoint: Breakpoint;
  /** Current viewport width in pixels. */
  width: number;
  isMobile: boolean;
  isTablet: boolean;
  isDesktop: boolean;
}

/** Classify a viewport width into a breakpoint name. */
export function getBreakpoint(width: number): Breakpoint {
  if (width >= BREAKPOINTS.desktop) return 'desktop';
  if (width >= BREAKPOINTS.tablet) return 'tablet';
  return 'mobile';
}

/** True when `window` and `matchMedia` are usable (SSR and jsdom safe). */
function canUseMatchMedia(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    typeof window.innerWidth === 'number'
  );
}

/** Read the current viewport width without touching the DOM during SSR. */
export function getViewportWidth(): number {
  if (typeof window === 'undefined' || typeof window.innerWidth !== 'number') {
    // Assume the smallest supported viewport when there is no window.
    return 320;
  }
  return window.innerWidth;
}

/**
 * Subscribe to a CSS media query, re-rendering when it changes.
 *
 * Falls back to a `resize` listener when `matchMedia` is unavailable, so the
 * hook keeps working in jsdom and older embedded webviews.
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState<boolean>(() =>
    canUseMatchMedia() ? window.matchMedia(query).matches : false
  );

  useEffect(() => {
    if (!canUseMatchMedia()) {
      return;
    }

    const mql = window.matchMedia(query);
    const handleChange = (event: MediaQueryListEvent) => setMatches(event.matches);

    setMatches(mql.matches);

    // Safari < 14 only implements the deprecated addListener API.
    if (typeof mql.addEventListener === 'function') {
      mql.addEventListener('change', handleChange);
      return () => mql.removeEventListener('change', handleChange);
    }

    mql.addListener(handleChange);
    return () => mql.removeListener(handleChange);
  }, [query]);

  return matches;
}

/** Track the viewport width, updating on resize and orientation changes. */
export function useViewportWidth(): number {
  const [width, setWidth] = useState<number>(getViewportWidth);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    const handleResize = () => setWidth(getViewportWidth());
    handleResize();

    window.addEventListener('resize', handleResize);
    window.addEventListener('orientationchange', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('orientationchange', handleResize);
    };
  }, []);

  return width;
}

/**
 * Describe the current breakpoint. Components should prefer this over reading
 * `window.innerWidth` directly so that server rendering and tests stay stable.
 *
 * The measured viewport width is the single source of truth, which keeps the
 * reported breakpoint consistent with what the CSS media queries render.
 */
export function useBreakpoint(): BreakpointInfo {
  const width = useViewportWidth();
  const breakpoint = getBreakpoint(width);

  return {
    breakpoint,
    width,
    isMobile: breakpoint === 'mobile',
    isTablet: breakpoint === 'tablet',
    isDesktop: breakpoint === 'desktop',
  };
}
