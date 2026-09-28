import { act, renderHook } from '@testing-library/react';
import { BREAKPOINTS, getBreakpoint, useBreakpoint, useViewportWidth } from '../useBreakpoint';

function setViewportWidth(width: number) {
  Object.defineProperty(window, 'innerWidth', {
    writable: true,
    configurable: true,
    value: width,
  });
  window.dispatchEvent(new Event('resize'));
}

afterEach(() => {
  setViewportWidth(1024);
});

describe('getBreakpoint', () => {
  it('classifies mobile viewports, down to the 320px minimum', () => {
    expect(getBreakpoint(320)).toBe('mobile');
    expect(getBreakpoint(480)).toBe('mobile');
    expect(getBreakpoint(BREAKPOINTS.tablet - 1)).toBe('mobile');
  });

  it('classifies tablet viewports', () => {
    expect(getBreakpoint(BREAKPOINTS.tablet)).toBe('tablet');
    expect(getBreakpoint(BREAKPOINTS.desktop - 1)).toBe('tablet');
  });

  it('classifies desktop viewports', () => {
    expect(getBreakpoint(BREAKPOINTS.desktop)).toBe('desktop');
    expect(getBreakpoint(2560)).toBe('desktop');
  });

  it('matches the breakpoints declared in styles/responsive.css', () => {
    expect(BREAKPOINTS).toEqual({ tablet: 768, desktop: 1024 });
  });
});

describe('useViewportWidth', () => {
  it('reports the current width and tracks resizes', () => {
    setViewportWidth(320);
    const { result } = renderHook(() => useViewportWidth());
    expect(result.current).toBe(320);

    act(() => setViewportWidth(1280));
    expect(result.current).toBe(1280);
  });
});

describe('useBreakpoint', () => {
  it('reports mobile at 320px', () => {
    setViewportWidth(320);
    const { result } = renderHook(() => useBreakpoint());

    expect(result.current.breakpoint).toBe('mobile');
    expect(result.current.isMobile).toBe(true);
    expect(result.current.isTablet).toBe(false);
    expect(result.current.isDesktop).toBe(false);
  });

  it('reports tablet at 900px', () => {
    setViewportWidth(900);
    const { result } = renderHook(() => useBreakpoint());

    expect(result.current.breakpoint).toBe('tablet');
    expect(result.current.isMobile).toBe(false);
    expect(result.current.isTablet).toBe(true);
  });

  it('reports desktop at 1440px', () => {
    setViewportWidth(1440);
    const { result } = renderHook(() => useBreakpoint());

    expect(result.current.breakpoint).toBe('desktop');
    expect(result.current.isDesktop).toBe(true);
  });

  it('updates when the viewport crosses a breakpoint', () => {
    setViewportWidth(320);
    const { result } = renderHook(() => useBreakpoint());
    expect(result.current.isMobile).toBe(true);

    act(() => setViewportWidth(1440));
    expect(result.current.isMobile).toBe(false);
    expect(result.current.isDesktop).toBe(true);
  });
});
