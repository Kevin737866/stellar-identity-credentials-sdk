import '@testing-library/jest-dom';
import { toHaveNoViolations } from 'jest-axe';

// Register the axe matcher once, so every suite can call
// `expect(await axe(container)).toHaveNoViolations()`.
expect.extend(toHaveNoViolations);

// jsdom does not implement these, and several components touch them.
if (!window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    }),
  });
}

if (!global.ResizeObserver) {
  (global as any).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}
