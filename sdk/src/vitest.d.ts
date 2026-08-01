/**
 * Type augmentation for `import.meta.vitest` used in inline test blocks.
 *
 * compression.ts uses the Vitest inline-test pattern:
 *
 *   if (import.meta.vitest) {
 *     const { describe, it, expect } = import.meta.vitest;
 *     // ...
 *   }
 *
 * Without this declaration the DTS build (tsup --dts) fails because
 * TypeScript does not know about the `vitest` property on ImportMeta.
 *
 * See https://vitest.dev/guide/in-source.html
 */

interface ImportMeta {
  vitest: {
    describe: typeof describe;
    it: typeof it;
    expect: typeof expect;
    // Additional Vitest globals can be added as needed.
    [key: string]: unknown;
  };
}
