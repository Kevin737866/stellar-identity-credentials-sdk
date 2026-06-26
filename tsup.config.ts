import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['sdk/src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  external: [
    'stellar-sdk',
    'axios',
    'bs58',
    'crypto-js',
    'did-jwt',
    'did-jwt-vc',
    'did-resolver',
    'multiformats',
    'snarkjs',
    'tweetnacl',
    'uint8arrays',
    'web-did-resolver',
  ],
  outDir: 'dist',
  target: 'es2020',
  platform: 'node',
  esbuildOptions(options) {
    options.mainFields = ['module', 'main'];
  },
});
