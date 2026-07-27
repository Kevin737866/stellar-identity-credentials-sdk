/**
 * Jest configuration for the @stellar-identity/sdk TypeScript sources.
 * Uses ts-jest so .ts files in sdk/src can be imported directly in tests.
 */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/sdk/src/__tests__/**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: { esModuleInterop: true, target: 'ES2020', module: 'commonjs' } }],
  },
};
