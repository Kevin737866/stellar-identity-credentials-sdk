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
  // Network-dependent suites are opt-in; they need a funded testnet account.
  testPathIgnorePatterns: ['<rootDir>/sdk/src/__tests__/integration'],
  collectCoverageFrom: [
    'sdk/src/**/*.ts',
    '!sdk/src/**/*.d.ts',
    '!sdk/src/__tests__/**',
  ],
  coverageThreshold: {
    global: { branches: 90, functions: 90, lines: 90, statements: 90 },
  },
};
