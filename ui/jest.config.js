/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.{ts,tsx}'],
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        diagnostics: false,
        tsconfig: {
          jsx: 'react-jsx',
          esModuleInterop: true,
          baseUrl: '.',
          paths: {
            '@/*': ['./src/*'],
            '@/components/*': ['./src/components/*'],
          },
        },
      },
    ],
  },
  moduleNameMapper: {
    '^@/components/(.*)$': '<rootDir>/src/components/$1',
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@stellar-identity/sdk$': '<rootDir>/__mocks__/@stellar-identity/sdk.js',
    '^lucide-react$': '<rootDir>/__mocks__/lucide-react.js',
    '^stellar-sdk$': '<rootDir>/__mocks__/stellar-sdk.js',
  },
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
  collectCoverage: false,
  passWithNoTests: true,
};
