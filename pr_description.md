## Description

This PR addresses infrastructure and developer experience requirements for the SDK, resolving existing issues in the build and testing pipeline.

### Changes Made

**1. API Gateway & Rate Limiting (Closes #120)**
- Created a declarative API Gateway using **Kong (DB-less mode)** and **Prometheus**.
- Located in `infra/gateway/`, the `docker-compose.yml` and `kong.yml` files configure secure routing, API key-based authentication (`x-api-key`), rate limiting (100 req/min), CORS, and metrics analytics.
- Added comprehensive documentation at `docs/api-gateway.md`.

**2. Contract Testing Sandbox (Closes #108)**
- Established a local testing sandbox for developers to test smart contracts without connecting to a public testnet.
- Added a `sandbox/start-sandbox.sh` script to spin up the local `stellar/quickstart` node.
- Created `sandbox/index.ts` featuring the `SorobanSandbox` utility to manage connections/deployments, `MockDataGenerator` to create deterministic or randomized DIDs and VCs, and `AssertionHelper` to validate standard transaction scenarios.
- Provided a `sandbox/test-scenario.template.ts` for developers to base their test suites on.

**3. SDK Typescript Fixes & Jest Configuration**
- Fixed major TypeScript compilation errors affecting `sdk/src/zkProofs.ts`, `sdk/src/reputation.ts`, `sdk/src/types.ts`, and `sdk/src/didResolver.ts` which prevented successful builds on the `main` branch.
- Added `snarkjs` and `@types/snarkjs` to `package.json` to resolve missing dependency errors in `zkProofs.ts`.
- Configured a `jest.config.js` to correctly leverage `ts-jest` for compiling and running the SDK tests. The 44 core test cases now execute perfectly.

### Checklist

- [x] Tested the local API Gateway setup via docker-compose
- [x] Verified the sandbox starts successfully locally
- [x] Validated TypeScript code compiles cleanly (`npm run build`)
- [x] Passed 100% of SDK unit tests via Jest (`npm test`)

### Related Issues
Closes #120
Closes #108
