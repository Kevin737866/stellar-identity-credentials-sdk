# Stellar Identity SDK — API Reference

Generated from the TypeScript source with [TypeDoc](https://typedoc.org).

## Getting started

```bash
npm install @stellar-identity/sdk
```

```typescript
import { StellarIdentitySDK, DEFAULT_CONFIGS } from '@stellar-identity/sdk';

const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);
```

## Where to look

| I want to… | Start here |
| --- | --- |
| Create or resolve a DID | [`DIDClient`](modules/sdk_src_didClient.html) |
| Issue or verify a credential | [`CredentialClient`](modules/sdk_src_credentialClient.html) |
| Read or update a score | [`ReputationClient`](modules/sdk_src_reputation.html) |
| Build a zero-knowledge proof | [`ZKProofsClient`](modules/sdk_src_zkProofs.html) |
| Screen an address | [`ComplianceClient`](modules/sdk_src_compliance.html) |
| Target a specific network | [`networks`](modules/sdk_src_networks.html) |
| Configure the SDK | [`config`](modules/sdk_src_config.html) |
| Handle a failure | [`errors`](modules/sdk_src_errors.html) |
| Survive a flaky RPC | [`retry`](modules/sdk_src_retry.html) |
| Avoid repeat network calls | [`cacheBackend`](modules/sdk_src_cacheBackend.html) |

## Design notes

Three things are worth knowing before reading the API.

**Errors are typed and classified.** Every failure extends
`StellarIdentityError` and carries a numeric `code`, an `errorClass`, a
`retryable` flag, and a `recovery` hint. The retry engine consults
`retryable`, so a transient network failure is retried and a contract rejection
is not. See [Error handling](error-handling-guide.html) for the full guide.

**Network configuration is explicit.** The passphrase is not derived from the
network name. A custom network must supply one, because a wrong passphrase
produces transactions that silently never validate. See
[`networks`](modules/sdk_src_networks.html).

**Caching is opt-in and invalidation-aware.** Entries are written with tags and
a write operation drops everything under a tag, so a cache that saves network
calls cannot serve a pre-update document. See
[`cacheBackend`](modules/sdk_src_cacheBackend.html).

## Conventions in these docs

Modules are grouped by category via `@category` JSDoc tags:

- **Client** — the domain clients you construct
- **Types** — configuration and result shapes
- **Errors** — the error hierarchy
- **Retry** — the retry engine and circuit breaker
- **Configuration** — network and config resolution
- **Utilities** — logging, caching, compression, and the rest

## Regenerating

```bash
npm run docs          # writes docs/api/
npm run docs:watch    # live rebuild while editing
npm run docs:check    # verify the build (used in CI)
```

Documentation is generated from source JSDoc, so it cannot drift from the code.
CI runs `docs:check` on every pull request and fails if the build breaks or if
a public export is missing documentation.
