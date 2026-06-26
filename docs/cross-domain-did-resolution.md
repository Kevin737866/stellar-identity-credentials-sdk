# Cross-Domain DID Resolution

This document covers the cross-domain DID resolution feature, which allows the SDK to resolve DIDs from multiple DID methods beyond `did:stellar`.

## Overview

The `DIDResolver` class in `sdk/src/didResolver.ts` implements the [W3C DID Core resolution algorithm](https://www.w3.org/TR/did-core/#resolution) and provides a pluggable resolver chain supporting:

| Method | Description |
|--------|-------------|
| `did:stellar` | Native Stellar on-chain DIDs (primary) |
| `did:key` | Self-describing cryptographic DIDs |
| `did:web` | Domain-based DIDs via HTTPS |
| `did:ethr` | Ethereum-based DIDs |

## Resolver Interface

```typescript
import { DIDResolver } from '@stellar-identity/sdk';

const resolver = new DIDResolver(config);

// Resolve any supported DID method
const result = await resolver.resolve('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
const result2 = await resolver.resolve('did:web:example.com');
const result3 = await resolver.resolve('did:stellar:GABC...');
```

### Resolution Result

```typescript
interface W3CResolutionResult {
  didDocument: DIDDocument | Record<string, never>;
  didResolutionMetadata: {
    contentType?: string;
    retrieved?: string;
    error?: string;       // 'notFound' | 'invalidDid' | 'methodNotSupported'
    duration?: number;    // milliseconds
    method?: string;      // e.g. 'stellar', 'key', 'web'
  };
  didDocumentMetadata: {
    created?: string;
    updated?: string;
    deactivated?: boolean;
  };
}
```

## DID Method Support

### did:key

Resolved locally from the DID string itself — no network call required.

```typescript
const result = await resolver.resolve(
  'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
);
```

### did:web

Resolved via HTTPS from the domain's `/.well-known/did.json` endpoint.

```typescript
const result = await resolver.resolve('did:web:identity.example.com');
// Fetches: https://identity.example.com/.well-known/did.json
```

### did:ethr

Resolved via Ethereum DID registry using the `ethr-did-resolver` package.

```typescript
const result = await resolver.resolve(
  'did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
);
```

### did:stellar

Resolved on-chain from the Stellar Soroban DID Registry contract.

```typescript
const result = await resolver.resolve('did:stellar:GABC...');
```

## DID Document Caching

Resolved documents are cached in-memory with a configurable TTL (default: 30 seconds) to reduce redundant network and on-chain calls.

```typescript
const resolver = new DIDResolver(config, {
  cacheTtlMs: 60_000, // 60 seconds
});

// Force bypass cache
const fresh = await resolver.resolve(did, { noCache: true });
```

## Resolver Fallback Chain

Configure a custom fallback order for multi-method resolution:

```typescript
const resolver = new DIDResolver(config, {
  fallbackMethods: ['stellar', 'key', 'web', 'ethr'],
});
```

When a DID method is unknown or resolution fails, the resolver cascades through the fallback chain.

## Dereferencing DID URLs

```typescript
// Dereference a specific verification method
const vmResult = await resolver.dereference(
  'did:stellar:GABC...#key-1'
);

// Dereference a service endpoint
const svcResult = await resolver.dereference(
  'did:stellar:GABC...#hub'
);
```

## Error Codes

| Code | Meaning |
|------|---------|
| `notFound` | DID document not found |
| `invalidDid` | DID string is malformed |
| `methodNotSupported` | DID method not in resolver chain |
| `internalError` | Unexpected resolver error |

## Tests

See `sdk/src/__tests__/didResolver.test.ts` for comprehensive multi-method resolution tests covering:

- Successful resolution for each supported method
- Cache hit/miss behaviour
- Fallback chain traversal
- Error handling for unknown methods and malformed DIDs
- DID URL dereferencing
