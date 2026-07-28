# ADR-002: DID Method and Resolution Strategy

**Status**: Accepted  
**Date**: 2024-01-15

## Context

We need a DID method that maps naturally onto Stellar's account model, supports W3C DID Core resolution, and can be resolved both on-chain and off-chain.

## Decision

Adopt the `did:stellar` method with the format:

```
did:stellar:<stellar_account_public_key>
```

**Resolution options (in order of preference):**
1. Direct on-chain call to `DIDRegistry::resolve_did`
2. Stellar TOML (`stellar.toml` at the issuer's domain)
3. HTTP DID resolution endpoint (optional, for performance-sensitive clients)

**DID Document** is stored in `DIDRegistry` as a `DIDDocument` struct containing verification methods, authentication references, service endpoints, and timestamps.

## Alternatives Considered

- **did:key**: Stateless but cannot be updated or have service endpoints.
- **did:web**: Centralized DNS dependency undermines decentralization.
- **Custom method on Soroban**: `did:stellar` provides the best alignment with existing Stellar tooling.

## Consequences

- ✅ DIDs are globally unique and tied to unforgeable Stellar keypairs.
- ✅ Resolution is fully on-chain; no external resolver infrastructure required.
- ✅ Compatible with existing W3C DID resolution interfaces.
- ⚠️ DID method spec must be registered with W3C.
- ⚠️ Resolution of deactivated DIDs still returns the document (with `deactivated: true`).
