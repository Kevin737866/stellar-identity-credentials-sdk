# ADR-001: Overall System Architecture and Contract Design

**Status**: Accepted  
**Date**: 2024-01-15

## Context

We need to build a decentralized identity and verifiable credentials system on the Stellar network using Soroban smart contracts. The system must support W3C DID and VC standards while operating within Soroban's contract size and compute limits.

## Decision

Deploy five independent Soroban contracts, each owning its own storage namespace:

1. **DID Registry** — CRUD for `did:stellar` documents
2. **Credential Issuer** — Issuance, verification, and revocation of VCs
3. **Reputation Score** — On-chain scoring from transaction history and credentials
4. **ZK Attestation** — Zero-knowledge proof submission and verification
5. **Compliance Filter** — Sanctions screening and risk assessment

Each contract is compiled to a separate WASM binary. Cross-contract calls use Soroban's `Address`-based invocation. A thin `StellarIdentity` facade stores the deployed addresses and exposes discovery endpoints.

## Alternatives Considered

- **Monolithic contract**: Exceeds WASM size limits; harder to upgrade individual components.
- **On-chain proxy pattern**: Adds indirection overhead; not idiomatic for Soroban.

## Consequences

- ✅ Each contract can be upgraded independently.
- ✅ Clear separation of concerns and storage namespaces prevents key collisions.
- ✅ Contracts can be audited independently.
- ⚠️ Cross-contract calls incur additional compute fees.
- ⚠️ Deployment and address management requires coordination.
