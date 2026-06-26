# Smart Contract Security Audit Preparation

## Threat Model — Stellar Identity Credentials SDK

### Overview

This document covers all five core Soroban contracts:

1. **DID Registry** (`src/did_registry.rs`)
2. **Credential Issuer** (`src/credential_issuer.rs`)
3. **Reputation Score** (`src/reputation_score.rs`)
4. **ZK Attestation** (`src/zk_attestation.rs`)
5. **Compliance Filter** (`src/compliance_filter.rs`)

---

## Security Assumptions and Trust Boundaries

| Boundary | Assumption |
|---|---|
| Controller key | The private key corresponding to a Stellar account is held securely by its owner |
| Soroban host | The Soroban runtime correctly enforces `require_auth()` |
| Ledger clock | `env.ledger().timestamp()` is monotonically increasing and cannot be manipulated by callers |
| Off-chain data | Credential data passed to `issue_credential` is pre-validated by the issuer before submission |
| Admin account | The admin address for `ReputationScore` and `ComplianceFilter` is controlled by a trusted multi-sig |

---

## Threat Model by Contract

### 1. DID Registry

| Threat | Attack Vector | Mitigation |
|---|---|---|
| Unauthorized DID creation | Attacker creates a DID for an address they don't control | `controller.require_auth()` enforces ownership |
| DID squatting / DoS | Attacker registers all possible DIDs to block legitimate users | Rate limiter: 5 creates per address per 300 s |
| Replay attacks | Re-submitting a `create_did` transaction | `AlreadyExists` check prevents duplicate registrations |
| Format injection | Malformed DID strings bypassing indexers | `check_did_prefix` validates `did:stellar:` prefix; length caps on all fields |
| Data corruption via update | Third party updating another user's DID | Only the registered controller can call `update_did` |
| Permanent lock-out | Accidental or malicious deactivation | `AlreadyDeactivated` prevents double-deactivation; deactivation is final by design (W3C spec) |

### 2. Credential Issuer

| Threat | Attack Vector | Mitigation |
|---|---|---|
| Credential flooding | Issuer or attacker minting unlimited credentials | Rate limiter: 10 issues per issuer per 60 s |
| Reentrancy via callback | Malicious subject contract calls back into `issue_credential` during execution | `ReentrancyGuard` on `issue_credential` |
| Unauthorized issuance | Non-issuer address creating credentials | `issuer.require_auth()` required on all issuance paths |
| Delegation abuse | Delegate exceeds authorization limits | `issued_count` tracked against `max_issuances`; delegation expiry checked |
| Credential forgery | Attacker alters credential data post-issuance | Credential ID derived from issuer + subject + ledger state; stored immutably |
| Schema bypass | Issuing credentials that violate a schema | `issue_credential_with_schema` validates against on-chain schema |

### 3. Reputation Score

| Threat | Attack Vector | Mitigation |
|---|---|---|
| Score inflation via callbacks | Contract calls back into `update_transaction_reputation` before first call returns | `ReentrancyGuard` on `update_transaction_reputation` |
| Rapid score manipulation | Flooding the contract with success transactions | Rate limiter: 20 updates per address per 60 s |
| Unauthorized config change | Non-admin changing scoring weights | `admin.require_auth()` on `update_config` |
| Score overflow | Extremely large weight values causing u32 overflow | `saturating_add` / `saturating_sub` used throughout; `max_score` cap enforced |
| Trust graph manipulation | Circular trust attestations to amplify scores | Depth capped at 4; duplicate attestation check prevents self-loops |

### 4. ZK Attestation

| Threat | Attack Vector | Mitigation |
|---|---|---|
| Proof replay | Reusing a valid proof for a different purpose | Proof ID includes circuit ID, timestamp, and ledger sequence |
| Invalid proof acceptance | Submitting a malformed proof | `env.crypto()` verification; invalid proofs cause a contract panic |
| Circuit spoofing | Registering a malicious circuit ID | Circuit registration restricted to admin |
| Commitment manipulation | Changing the committed value after proof submission | Commitment is stored at proof registration time and immutable |

### 5. Compliance Filter

| Threat | Attack Vector | Mitigation |
|---|---|---|
| Sanctions list bypass | Submitting addresses just before a list update | Screening is point-in-time; callers should re-screen periodically |
| Admin abuse | Admin adding arbitrary addresses to block lists | Admin is expected to be a multi-sig; changes are on-chain and auditable |
| DoS via screening | Flooding the contract with screening requests | Rate limiting should be applied at the API gateway layer (see issue #120) |
| Data staleness | Off-chain data feed becomes outdated | `last_updated` timestamp exposed; integrators should validate freshness |

---

## Known Attack Vectors and Mitigations Summary

| Attack | Contracts Affected | Status |
|---|---|---|
| Reentrancy via cross-contract callbacks | Credential Issuer, Reputation Score | Mitigated — `ReentrancyGuard` added |
| Rate-based DoS | DID Registry, Credential Issuer, Reputation Score | Mitigated — `rate_limiter` module added |
| Unauthorized state mutation | All contracts | Mitigated — `require_auth()` on all mutating functions |
| Integer overflow/underflow | Reputation Score | Mitigated — `saturating_*` arithmetic used |
| Input validation bypass | DID Registry, Credential Issuer | Mitigated — length and format checks on all inputs |

---

## Security Review Checklist

### Access Control
- [x] All state-mutating functions call `require_auth()` on the relevant authority
- [x] Admin-only functions check the stored admin address before proceeding
- [x] DID operations verify the caller is the registered controller

### Input Validation
- [x] DID strings validated for `did:stellar:` prefix and max length (256 bytes)
- [x] Verification method IDs capped at 128 bytes
- [x] Service IDs capped at 128 bytes; endpoints capped at 512 bytes
- [x] Credential type and data length validated before storage
- [x] Rate limit parameters are non-zero (enforced in `check_rate_limit`)

### Reentrancy
- [x] `issue_credential` protected by `ReentrancyGuard`
- [x] `update_transaction_reputation` protected by `ReentrancyGuard`
- [x] Guard scopes are unique per function to avoid cross-function interference

### Rate Limiting
- [x] `create_did`: 5 per address per 300 seconds
- [x] `issue_credential`: 10 per issuer per 60 seconds
- [x] `update_transaction_reputation`: 20 per address per 60 seconds
- [x] Rate limit exceeded events emitted for monitoring

### State Management
- [x] No state changes after external calls (checks-effects-interactions pattern)
- [x] Deactivated DID guard prevents mutations on inactive identifiers
- [x] Duplicate registration rejected atomically

### Events / Auditability
- [x] `DIDCreated`, `DIDUpdated`, `DIDDeactivated` events emitted
- [x] `CredentialIssued` event emitted with credential ID and issuer
- [x] `RateLimitHit` event emitted when a caller is throttled
- [x] `rep_updated` event emitted with new score and outcome

### Code Hygiene
- [x] No TODO/FIXME comments in security-critical paths
- [x] All public contract functions have rustdoc comments
- [x] Error variants are documented with their semantics

---

## Recommended Follow-up Actions (pre-audit)

1. **Formal verification** of the rate-limiter window reset logic.
2. **Fuzz testing** of input validation paths (see `src/fuzz_test_script.rs`).
3. **Multi-sig admin setup** for `ReputationScore` and `ComplianceFilter` before mainnet deployment.
4. **External audit** of ZK circuit definitions in `circuits/` by a ZK specialist.
5. **Integration test** confirming reentrancy guard blocks cross-contract callback attacks.
