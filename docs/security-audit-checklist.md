# Security Audit Checklist

This checklist covers all five core Soroban contracts and must be reviewed before every release.

## Contracts in Scope

| Contract | File |
|---|---|
| DID Registry | `src/did_registry.rs` |
| Credential Issuer | `src/credential_issuer.rs` |
| Reputation Score | `src/reputation_score.rs` |
| ZK Attestation | `src/zk_attestation.rs` |
| Compliance Filter | `src/compliance_filter.rs` |

---

## 1. Access Control

- [ ] Every state-mutating function calls `require_auth()` on the relevant authority
- [ ] Admin-only functions verify the caller matches the stored admin address
- [ ] DID operations verify the caller is the registered controller
- [ ] Delegation limits (`max_issuances`, expiry) are enforced before executing delegated calls
- [ ] No public function bypasses access control via an internal helper

## 2. Input Validation

- [ ] DID strings validated for `did:stellar:` prefix and max length (256 bytes)
- [ ] Verification method IDs capped at 128 bytes
- [ ] Service endpoint strings capped at 512 bytes
- [ ] Credential type and data blobs validated for length before storage
- [ ] Rate-limit parameters are non-zero (enforced in `check_rate_limit`)
- [ ] All numeric inputs validated against expected ranges

## 3. Reentrancy

- [ ] `issue_credential` protected by `ReentrancyGuard`
- [ ] `update_transaction_reputation` protected by `ReentrancyGuard`
- [ ] No state changes occur after external contract calls (checks-effects-interactions)
- [ ] Guard scopes are unique per function to prevent cross-function interference

## 4. Arithmetic Overflow

- [ ] `saturating_add` / `saturating_sub` used for reputation score arithmetic
- [ ] `max_score` cap enforced after every score update
- [ ] No unchecked arithmetic in weight calculations
- [ ] Rate-limit counters use saturating increments

## 5. Event Emission

- [ ] `DIDCreated` event emitted on successful DID creation
- [ ] `DIDUpdated` event emitted on DID document update
- [ ] `DIDDeactivated` event emitted on deactivation
- [ ] `CredentialIssued` event emitted with credential ID and issuer
- [ ] `RateLimitHit` event emitted when a caller is throttled
- [ ] `rep_updated` event emitted with new score and outcome
- [ ] No sensitive personal data included in emitted events

## 6. Upgrade Safety

- [ ] Upgrade governance contract reviewed for multi-sig requirements
- [ ] Storage layout changes are backward-compatible
- [ ] Migration logic tested before deployment
- [ ] Upgrade timelock period enforced (minimum 48 h for non-emergency)
- [ ] Emergency upgrade path documented and access-controlled

## 7. Rate Limiting

- [ ] `create_did`: 5 per address per 300 seconds
- [ ] `issue_credential`: 10 per issuer per 60 seconds
- [ ] `update_transaction_reputation`: 20 per address per 60 seconds
- [ ] Rate limit window resets are tested with boundary values

## 8. ZK Attestation Specifics

- [ ] Proof IDs include circuit ID, timestamp, and ledger sequence (replay prevention)
- [ ] Circuit registration restricted to admin address
- [ ] Commitment stored immutably at proof registration time
- [ ] `env.crypto()` verification called; invalid proofs cause a controlled panic

## 9. Code Hygiene

- [ ] No TODO/FIXME comments in security-critical paths
- [ ] All public contract functions have rustdoc comments
- [ ] Error variants are documented with their semantics
- [ ] Dead code removed (`cargo clippy -- -D warnings` passes clean)

---

## Vulnerability Remediation SLA

| Severity | Remediation Deadline |
|---|---|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | Next scheduled release |

Critical and High vulnerabilities must be reported to **security@stellar-identity.org** immediately upon discovery and tracked in a private security advisory until a patch is released.

---

## Pre-Release Sign-Off

All items above must be checked and the checklist signed off by two members of the security team before a contract is deployed to mainnet.

| Reviewer | Date | Signature |
|---|---|---|
| | | |
| | | |
