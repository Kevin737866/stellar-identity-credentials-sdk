# Threat Model & Data-Flow Map — Stellar Identity Credentials

> Created for Issue #521. This document is the authoritative model behind
> the assertions in [`SECURITY_AUDIT_PREP.md`](SECURITY_AUDIT_PREP.md) and
> [`security-audit-checklist.md`](security-audit-checklist.md). Changes to
> sensitive paths (issuance, verification, revocation, resolution, ZK
> proving/verification, key handling) must update this document in the same
> pull request.

## 1. System overview

Stellar Identity issues, holds, verifies and revokes verifiable credentials
on Stellar/Soroban contracts, with an optional zero-knowledge attestation
path. Components:

| Component | Location | Role |
| --- | --- | --- |
| DID registry contract | `src/did_registry.rs` | Create/resolve/recover `did:stellar` identifiers |
| Credential issuer contract | `src/credential_issuer.rs` | Issue, verify, revoke credentials |
| Reputation contract | `src/reputation_score.rs` | Per-address reputation scores |
| ZK attestation contract | `src/zk_attestation.rs` | Register circuits/keys, verify proofs |
| Compliance filter | `src/compliance_filter.rs` | Sanctions screening hooks |
| Status list | `src/status_list.rs` | Revocation bitstring |
| Rate limiter | `src/rate_limiter.rs` | Per-operation call limits |
| TypeScript SDK | `sdk/src/` | Client library (issuance, resolution, ZK helpers) |
| DID resolver | `sdk/src/didResolver.ts` | Contract / HTTP / TOML resolution with fallback |
| CLI | `cli/index.ts` | Interactive demo and operations tool |
| UI | `ui/` | Dashboards and widgets |

## 2. Assets and sensitivity

| Asset | Where it lives | Sensitivity |
| --- | --- | --- |
| Issuer signing keys (`S...` secrets) | Client-side only; env/secret manager (`.env.example`) | **Critical** — compromise enables fraudulent credentials |
| Subject private data (name, DOB, document number) | Submitted at issuance; `credential_data` on-chain in current design | **Critical** — PII, GDPR-scoped |
| Credential proofs (`proof` field) | On-chain inside `VerifiableCredential` | High — forgery enables impersonation |
| Revocation state (status list) | On-chain (`src/status_list.rs`) | High — tampering revives revoked credentials |
| Reputation scores | On-chain (`src/reputation_score.rs`) | Medium — manipulation biases access control |
| ZK verification keys (`.vkey`) | Off-repo artefacts; provenance currently unspecified (see circuits `README.md`) | High — a rogue key verifies arbitrary proofs |
| DID document / services | On-chain + off-chain TOML/HTTP (`sdk/src/didResolver.ts`) | Medium — redirection of resolution |
| Rate-limit & admin config | On-chain storage | Medium — disabling limits enables abuse |
| Audit trail | On-chain (`src/audit_trail.rs`) | Medium — evidence integrity |

## 3. Trust boundaries and assumptions

```
[Subject device]  --signs-->  [Issuer backend/SDK]
                                    |
                              boundary B1: issuer verifies identity off-chain
                                    |
                                    v
                            [CredentialIssuer contract]  <-- boundary B2: chain consensus
                                    |
              +---------------------+---------------------+
              |                     |                     |
     [Verifier SDK]        [DID resolver]          [ZK verifier contract]
      boundary B3:         boundary B4:             boundary B5: proof vs
      verifier trusts     resolver merges          verification key
      issuer keys +       contract/HTTP/TOML
      status list         sources
```

| Boundary | Assumption |
| --- | --- |
| B1 Subject → Issuer | The issuer performs real-world identity checks off-chain; the contract cannot validate them. Issuer key custody is the issuer's responsibility. |
| B2 Chain | Stellar/Soroban consensus and contract code behave as written; admin signers are honest or multisig-gated. |
| B3 Verifier | The verifier trusts the issuer list and the on-chain status list; a compromised issuer is detectable only via revocation + re-issue. |
| B4 Resolution | HTTP/TOML resolution results are **unauthenticated off-chain hints**; only contract resolution is authoritative. Callers must treat merged fields as untrusted (see `sdk/src/didResolver.ts`). |
| B5 ZK | Soundness holds only if the verification-key toxic waste was destroyed in setup — currently a documented development-only assumption (see `circuits/README.md`). |

## 4. Adversary classes

| Adversary | Capabilities considered | In scope? |
| --- | --- | --- |
| Malicious verifier | Calls any public contract fn; harvests on-chain data | Yes |
| Malicious subject | Forges proofs, replays presentations, spams issuance requests | Yes |
| Compromised issuer key | Issues arbitrary credentials as a trusted issuer | Yes |
| Network attacker during resolution | MITM on HTTP/TOML resolution endpoints | Yes |
| Malicious contract caller | Direct Soroban invocation with arbitrary args | Yes |
| compromised admin key | Attempts pause/config/upgrade functions | Yes (mitigated by multisig `src/admin_multisig.rs`) |
| Stellar network-level attacker (consensus) | Censors/reorders transactions | **Out of scope** — inherits L1 security |
| Physical theft of subject device | — | **Out of scope** |
| Denial of service at network level | — | Out of scope (contract-level rate limits are in scope, `src/rate_limiter.rs`) |
| Third-party dependency compromise | — | Partially — mitigated by `cargo audit` / `npm audit` in `.github/workflows/security.yml` |

## 5. Data classification (authoritative)

Every field persisted by the contracts must be classified here. A field not
listed may not be added to on-chain storage without updating this table and
the corresponding contract validation.

| Field / data | Classification | Rationale |
| --- | --- | --- |
| `credential_data` payload (name, DOB, document number) | **Hashed-only — currently violated** | Stored raw in `src/credential_issuer.rs` (`VerifiableCredential.credential_data`, ~lines 330–345). See open work items; this table supersedes the current implementation for redesign purposes. |
| `proof` | On-chain (public) | Public by design; must verify against pinned keys |
| Credential id / issuer / subject / dates | On-chain (public) | Public graph; linkable by design |
| Revocation status | On-chain (public) | Must be public for verifiers |
| Reputation score components | On-chain (public aggregate; hashed details) | Aggregates public, raw tx data hashed |
| Issuer secret keys | **Never on-chain, never in repo** | Env/secret manager only (`.env.example`) |
| DID services/endpoints | On-chain or TOML (public) | Public discovery data |
| ZK private inputs (DOB, income, …) | **Never leaves prover** | Only commitments/proofs on-chain |

Retention: on-chain data has **indefinite retention**; the GDPR-erasure
path must therefore operate on off-chain stores and hash-only on-chain
records.

## 6. Risks and mitigating controls

| # | Risk | Mitigation | Code | Test |
| --- | --- | --- | --- | --- |
| R1 | Forged credentials via stolen issuer key | Issuer identity checked off-chain; revocation via status list; multisig admin | `src/credential_issuer.rs`, `src/status_list.rs`, `src/admin_multisig.rs` | `src/integration_tests.rs`, `sdk/src/__tests__/credentialClient.test.ts` |
| R2 | Replay of presentations/proofs | Nonce/timestamp checks in validation layer | `src/validation.rs` | `src/validation.rs` (`#[cfg(test)]`) |
| R3 | Rogue verification key registration | Admin-gated key registration; vkey hashes must be pinned (tracked: circuit pipeline issue #517) | `src/zk_attestation.rs` (`check_peer_compatibility` at ~line 1369) | `src/zk_attestation.rs` tests |
| R4 | Resolution spoofing via HTTP/TOML | Contract resolution preferred; fallback marked; SDK flags source | `sdk/src/didResolver.ts` | `sdk/src/__tests__/didResolver.test.ts` |
| R5 | Spam / scraping of public endpoints | Per-operation rate limits with admin exemptions | `src/rate_limiter.rs` (`check_operation`) | `src/rate_limiter.rs` tests |
| R6 | PII exposure from raw on-chain payload | Classification table mandates hashed-only; redesign tracked (privacy issues) | §5 above | — (gap) |
| R7 | Malicious contract upgrade | Timelocked, multisig-governed upgrades | `src/contract_upgrade.rs`, `src/admin_multisig.rs` | `src/contract_upgrade.rs` tests |
| R8 | Pause/unpause abuse | Admin-gated pause path (enforcement completeness tracked by audit finding on pause guards) | `src/contract_upgrade.rs` | — (gap) |
| R9 | Integer overflow in reputation/royalty math | BigInt safe math in SDK; checked arithmetic in contracts | `docs/safe-math.md`, `src/reputation_score.rs` | `sdk/src/__tests__/reputationScoring.test.ts` |
| R10 | Rogue contract configuration in SDK clients | Version/compatibility checks on construction (tracked: compatibility matrix issue #522) | `src/contract_version.rs` | — (gap) |

**Known gaps** (R6, R8, R10) are tracked by open issues; this model is
authoritative for what *must* hold, not for what currently does.

## 7. Review process

- Any pull request touching the sensitive paths listed in §1 must update
  this document.
- The release checklist verifies that each risk in §6 still maps to a real
  code reference and test.
- New on-chain fields require a §5 classification row in the same PR;
  contract validation must enforce the classification (hashed-only fields
  are stored as hashes).
