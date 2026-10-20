# ADR-004: ZK Proof System and Circuit Design

**Status**: Accepted (partially implemented)  
**Date**: 2024-01-15  
**Last re-audited**: 2026-10-18 against the implementation at commit `8fb6167`

## Context

Users must be able to prove claims about their credentials (age ≥ 18, income ≥ threshold, set membership) without revealing the underlying values. The proof system must operate within Soroban's deterministic compute environment.

## Decision

Use **Groth16** proofs (via the `ark-groth16` crate) over the **BLS12-381** curve. Proofs are generated off-chain (in the client).

**Verification status**: on-chain verification is **not implemented**. The entry points in `src/zk_attestation.rs` (`verify_proof`, the Groth16 pairing evaluation, and the selective-disclosure stub) currently return `Ok(true)` for any non-empty proof — see `verify_zk_proof` at `src/zk_attestation.rs:1198` and `evaluate_pairing_check` at `src/zk_attestation.rs:1258`. No nullifier is enforced and no circuit verification key is actually checked against the proof. Consequently, ADR-004 must not be read as asserting that proofs are verified on-chain by `ZKAttestation`; that property does not hold today.

**Circuit library** (`circuits/`):
| File | Purpose |
|------|---------|
| `range_proof.circom` | Prove value ∈ [min, max] — used for age and income thresholds |
| `set_membership.circom` | Prove element ∈ Merkle set — used for country/whitelist checks |
| `credential_ownership.circom` | Prove possession of a valid credential without revealing it |
| `composite_proof.circom` | Combine multiple proof statements into one proof |

**On-chain flow (implemented subset):**
1. Circuit is registered via `ZKAttestation::register_circuit` with its verification key.
2. Client generates proof off-chain and calls `ZKAttestation::submit_proof`.
3. A nullifier is computed to prevent proof replay (unverified until real verification lands).
4. `Verifiers call `ZKAttestation::verify_proof` — currently a stub that accepts any non-empty proof; do not rely on it for authorization decisions.

## Alternatives Considered

- **PLONK / STARKs**: Larger proof sizes and higher verification cost on Soroban.
- **Bulletproofs**: No trusted setup, but slower on-chain verification.
- **Groth16 on BN254**: Smaller proofs but weaker security margin vs BLS12-381.

## Consequences

- ⚠️ Groth16 proofs are compact (~192 bytes) and fast to verify *in principle*, but on-chain verification is not yet implemented.
- ⚠️ Nullifiers are computed but not enforced by real verification, so they do not yet prevent double-spend of proofs.
- ✅ Circuits are upgradable: new circuits can be registered without contract redeployment.
- ⚠️ Requires a trusted setup ceremony per circuit.
- ⚠️ Proof generation is compute-intensive and must occur off-chain.

## Re-audit findings (commit `8fb6167`)

All six ADRs were re-reviewed against the implementation. ADR-004 is the only ADR that asserts a verified security property (`verified on-chain by ZKAttestation`) without a linked, passing test. The other five ADRs describe design decisions whose runtime behaviour matches their documentation, or are explicitly marked as future work. ADR-004 must be updated to state the actual verification status (above) before any release that treats ZK proofs as an enforcement mechanism.

**Plan for completion:** Implement real Groth16 verification inside `verify_zk_proof` / `evaluate_pairing_check`, enforce the nullifier, and add a test per claimed verification property linked from this ADR. Until then, treat `submit_proof`/`verify_proof` as client-side only.
