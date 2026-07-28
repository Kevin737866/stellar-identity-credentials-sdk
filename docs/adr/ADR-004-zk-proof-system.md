# ADR-004: ZK Proof System and Circuit Design

**Status**: Accepted  
**Date**: 2024-01-15

## Context

Users must be able to prove claims about their credentials (age ≥ 18, income ≥ threshold, set membership) without revealing the underlying values. The proof system must operate within Soroban's deterministic compute environment.

## Decision

Use **Groth16** proofs (via the `ark-groth16` crate) over the **BLS12-381** curve. Proofs are generated off-chain (in the client) and verified on-chain by `ZKAttestation`.

**Circuit library** (`circuits/`):
| File | Purpose |
|------|---------|
| `range_proof.circom` | Prove value ∈ [min, max] — used for age and income thresholds |
| `set_membership.circom` | Prove element ∈ Merkle set — used for country/whitelist checks |
| `credential_ownership.circom` | Prove possession of a valid credential without revealing it |
| `composite_proof.circom` | Combine multiple proof statements into one proof |

**On-chain flow:**
1. Circuit is registered via `ZKAttestation::register_circuit` with its verification key.
2. Client generates proof off-chain and calls `ZKAttestation::submit_proof`.
3. A nullifier prevents proof replay.
4. Verifiers call `ZKAttestation::verify_proof`.

## Alternatives Considered

- **PLONK / STARKs**: Larger proof sizes and higher verification cost on Soroban.
- **Bulletproofs**: No trusted setup, but slower on-chain verification.
- **Groth16 on BN254**: Smaller proofs but weaker security margin vs BLS12-381.

## Consequences

- ✅ Groth16 proofs are compact (~192 bytes) and fast to verify.
- ✅ Nullifiers prevent double-spend of proofs.
- ✅ Circuits are upgradable: new circuits can be registered without contract redeployment.
- ⚠️ Requires a trusted setup ceremony per circuit.
- ⚠️ Proof generation is compute-intensive and must occur off-chain.
