# Stellar Identity Circuits

Circom circuits for the Stellar Identity zero-knowledge proofs.

## Circuits

All eight circuit sources in this directory are compiled by a single
command (`npm run build`), which delegates to `scripts/build-circuits.js`:

| Circuit | Purpose |
| --- | --- |
| `age_verification` | Prove the subject is above a minimum age without revealing the birth date |
| `composite_proof` | Combine multiple sub-proofs into one verification |
| `credential_ownership` | Prove ownership of an issued credential |
| `income_verification` | Prove income above a threshold without revealing the value |
| `membership-verification` | Prove membership in a set via a Merkle path |
| `range_proof` | Prove a value lies within a committed range |
| `selective_disclosure` | Disclose a subset of credential attributes |
| `set_membership` | Prove set membership without revealing the element |

## Commands

```bash
npm install
npm run build            # compile every circuit (.r1cs/.wasm/.sym)
npm run setup            # powers-of-tau ceremony (see "Trusted setup" below)
npm run generate-keys    # groth16 setup + verification key export
npm run generate-random  # write sample inputs for every circuit
npm test                 # smoke checks for sources, build script and artefacts
```

## Trusted setup record

> **Status: development-only ceremony. Do NOT use these artefacts in production.**

The `setup` script performs a **single-contributor** powers-of-tau
ceremony: one local contribution, no external participants, and no
published transcript. That means the toxic waste from the setup is
assumed to be known to whoever ran it, so proofs generated against these
keys provide **no zero-knowledge or soundness guarantees** against a
malicious coordinator.

Production deployments require either:

1. A documented multi-party ceremony (list every contributor, publish the
   contribution transcript, retain `.ptau` hashes), or
2. An explicit, signed statement from the maintainers accepting the
   single-contributor trust assumption for a given deployment.

Until then, contracts must not pin verification keys produced by
`npm run generate-keys` for mainnet use. Verification keys shipped for
test environments must record the `.ptau` hash they were derived from.

### Recording a ceremony

When a real ceremony is run, append an entry here with:

- Date and network parameters (`bn128`, power size)
- Every contributor (name/handle, order)
- Hashes of `pot_final.ptau` and each exported `.vkey`
- The contract configuration that pins those `.vkey` hashes
