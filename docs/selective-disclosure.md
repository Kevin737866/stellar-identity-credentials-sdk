# Zero-Knowledge Selective Disclosure

## Overview

The selective disclosure system allows credential holders to prove specific
predicates about their attributes **without revealing the actual attribute
values**. This enables privacy-preserving verification where a verifier only
learns that a condition is satisfied (e.g., "age >= 18") rather than the
underlying data (e.g., "age = 32").

## Supported Predicate Types

| Predicate | Code | Description | Example |
|-----------|------|-------------|---------|
| GreaterThan | 0 | attribute > threshold | income > $50k |
| LessThan | 1 | attribute < threshold | debt < $10k |
| GreaterThanOrEqual | 2 | attribute >= threshold | age >= 21 |
| LessThanOrEqual | 3 | attribute <= threshold | score <= 850 |
| Equality | 4 | attribute == expected value | nationality == "US" |
| Range | 5 | min <= attribute <= max | credit score in [300, 850] |
| InSet | 6 | attribute is in allowed set | country in {US, UK, CA} |
| NotInSet | 7 | attribute NOT in blocked set | country not in sanctions list |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                 Holder (Prover)                  │
│  ┌──────────┐   ┌────────────┐   ┌───────────┐  │
│  │ Select   │   │ Generate   │   │ Submit    │  │
│  │ Predicate├──►│ ZK Proof   ├──►│ to Chain  │  │
│  └──────────┘   └────────────┘   └─────┬─────┘  │
│                                        │        │
└────────────────────────────────────────┼────────┘
                                         │
                    ┌────────────────────┴───────────────┐
                    │         Stellar Network             │
                    │  ┌──────────────────────────────┐  │
                    │  │   ZKAttestation Contract     │  │
                    │  │  - store proof               │  │
                    │  │  - verify predicate          │  │
                    │  │  - combine disclosures       │  │
                    │  └──────────┬───────────────────┘  │
                    └─────────────┼──────────────────────┘
                                  │
               ┌──────────────────┴──────────────────┐
               │          Verifier                    │
               │  ┌──────────────┐  ┌──────────────┐ │
               │  │ Verify       │  │ Check        │ │
               │  │ Proof        │  │ Predicates   │ │
               │  └──────────────┘  └──────────────┘ │
               └─────────────────────────────────────┘
```

## Smart Contract API

### `create_selective_disclosure_proof`

Creates a proof that selectively discloses attribute info via predicates.

Parameters:
- `credential_id` — The credential being proved
- `circuit_id` — The ZK circuit to use
- `public_inputs` — Public inputs for the proof
- `proof_bytes` — The generated proof
- `nullifier` — Unique nullifier to prevent replay
- `revealed_attributes` — Attributes whose exact values are revealed
- `hidden_attributes` — Attributes proved via predicates, not revealed
- `predicates` — Array of predicate constraints
- `expires_at` — Optional expiry timestamp
- `metadata` — Additional metadata

### `verify_selective_disclosure`

Verifies a proof against expected predicates.

Parameters:
- `proof_id` — ID of the disclosure proof
- `expected_predicates` — Predicates the verifier expects to be satisfied

Returns `true` if all predicates match and the proof is valid.

### `combine_selective_disclosures`

Combines multiple selective disclosure proofs into a single reference.

Parameters:
- `proof_ids` — Array of disclosure proof IDs to combine
- `metadata` — Additional metadata

Returns a combined disclosure proof ID.

## TypeScript SDK Usage

```typescript
import { PredicateType } from '@stellar-identity/sdk';

// Prove age is in range [18, 65] without revealing exact age
const proofId = await sdk.zkProofs.createRangeProof(
  userKeypair,
  'age',           // attribute name
  32,              // actual value (kept private)
  18,              // range min (public)
  65,              // range max (public)
  'cred_123',      // credential ID
  'sd_circuit',    // circuit ID
);

// Prove income > 50000 without revealing exact income
const proofId = await sdk.zkProofs.createGreaterThanProof(
  userKeypair,
  'income',
  75000,           // actual income (private)
  50000,           // threshold (public)
  'cred_123',
  'sd_circuit',
);

// Selectively reveal exact nationality (equality)
const proofId = await sdk.zkProofs.createEqualityDisclosure(
  userKeypair,
  'nationality',
  1,               // US
  'cred_123',
  'sd_circuit',
);

// Verify a disclosure
const result = await sdk.zkProofs.verifySelectiveDisclosure(
  proofId,
  [{ attributeName: 'age', predicateType: PredicateType.Range,
     rangeMin: '18', rangeMax: '65' }]
);
console.log('Valid:', result.valid);

// Combine multiple disclosures into one
const combinedId = await sdk.zkProofs.combineSelectiveDisclosures(
  userKeypair,
  ['proof_age', 'proof_income'],
  { purpose: 'loan_application' }
);
```

## Circom Circuits

The `circuits/selective_disclosure.circom` file implements:

- **AttributeCommitment** — Hashes attribute + nonce via Poseidon
- **GreaterThanPredicate** / **LessThanPredicate** — Compare attribute vs threshold
- **GreaterEqPredicate** / **LessEqPredicate** — Inclusive comparisons
- **EqualityPredicate** — Exact match disclosure
- **RangePredicate** — Two-sided bounded check
- **InSetPredicate** / **NotInSetPredicate** — Set membership checks
- **MultiAttributeSelectiveDisclosure** — Combines multiple predicates across attributes

## React Component

```tsx
import { SelectiveDisclosure } from '@stellar-identity/ui';

function App() {
  return (
    <SelectiveDisclosure
      sdk={sdk}
      address={address}
      keypair={keypair}
    />
  );
}
```

The component provides:
- Predicate type selection (range, GT, LT, equality, etc.)
- Attribute name and value input
- Threshold/range configuration
- Creation of selective disclosure proofs
- Verification against expected predicates
- Combining multiple disclosures
- Visual indicators for revealed vs hidden attributes

## Testing

```bash
# Run Rust contract tests
cargo test -- zk_attestation::tests::test_selective

# Run TypeScript SDK tests
npx jest -- selectiveDisclosure
```

## Security Considerations

1. **Nullifier uniqueness** — Each disclosure uses a unique nullifier to
   prevent replay attacks.
2. **Commitment binding** — Attributes are committed via Poseidon hash before
   proof generation, ensuring the prover cannot change values after commitment.
3. **Predicate integrity** — The verifier checks that disclosed predicates
   exactly match what was proven; any mismatch is rejected.
4. **Expiration** — Proofs can be time-limited via `expires_at`.
5. **Attribute conflict prevention** — An attribute cannot be simultaneously
   "revealed" and "hidden" in the same disclosure.
