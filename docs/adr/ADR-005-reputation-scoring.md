# ADR-005: Reputation Scoring Algorithm

**Status**: Accepted  
**Date**: 2024-01-15

## Context

We need an on-chain reputation system that reflects an address's trustworthiness based on observable on-chain events (transaction history, credential validity). The algorithm must be deterministic, gas-efficient, and resistant to gaming.

## Decision

**Score representation**: Integer in range `[0, 10000]` (i.e., `0–1000` scaled by `SCORE_SCALE=10`). All arithmetic uses `saturating_add` / `saturating_sub` to avoid overflow/underflow panics.

**Scoring components**:
| Event | Effect |
|-------|--------|
| Successful transaction | `+transaction_success_weight` (configurable) |
| Failed transaction | `−transaction_failure_weight` (configurable) |
| Valid credential | `+credential_valid_weight` (configurable) |
| Invalid/revoked credential | `−credential_invalid_weight` (configurable) |
| Trust attestation | Weighted graph aggregation up to depth 4 |

**Storage**: Profile and history stored in `persistent` storage. History capped at `MAX_HISTORY_POINTS=120` entries per address to bound storage growth.

**Batch updates** (`batch_update_transaction_reputation`): Issue #84 — batch multiple score updates in one transaction to reduce per-call overhead and improve throughput.

## Alternatives Considered

- **Floating-point scoring**: Not supported in Soroban's deterministic environment.
- **External oracle for scoring**: Adds latency and trust assumptions.
- **ELO-style relative scoring**: Too complex for on-chain compute; score manipulation risk.

## Consequences

- ✅ Fully deterministic; same inputs always produce same score.
- ✅ No floating-point dependencies.
- ✅ Configurable weights allow tuning without contract redeployment.
- ✅ Batch updates reduce gas overhead for bulk reputation events.
- ⚠️ Score history is bounded; very active addresses lose oldest entries.
- ⚠️ Weights are global; per-credential-type weighting requires a future upgrade.
