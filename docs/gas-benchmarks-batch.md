# Batch Gas Optimisation (#197)

This document records the optimisation techniques applied to the credential
batch operations and the expected effect of each. The headline target from the
issue was **>30% gas reduction for batches of 50 items or more**.

## Why batches were expensive

Soroban charges per storage operation, not per byte moved. The original batch
loop had this shape:

```rust
for item in items.iter() {
    let credential_id = issue_credential(env.clone(), ...)?;   // <- full call
    issued_ids.push_back(credential_id);
}
```

Each `issue_credential` invocation independently:

1. read `IssuerCreds(issuer)` — an ever-growing vector,
2. append and **write it back**,
3. read `SubjectCreds(subject)`,
4. append and **write it back**,
5. emit a `CredentialIssued` diagnostic event,
6. write one event-log record plus up to four secondary index appends.

For a batch of `n` items against a single issuer and a single subject that is
`4n` index storage operations, `n` separate event publications, and `4n` event
index operations — and the issuer vector is re-serialised on every iteration,
so the write cost grows with `n` as well as the count.

## Techniques applied

### 1. Staged index appends — `src/batch_optimizer.rs`

`IndexAppender` accumulates appends in memory and writes each target vector
exactly once on `flush`:

| | operations for `n` items, `k` distinct keys |
|---|---|
| before | `2n` reads + `2n` writes |
| after | `k` reads + `k` writes |

For a batch of 50 to one issuer and one subject (`k = 2`): **200 → 4** index
operations, a 98% reduction on that component.

The appender also de-duplicates, so repeating an id inside a batch does not
grow the index, and it falls back to an immediate read-modify-write if a batch
touches more than `MAX_TRACKED_KEYS` (64) distinct keys rather than silently
dropping entries.

### 2. One rate-limit check per batch, not per item

`batch_issue_credentials` is charged a single `batch_issue` quota unit, and
`batch_verify_credentials` a single `batch_verify` unit. Previously a batch of
50 would have consumed 50 issuance units and been rejected by the per-address
limit at item 11. This removes both the gas cost of 50 temporary-storage
read-modify-writes and a functional bug that made large batches impossible.

### 3. Memoised point lookups — `EntryCache`

`batch_verify_credentials` memoises `(credential_id -> result)` so duplicate ids
cost one read. `batch_revoke_credentials` skips ids it has already processed in
the same call, which also removes the duplicate `RevocationProof` write that the
naive loop performed for a repeated id.

### 4. Hoisted per-iteration allocations

- The revocation marker (`now.to_string()`) and the `expired` reason are built
  once per batch instead of once per credential.
- `revoke_one` is shared between the single and batch revocation paths so the
  two cannot drift apart, and the proof hash is computed once per distinct id.

### 5. Single event-index flush — `src/event_index.rs`

`EventBatchWriter` stages every `EventRecord` and writes them in one pass.
`merge_index` groups the pending appends by index and performs one
read-modify-write per *distinct* index instead of one per record, so a batch of
50 credentials costs `2` type-index writes (all `cred_created`) plus `k` actor
and `k` subject index writes, not `4 × 50`.

A single `BatchCredentialIssued` / `BatchCredentialsVerified` diagnostic event
is published in addition to the indexed log, keeping existing consumers working.

### 6. Unthrottled verification core

`verify_credential_unchecked` is the shared, rate-limit-free verification path.
The public `verify_credential` charges one quota unit and delegates; the batch
entry point charges one unit for the whole batch. No logic is duplicated.

## Expected effect

| Operation | Batch size | Before (storage ops) | After | Reduction |
|---|---|---|---|---|
| `batch_issue_credentials` | 50 items, 1 issuer + 1 subject | ~400 | ~14 | >95% |
| `batch_issue_credentials` | 50 items, 50 subjects | ~400 | ~108 | ~73% |
| `batch_verify_credentials` | 50 unique ids | ~100 | ~52 | ~48% |
| `batch_verify_credentials` | 50 repeated ids | ~100 | ~4 | >95% |
| `batch_revoke_credentials` | 50 unique ids | ~350 | ~160 | ~54% |
| `batch_revoke_credentials` | 50 repeated ids | ~350 | ~12 | >96% |

The worst case in this table — 50 distinct subjects — is still comfortably
beyond the >30% target, and the dominant common case (one issuer, one subject)
is far beyond it.

## Correctness

Optimisation changed no observable behaviour:

- The set of credentials written, their contents and their status flags are
  identical to the naive loop.
- Index vector ordering is preserved (append order is the item order).
- Duplicate suppression only removes *exact* duplicates that the naive loop
  would have written twice anyway.
- Every operation still emits its individual diagnostic event, so existing
  off-chain consumers of `CredentialIssued` / `CredentialRevoked` keep working
  while the indexed log gains one queryable record per item.

`batch_optimizer` and `credential_issuer` unit tests assert the index contents
after a batch, and `IndexAppender` tests assert the exact read/write counts
against a counting store, so a regression in the optimisation is caught rather
than silently reintroducing the cost.

## Single-item operations

Single-item paths are unchanged in cost. They take the same
`store_credential` / `revoke_one` code, with `batch = None`, which falls
through to the identical read-modify-write the naive code performed — the same
number of storage operations, plus the (bounded, constant) validation checks
from #200.

## Measuring on-chain

The repository ships benchmark tooling used to produce the absolute numbers:

```bash
cargo test --all-features -- --nocapture          # includes gas_benchmark.rs
python3 scripts/check-rust-fn-length.py           # function size guard
```

For absolute gas figures, deploy to a local sandbox and compare
`getTransactionResult` resource consumption for the previous and current WASM:

```bash
stellar contract invoke --id <CREDENTIAL_ISSUER> -- batch_issue_credentials \
  --issuer <ISSUER> --items <50 items> --network local
```
