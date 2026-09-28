# Gas Benchmarks

This document describes the gas benchmark regression testing infrastructure for the Stellar Identity & Credentials SDK.

## Overview

Gas benchmarks measure the computational cost (in terms of Rust operations, which correlate to Stellar network fees) of each contract's main functions. They are run on every PR to detect performance regressions before they reach production.

## Running Benchmarks Locally

```bash
cargo test
```

Benchmark output is tagged with `[BENCH]` prefix for easy parsing:

```
[BENCH] create_did            OK
[BENCH] resolve_did           OK
[BENCH] issue_credential      OK
...
```

## Benchmark Coverage

### DID Registry

| Benchmark | Operation | Description |
|-----------|-----------|-------------|
| `bench_create_did` | `create_did` | Register a new DID with 1 verification method and 1 service |
| `bench_resolve_did` | `resolve_did` | Retrieve a stored DID document |
| `bench_update_did` | `update_did` | Update verification methods on an existing DID |
| `bench_deactivate_did` | `deactivate_did` | Permanently deactivate a DID |
| `bench_configure_multisig` | `configure_multisig` | Set up multi-sig governance (3-of-3) |
| `bench_multisig_operation_lifecycle` | `create_multisig_operation` + `sign_multisig_operation` + `execute_multisig_operation` | Full lifecycle: create, sign by 2 parties, execute |

### Credential Issuer

| Benchmark | Operation | Description |
|-----------|-----------|-------------|
| `bench_issue_credential` | `issue_credential` | Issue a single verifiable credential |
| `bench_verify_credential` | `verify_credential` | Verify an issued credential |
| `bench_revoke_credential` | `revoke_credential` | Revoke a credential with reason |
| `bench_batch_issue_credentials` | `batch_issue_credentials` | Issue 2 credentials in a single transaction |
| `bench_batch_verify_credentials` | `batch_verify_credentials` | Verify 2 credentials in a single transaction |
| `bench_register_schema` | `register_schema` | Register a credential schema with required/optional fields |
| `bench_paginated_credentials` | `get_credentials_by_subject` | Paginate through 25 credentials (page size 10) |

### Reputation Score

| Benchmark | Operation | Description |
|-----------|-----------|-------------|
| `bench_initialize_reputation` | `initialize_reputation` | Create a user reputation record |
| `bench_update_reputation` | `update_transaction_reputation` | Record a successful transaction |
| `bench_update_credential_reputation` | `update_credential_reputation` | Record a valid credential verification |
| `bench_batch_update_transaction_reputation` | `batch_update_transaction_reputation` | Update 2 users in a single call |
| `bench_attest_trust` | `attest_trust` | Record a trust attestation with reason |

### ZK Attestation

| Benchmark | Operation | Description |
|-----------|-----------|-------------|
| `bench_register_circuit` | `register_circuit` | Register a new ZK circuit definition |
| `bench_submit_proof` | `submit_proof` | Submit and verify a ZK proof |
| `bench_verify_proof` | `verify_proof` | Re-verify a stored ZK proof |
| `bench_batch_verify_proofs` | `batch_verify_proofs` | Verify 2 proofs in a single call |

### Compliance Filter

| Benchmark | Operation | Description |
|-----------|-----------|-------------|
| `bench_screen_address` | `screen_address` | Screen a single address against sanctions lists |
| `bench_batch_screen_addresses` | `batch_screen_addresses` | Batch-screen 5 addresses |
| `bench_update_sanctions_list` | `update_sanctions_list` | Publish a new sanctions list header |
| `bench_add_to_sanctions_list` | `add_to_sanctions_list` | Add a single address to a sanctions list |

## CI Integration

The `.github/workflows/gas-benchmarks.yml` workflow:

1. **Triggers** on push/PR to `master` or `main` branches.
  2. **Runs** `cargo test` on the `wasm32-unknown-unknown` target.
3. **Archives** the raw output as a CI artifact (`gas-benchmarks-<sha>`) retained for 90 days.
4. **Regression checks** compare each `[BENCH]` line against `gas-benchmark-baseline.txt`.
   - If a benchmark returns `FAIL` instead of `OK`, the job fails.
   - New benchmarks (not in baseline) emit a warning but do not fail the job.
   - If no baseline exists yet, the current run generates one and exits successfully.

## Alert Threshold

The regression threshold is controlled by the `GAS_REGRESSION_THRESHOLD` environment variable (default: `10`). The CI workflow currently enforces a binary pass/fail per benchmark outcome. For future enhancements, numeric gas usage tracking can be added by instrumenting benchmarks with Soroban `Ledger` metering to capture precise `consumed_ledger` values and compare deltas against the threshold.

## Baseline File

`gas-benchmark-baseline.txt` stores the expected state of all benchmarks. Update it manually when intentional changes are made:

```bash
cargo test 2>&1 | grep '\[BENCH\]' > gas-benchmark-baseline.txt
git add gas-benchmark-baseline.txt
git commit -m "bench: update gas benchmark baseline"
```

## Adding New Benchmarks

1. Add a `#[test]` function in `src/gas_benchmark.rs` following the existing pattern.
2. Use `std::println!("[BENCH] <name> ... OK")` to report success.
3. Include setup assertions to ensure the test is self-contained.
4. Re-run to regenerate the baseline.

## Gas Optimization Tips

Based on benchmark results:

- **Persistent storage writes** are the most expensive operation. Minimize writes per transaction.
- **Vector iterations** over large collections add linear cost. Prefer pagination for user-facing reads.
- **Cross-contract calls** (e.g., `schema_registry::validate`) incur additional overhead. Cache validation results where possible.
- **Event emission** has modest cost but should be limited to critical state changes.
- **Rate limiter checks** add a small constant overhead but prevent abuse and reduce overall system load.
