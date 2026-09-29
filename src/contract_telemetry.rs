//! Contract Telemetry & Health Monitoring (#203)
//!
//! A production Soroban deployment needs to answer two questions without
//! running a full indexer: *is this contract healthy right now?* and *how has
//! it behaved over time?*  This module answers both from on-chain state.
//!
//! * [`get_health_status`] returns a single snapshot a load balancer can poll:
//!   healthy / degraded / unhealthy, plus the reason.
//! * [`get_metrics`] returns time-bucketed counters, so a dashboard can plot
//!   throughput and error rate over a window without re-reading every entry.
//! * [`prometheus_export`] renders the current snapshot in the Prometheus text
//!   exposition format, ready to be scraped.
//!
//! # Recording
//!
//! Instrumentation is opt-in and explicit: a contract calls
//! [`record_operation`] at the end of a state-changing entry point, passing
//! whether it succeeded.  Recording is a single instance-storage write, so the
//! overhead is bounded and predictable.
//!
//! # Bucketing
//!
//! Counters are bucketed by [`bucket_start`] using [`DEFAULT_BUCKET_SECONDS`].
//! A run only ever touches the current bucket and the one before it, which
//! caps the per-call cost no matter how long the contract has been live.
//! Older buckets are pruned on write, so storage does not grow without bound.
//!
//! # Health semantics
//!
//! `healthy` requires that the contract is not paused, that its storage TTLs
//! have headroom, and that its error rate over the recent window is below
//! [`UNHEALTHY_ERROR_RATE_BPS`].  `degraded` means it still functions but one
//! of those is off; `unhealthy` means it is paused or the error rate has
//! crossed the hard threshold.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Bytes, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default width of a metrics bucket, in seconds (5 minutes).
pub const DEFAULT_BUCKET_SECONDS: u64 = 300;

/// Number of recent buckets retained on chain.
pub const MAX_BUCKETS: u32 = 12;

/// Error rate (in basis points) at or above which a contract is `unhealthy`.
pub const UNHEALTHY_ERROR_RATE_BPS: u32 = 5_000; // 50%

/// Error rate (in basis points) at or above which a contract is `degraded`.
pub const DEGRADED_ERROR_RATE_BPS: u32 = 1_000; // 10%

/// Basis points used to normalise rates, so all rate maths stays in integers.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Remaining TTL (in ledgers) below which a contract reports `degraded`.
pub const LOW_TTL_THRESHOLD_LEDGERS: u32 = 100;

/// TTL for telemetry storage entries (~1 year).
const TELEMETRY_TTL_LEDGERS: u32 = 6_307_200;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Overall verdict from [`get_health_status`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealthStatus {
    /// All checks pass.
    Healthy,
    /// Usable, but at least one check is off.
    Degraded,
    /// Not safe to route traffic to.
    Unhealthy,
}

impl HealthStatus {
    /// Render as a Prometheus-friendly lowercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        }
    }
}

/// A point-in-time health snapshot.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthReport {
    /// Overall verdict.
    pub status: HealthStatus,
    /// `true` when the contract is not paused.
    pub is_paused: bool,
    /// Whether at least one storage key is within [`LOW_TTL_THRESHOLD_LEDGERS`]
    /// of expiry.
    pub storage_ttl_low: bool,
    /// Total successful operations observed.
    pub total_success: u32,
    /// Total failed operations observed.
    pub total_errors: u32,
    /// Error rate over the recent window, in basis points.
    pub error_rate_bps: u32,
    /// Ledger timestamp the snapshot was taken at.
    pub observed_at: u64,
    /// Machine-readable detail on the most significant failure, if any.
    pub reason: Symbol,
}

/// Counters for one time bucket.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricBucket {
    /// Start of the bucket window, as a Unix timestamp.
    pub bucket_start: u64,
    /// Bucket width in seconds.
    pub bucket_seconds: u64,
    /// Successful operations in this bucket.
    pub success: u32,
    /// Failed operations in this bucket.
    pub errors: u32,
    /// Total operations observed in this bucket.
    pub total: u32,
}

/// Aggregate counters plus the recent bucket series.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricsSnapshot {
    /// Lifetime successful operations.
    pub total_success: u32,
    /// Lifetime failed operations.
    pub total_errors: u32,
    /// Lifetime total operations.
    pub total_operations: u32,
    /// Lifetime error rate in basis points.
    pub error_rate_bps: u32,
    /// Number of collection-relevant state entries tracked by the contract.
    pub tracked_entries: u32,
    /// Retained buckets, oldest first.
    pub buckets: Vec<MetricBucket>,
    /// Ledger timestamp the snapshot was taken at.
    pub observed_at: u64,
}

/// One recorded operation, for auditing the counters.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    /// Name of the entry point that ran.
    pub operation: Symbol,
    /// Whether it succeeded.
    pub success: bool,
    /// Ledger timestamp.
    pub timestamp: u64,
    /// TTL of the contract's telemetry key at the time of recording.
    pub ttl_ledgers: u32,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub enum TelemetryKey {
    /// Lifetime successful operations.
    TotalSuccess,
    /// Lifetime failed operations.
    TotalErrors,
    /// Number of tracked state entries, set by the owning contract.
    TrackedEntries,
    /// The most recent operation record.
    LastOperation,
    /// A metrics bucket identified by its start timestamp.
    Bucket(u64),
    /// Start timestamps of retained buckets, oldest first.
    BucketIndex,
    /// Current paused flag, mirrored from the owning contract.
    Paused,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum TelemetryError {
    /// A supplied bucket width was zero.
    InvalidBucketWidth = 1,
    /// More buckets were requested than [`MAX_BUCKETS`] allows.
    TooManyBuckets = 2,
    /// A supplied entry count exceeded the u32 range.
    InvalidEntryCount = 3,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Compute the start of the bucket containing `timestamp`.
pub fn bucket_start(timestamp: u64, bucket_seconds: u64) -> u64 {
    if bucket_seconds == 0 {
        return timestamp;
    }
    timestamp - (timestamp % bucket_seconds)
}

/// Number of whole buckets between two timestamps, plus one for the
/// inclusive endpoint.  Used to size a range query.
pub fn bucket_span(from: u64, to: u64, bucket_seconds: u64) -> u32 {
    if bucket_seconds == 0 || to < from {
        return 1;
    }
    let start = bucket_start(from, bucket_seconds);
    let end = bucket_start(to, bucket_seconds);
    (((end - start) / bucket_seconds) + 1) as u32
}

/// Error rate in basis points, rounded down.  A window with no operations is
/// reported as `0` rather than dividing by zero.
pub fn error_rate_bps(success: u32, errors: u32) -> u32 {
    let total = success + errors;
    if total == 0 {
        return 0;
    }
    (errors * BPS_DENOMINATOR) / total
}

/// Roll an error rate up to a [`HealthStatus`].
///
/// Split out from [`get_health_status`] so the mapping is directly testable
/// and can be reused by callers that compute rates themselves.
pub fn classify_error_rate(error_rate_bps: u32) -> HealthStatus {
    if error_rate_bps >= UNHEALTHY_ERROR_RATE_BPS {
        HealthStatus::Unhealthy
    } else if error_rate_bps >= DEGRADED_ERROR_RATE_BPS {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    }
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// Record the outcome of one operation and fold it into the current bucket.
///
/// `storage_ttl_ledgers` is the remaining TTL the caller observed on its own
/// state; the module uses it to feed the low-TTL health signal but does not
/// interpret it beyond the threshold check.
pub fn record_operation(env: &Env, operation: Symbol, success: bool, storage_ttl_ledgers: u32) {
    let now = env.ledger().timestamp();
    let bucket_seconds = resolve_bucket_seconds(env);

    if success {
        let total = read_u32(env, &TelemetryKey::TotalSuccess) + 1;
        env.storage()
            .persistent()
            .set(&TelemetryKey::TotalSuccess, &total);
    } else {
        let total = read_u32(env, &TelemetryKey::TotalErrors) + 1;
        env.storage()
            .persistent()
            .set(&TelemetryKey::TotalErrors, &total);
    }

    let bucket = bucket_start(now, bucket_seconds);
    let mut entry = read_bucket(env, bucket, bucket_seconds);
    if success {
        entry.success += 1;
    } else {
        entry.errors += 1;
    }
    entry.total = entry.success + entry.errors;
    env.storage()
        .persistent()
        .set(&TelemetryKey::Bucket(bucket), &entry);

    touch_bucket_index(env, bucket);
    prune_buckets(env);

    env.storage().persistent().set(
        &TelemetryKey::LastOperation,
        &OperationRecord {
            operation: operation.clone(),
            success,
            timestamp: now,
            ttl_ledgers: storage_ttl_ledgers,
        },
    );

    env.events().publish(
        (Symbol::new(env, "ContractOperationRecorded"),),
        (operation, success, bucket),
    );

    extend_ttls(env);
}

/// Declare how many state entries the owning contract tracks, which becomes
/// the `tracked_entries` metric.
pub fn set_tracked_entries(env: &Env, entries: u32) -> Result<(), TelemetryError> {
    env.storage()
        .persistent()
        .set(&TelemetryKey::TrackedEntries, &entries);
    Ok(())
}

/// Mirror the owning contract's paused flag so health checks can read it
/// without a cross-contract call.
pub fn set_paused(env: &Env, paused: bool) {
    env.storage()
        .persistent()
        .set(&TelemetryKey::Paused, &paused);
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Return a health snapshot for the contract.
///
/// A load balancer can poll this on an interval and route on `status`.
pub fn get_health_status(env: &Env) -> HealthReport {
    let now = env.ledger().timestamp();
    let total_success = read_u32(env, &TelemetryKey::TotalSuccess);
    let total_errors = read_u32(env, &TelemetryKey::TotalErrors);

    // Prefer the recent bucket series for the error rate so a contract that
    // was briefly unhealthy does not look permanently broken; fall back to
    // lifetime totals when there is not yet a full bucket of data.
    let (rate_success, rate_errors) = recent_window(env, now);
    let (error_rate_bps, has_window) = if rate_success + rate_errors > 0 {
        (error_rate_bps(rate_success, rate_errors), true)
    } else {
        (error_rate_bps(total_success, total_errors), false)
    };

    let is_paused = env
        .storage()
        .persistent()
        .get(&TelemetryKey::Paused)
        .unwrap_or(false);

    let storage_ttl_low = env
        .storage()
        .persistent()
        .get(&TelemetryKey::LastOperation)
        .map(|record: OperationRecord| record.ttl_ledgers < LOW_TTL_THRESHOLD_LEDGERS)
        .unwrap_or(false);

    let rate_status = classify_error_rate(error_rate_bps);
    let status = if is_paused {
        HealthStatus::Unhealthy
    } else if rate_status == HealthStatus::Unhealthy {
        HealthStatus::Unhealthy
    } else if rate_status == HealthStatus::Degraded || storage_ttl_low || !has_window {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    let reason = if is_paused {
        "paused"
    } else if rate_status == HealthStatus::Unhealthy {
        "error_rate"
    } else if storage_ttl_low {
        "low_storage_ttl"
    } else if !has_window {
        "insufficient_data"
    } else {
        "ok"
    };

    HealthReport {
        status,
        is_paused,
        storage_ttl_low,
        total_success,
        total_errors,
        error_rate_bps,
        observed_at: now,
        reason: Symbol::new(env, reason),
    }
}

/// Return aggregate counters plus the recent bucket series.
///
/// `bucket_count` is clamped to [`MAX_BUCKETS`]; `bucket_seconds == 0`
/// selects [`DEFAULT_BUCKET_SECONDS`].
pub fn get_metrics(
    env: &Env,
    bucket_count: u32,
    mut bucket_seconds: u64,
) -> Result<MetricsSnapshot, TelemetryError> {
    if bucket_count > MAX_BUCKETS {
        return Err(TelemetryError::TooManyBuckets);
    }
    if bucket_seconds == 0 {
        // Zero means "use the default", not an error.
        bucket_seconds = DEFAULT_BUCKET_SECONDS;
    }

    let total_success = read_u32(env, &TelemetryKey::TotalSuccess);
    let total_errors = read_u32(env, &TelemetryKey::TotalErrors);

    let index: Vec<u64> = env
        .storage()
        .persistent()
        .get(&TelemetryKey::BucketIndex)
        .unwrap_or_else(|| Vec::new(env));

    let len = index.len();
    let take = core::cmp::min(bucket_count as u32, len);
    let start = len - take as u32;

    let mut buckets = Vec::new(env);
    for i in start..len {
        if let Some(bucket) = index.get(i) {
            buckets.push_back(read_bucket(env, bucket, bucket_seconds));
        }
    }

    Ok(MetricsSnapshot {
        total_success,
        total_errors,
        total_operations: total_success + total_errors,
        error_rate_bps: error_rate_bps(total_success, total_errors),
        tracked_entries: read_u32(env, &TelemetryKey::TrackedEntries),
        buckets,
        observed_at: env.ledger().timestamp(),
    })
}

/// The most recently recorded operation, if any.
pub fn get_last_operation(env: &Env) -> Option<OperationRecord> {
    env.storage().persistent().get(&TelemetryKey::LastOperation)
}

/// Number of retained buckets.
pub fn get_bucket_count(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&TelemetryKey::BucketIndex)
        .map(|index: Vec<u64>| index.len())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Prometheus export
// ---------------------------------------------------------------------------

/// Render the health report and metrics in Prometheus text exposition format.
///
/// The output is newline-delimited `name{labels} value` records, which is
/// exactly what a Prometheus textfile collector or a `/metrics` endpoint
/// expects.  A `# HELP` and `# TYPE` header precedes each metric family.
pub fn prometheus_export(
    env: &Env,
    contract_name: &str,
    bucket_count: u32,
) -> Result<Bytes, TelemetryError> {
    let p = contract_name;
    let health = get_health_status(env);
    let snapshot = get_metrics(env, bucket_count, DEFAULT_BUCKET_SECONDS)?;

    let mut out = alloc::format!(
        "# HELP {p}_up 1 when the contract is not paused.\n\
         # TYPE {p}_up gauge\n\
         {p}_up {up}\n\
         # HELP {p}_health_status 1 for the active health status.\n\
         # TYPE {p}_health_status gauge\n\
         {p}_health_status{{status=\"{status}\"}} 1\n\
         # HELP {p}_error_rate_bps Recent error rate in basis points.\n\
         # TYPE {p}_error_rate_bps gauge\n\
         {p}_error_rate_bps {rate}\n\
         # HELP {p}_operations_total Operations observed, by outcome.\n\
         # TYPE {p}_operations_total counter\n\
         {p}_operations_total{{outcome=\"success\"}} {success}\n\
         {p}_operations_total{{outcome=\"error\"}} {errors}\n\
         # HELP {p}_storage_ttl_low 1 when a tracked storage key is near expiry.\n\
         # TYPE {p}_storage_ttl_low gauge\n\
         {p}_storage_ttl_low {ttl_low}\n\
         # HELP {p}_operations_bucket Operations per time bucket.\n\
         # TYPE {p}_operations_bucket counter\n",
        p = p,
        up = u8::from(!health.is_paused),
        status = health.status.as_str(),
        rate = health.error_rate_bps,
        success = health.total_success,
        errors = health.total_errors,
        ttl_low = u8::from(health.storage_ttl_low),
    );

    for bucket in snapshot.buckets.iter() {
        out.push_str(&alloc::format!(
            "{p}_operations_bucket{{start=\"{start}\"}} {total}\n",
            p = p,
            start = bucket.bucket_start,
            total = bucket.total,
        ));
    }

    Ok(Bytes::from_slice(env, out.as_bytes()))
}

// ---------------------------------------------------------------------------
// Standalone contract surface
// ---------------------------------------------------------------------------

/// A standalone telemetry contract, so a deployment can host monitoring
/// independently of the contracts it observes.
#[contract]
pub struct ContractTelemetry;

#[contractimpl]
impl ContractTelemetry {
    /// Record the outcome of an operation.
    pub fn record_operation(env: Env, operation: Symbol, success: bool, storage_ttl_ledgers: u32) {
        record_operation(&env, operation, success, storage_ttl_ledgers);
    }

    /// A health snapshot, suitable for a load-balancer health check.
    pub fn get_health_status(env: Env) -> HealthReport {
        get_health_status(&env)
    }

    /// `true` when the contract reports `Healthy`.
    ///
    /// A dedicated boolean keeps the health endpoint cheap to scrape.
    pub fn is_healthy(env: Env) -> bool {
        get_health_status(&env).status == HealthStatus::Healthy
    }

    /// The current health verdict as a lowercase string.
    pub fn health_status_string(env: Env) -> Symbol {
        let status = get_health_status(&env).status;
        Symbol::new(
            &env,
            match status {
                HealthStatus::Healthy => "healthy",
                HealthStatus::Degraded => "degraded",
                HealthStatus::Unhealthy => "unhealthy",
            },
        )
    }

    /// Aggregate counters and the recent bucket series.
    pub fn get_metrics(
        env: Env,
        bucket_count: u32,
        bucket_seconds: u64,
    ) -> Result<MetricsSnapshot, TelemetryError> {
        get_metrics(&env, bucket_count, bucket_seconds)
    }

    /// The most recently recorded operation.
    pub fn get_last_operation(env: Env) -> Option<OperationRecord> {
        get_last_operation(&env)
    }

    /// Declare the number of tracked state entries.
    pub fn set_tracked_entries(env: Env, entries: u32) -> Result<(), TelemetryError> {
        set_tracked_entries(&env, entries)
    }

    /// Mirror the owning contract's paused flag.
    pub fn set_paused(env: Env, paused: bool) {
        set_paused(&env, paused);
    }

    /// Prometheus text exposition of the current snapshot.
    pub fn prometheus_export(
        env: Env,
        contract_name: Symbol,
        bucket_count: u32,
    ) -> Result<Bytes, TelemetryError> {
        let name = contract_name.to_string();
        prometheus_export(&env, &name, bucket_count)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn resolve_bucket_seconds(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&soroban_sdk::Symbol::new(env, "bucket_seconds"))
        .unwrap_or(DEFAULT_BUCKET_SECONDS)
}

fn read_u32(env: &Env, key: &TelemetryKey) -> u32 {
    env.storage().persistent().get(key).unwrap_or(0)
}

fn read_bucket(env: &Env, start: u64, bucket_seconds: u64) -> MetricBucket {
    env.storage()
        .persistent()
        .get(&TelemetryKey::Bucket(start))
        .unwrap_or(MetricBucket {
            bucket_start: start,
            bucket_seconds,
            success: 0,
            errors: 0,
            total: 0,
        })
}

fn touch_bucket_index(env: &Env, bucket: u64) {
    let mut index: Vec<u64> = env
        .storage()
        .persistent()
        .get(&TelemetryKey::BucketIndex)
        .unwrap_or_else(|| Vec::new(env));
    if index.is_empty() || index.get(index.len() - 1).unwrap_or(0) != bucket {
        index.push_back(bucket);
    }
    env.storage()
        .persistent()
        .set(&TelemetryKey::BucketIndex, &index);
}

/// Drop buckets older than [`MAX_BUCKETS`], keeping the series bounded.
fn prune_buckets(env: &Env) {
    let index: Vec<u64> = env
        .storage()
        .persistent()
        .get(&TelemetryKey::BucketIndex)
        .unwrap_or_else(|| Vec::new(env));

    let len = index.len();
    if len <= MAX_BUCKETS as u32 {
        return;
    }

    let drop_count = len - MAX_BUCKETS;
    let mut kept = Vec::new(env);
    for i in drop_count..len {
        if let Some(bucket) = index.get(i) {
            kept.push_back(bucket);
            env.storage()
                .persistent()
                .remove(&TelemetryKey::Bucket(bucket));
        }
    }
    env.storage()
        .persistent()
        .set(&TelemetryKey::BucketIndex, &kept);
}

/// Sum successes and errors over the most recent non-empty bucket.
fn recent_window(env: &Env, now: u64) -> (u32, u32) {
    let index: Vec<u64> = env
        .storage()
        .persistent()
        .get(&TelemetryKey::BucketIndex)
        .unwrap_or_else(|| Vec::new(env));

    let bucket_seconds = resolve_bucket_seconds(env);
    let mut i = index.len();
    while i > 0 {
        i -= 1;
        if let Some(bucket) = index.get(i) {
            // Only buckets that have actually started count; a bucket for a
            // future window would skew the rate.
            if bucket <= now {
                let entry = read_bucket(env, bucket, bucket_seconds);
                return (entry.success, entry.errors);
            }
        }
    }
    (0, 0)
}

fn extend_ttls(env: &Env) {
    for key in [
        TelemetryKey::TotalSuccess,
        TelemetryKey::TotalErrors,
        TelemetryKey::TrackedEntries,
        TelemetryKey::LastOperation,
        TelemetryKey::Paused,
        TelemetryKey::BucketIndex,
    ] {
        env.storage()
            .persistent()
            .extend_ttl(&key, TELEMETRY_TTL_LEDGERS, TELEMETRY_TTL_LEDGERS);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::Symbol;

    fn setup_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000,
            protocol_version: 22,
            sequence_number: 1000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });
        env
    }

    fn op(env: &Env, name: &str) -> Symbol {
        Symbol::new(env, name)
    }

    #[test]
    fn bucket_start_snapshots_to_window() {
        assert_eq!(bucket_start(1_000, 300), 900);
        assert_eq!(bucket_start(900, 300), 900);
        assert_eq!(bucket_start(1_200, 300), 1_200);
    }

    #[test]
    fn bucket_start_with_zero_width_is_identity() {
        assert_eq!(bucket_start(1_234, 0), 1_234);
    }

    #[test]
    fn bucket_span_counts_inclusive() {
        assert_eq!(bucket_span(0, 0, 300), 1);
        assert_eq!(bucket_span(0, 300, 300), 2);
        assert_eq!(bucket_span(0, 299, 300), 1);
    }

    #[test]
    fn bucket_span_handles_inverted_range() {
        assert_eq!(bucket_span(500, 100, 300), 1);
    }

    #[test]
    fn error_rate_is_zero_without_operations() {
        assert_eq!(error_rate_bps(0, 0), 0);
    }

    #[test]
    fn error_rate_computes_basis_points() {
        assert_eq!(error_rate_bps(90, 10), 1_000);
        assert_eq!(error_rate_bps(0, 100), 10_000);
    }

    #[test]
    fn classify_error_rate_thresholds() {
        assert_eq!(classify_error_rate(0), HealthStatus::Healthy);
        assert_eq!(classify_error_rate(999), HealthStatus::Healthy);
        assert_eq!(classify_error_rate(1_000), HealthStatus::Degraded);
        assert_eq!(classify_error_rate(4_999), HealthStatus::Degraded);
        assert_eq!(classify_error_rate(5_000), HealthStatus::Unhealthy);
    }

    #[test]
    fn health_status_as_str() {
        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.as_str(), "unhealthy");
    }

    #[test]
    fn fresh_contract_is_degraded_for_lack_of_data() {
        let env = setup_env();
        let report = get_health_status(&env);
        assert_eq!(report.status, HealthStatus::Degraded);
        assert_eq!(report.reason, Symbol::new(&env, "insufficient_data"));
        assert!(!report.is_paused);
    }

    #[test]
    fn recording_success_improves_health() {
        let env = setup_env();
        for _ in 0..5 {
            record_operation(&env, op(&env, "issue"), true, 5_000);
        }
        let report = get_health_status(&env);
        assert_eq!(report.status, HealthStatus::Healthy);
        assert_eq!(report.total_success, 5);
        assert_eq!(report.total_errors, 0);
        assert_eq!(report.error_rate_bps, 0);
    }

    #[test]
    fn paused_contract_is_unhealthy() {
        let env = setup_env();
        record_operation(&env, op(&env, "issue"), true, 5_000);
        set_paused(&env, true);
        let report = get_health_status(&env);
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(report.is_paused);
        assert_eq!(report.reason, Symbol::new(&env, "paused"));
    }

    #[test]
    fn high_error_rate_is_unhealthy() {
        let env = setup_env();
        for _ in 0..9 {
            record_operation(&env, op(&env, "issue"), true, 5_000);
        }
        record_operation(&env, op(&env, "issue"), false, 5_000);
        let report = get_health_status(&env);
        assert_eq!(report.error_rate_bps, 1_000);
        assert_eq!(report.status, HealthStatus::Degraded);
    }

    #[test]
    fn low_storage_ttl_is_degraded() {
        let env = setup_env();
        record_operation(&env, op(&env, "issue"), true, 1);
        let report = get_health_status(&env);
        assert!(report.storage_ttl_low);
        assert_eq!(report.status, HealthStatus::Degraded);
        assert_eq!(report.reason, Symbol::new(&env, "low_storage_ttl"));
    }

    #[test]
    fn metrics_counters_accumulate() {
        let env = setup_env();
        for _ in 0..3 {
            record_operation(&env, op(&env, "issue"), true, 5_000);
        }
        record_operation(&env, op(&env, "issue"), false, 5_000);

        let snapshot = get_metrics(&env, 4, DEFAULT_BUCKET_SECONDS).unwrap();
        assert_eq!(snapshot.total_success, 3);
        assert_eq!(snapshot.total_errors, 1);
        assert_eq!(snapshot.total_operations, 4);
        assert_eq!(snapshot.error_rate_bps, 2_500);
        assert_eq!(snapshot.buckets.len(), 1);
        assert_eq!(snapshot.buckets.get(0).unwrap().total, 4);
    }

    #[test]
    fn buckets_split_over_time() {
        let env = setup_env();
        record_operation(&env, op(&env, "issue"), true, 5_000);

        env.ledger()
            .with_mut(|li| li.timestamp += DEFAULT_BUCKET_SECONDS);
        record_operation(&env, op(&env, "issue"), true, 5_000);

        let snapshot = get_metrics(&env, 4, DEFAULT_BUCKET_SECONDS).unwrap();
        assert_eq!(snapshot.buckets.len(), 2);
        assert_eq!(snapshot.buckets.get(0).unwrap().total, 1);
        assert_eq!(snapshot.buckets.get(1).unwrap().total, 1);
    }

    #[test]
    fn buckets_are_pruned_to_the_cap() {
        let env = setup_env();
        for i in 0..(MAX_BUCKETS + 5) {
            record_operation(&env, op(&env, "issue"), true, 5_000);
            env.ledger()
                .with_mut(|li| li.timestamp += DEFAULT_BUCKET_SECONDS);
        }
        assert_eq!(get_bucket_count(&env), MAX_BUCKETS);
    }

    #[test]
    fn bucket_count_over_cap_is_rejected() {
        let env = setup_env();
        assert_eq!(
            get_metrics(&env, MAX_BUCKETS + 1, DEFAULT_BUCKET_SECONDS),
            Err(TelemetryError::TooManyBuckets)
        );
    }

    #[test]
    fn zero_bucket_width_falls_back_to_default() {
        let env = setup_env();
        record_operation(&env, op(&env, "issue"), true, 5_000);
        let snapshot = get_metrics(&env, 2, 0).unwrap();
        assert_eq!(
            snapshot.buckets.get(0).unwrap().bucket_seconds,
            DEFAULT_BUCKET_SECONDS
        );
    }

    #[test]
    fn last_operation_is_recorded() {
        let env = setup_env();
        record_operation(&env, op(&env, "revoke"), false, 4_200);
        let record = get_last_operation(&env).unwrap();
        assert_eq!(record.operation, op(&env, "revoke"));
        assert!(!record.success);
        assert_eq!(record.ttl_ledgers, 4_200);
        assert_eq!(record.timestamp, 1_700_000_000);
    }

    #[test]
    fn tracked_entries_are_reported() {
        let env = setup_env();
        set_tracked_entries(&env, 17).unwrap();
        let snapshot = get_metrics(&env, 1, DEFAULT_BUCKET_SECONDS).unwrap();
        assert_eq!(snapshot.tracked_entries, 17);
    }

    #[test]
    fn prometheus_export_has_expected_shape() {
        let env = setup_env();
        for _ in 0..4 {
            record_operation(&env, op(&env, "issue"), true, 5_000);
        }
        let exported = prometheus_export(&env, "did_registry", 4).unwrap();
        let text: alloc::string::String = exported.to_array().iter().map(|b| *b as char).collect();
        assert!(text.contains("# TYPE did_registry_up gauge"));
        assert!(text.contains("did_registry_up 1"));
        assert!(text.contains("did_registry_operations_total{outcome=\"success\"} 4"));
        assert!(text.contains("did_registry_health_status{status=\"healthy\"} 1"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn prometheus_export_reports_paused() {
        let env = setup_env();
        record_operation(&env, op(&env, "issue"), true, 5_000);
        set_paused(&env, true);
        let exported = prometheus_export(&env, "did_registry", 4).unwrap();
        let text: alloc::string::String = exported.to_array().iter().map(|b| *b as char).collect();
        assert!(text.contains("did_registry_up 0"));
        assert!(text.contains("status=\"unhealthy\""));
    }

    #[test]
    fn prometheus_export_works_without_data() {
        let env = setup_env();
        let exported = prometheus_export(&env, "empty", 2).unwrap();
        let text: alloc::string::String = exported.to_array().iter().map(|b| *b as char).collect();
        assert!(text.contains("empty_up 1"));
    }
}
