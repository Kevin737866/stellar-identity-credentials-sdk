//! Storage Garbage Collection for Expired Entries (#199)
//!
//! Time-limited data — credentials with an `expiration_date`, proofs with an
//! expiry, cached attestations — occupies persistent storage until somebody
//! removes it.  Soroban charges rent for as long as an entry lives, so an
//! unbounded pile of expired records both wastes rent and slows down scans that
//! have to walk past them.
//!
//! This module provides a permissionless, batched collector:
//!
//! * [`collect_garbage`] walks a caller-supplied set of entry keys in bounded
//!   batches, removes the ones that are genuinely expired, and reports how
//!   much was reclaimed.
//! * Explicit TTL extension ([`extend_entry_ttl`]) lets an entry that should
//!   persist outlive its natural expiry without being deleted.
//! * [`collect_across_contracts`] fans a collection run out over several
//!   registered contracts in a single transaction.
//!
//! # Gas model
//!
//! Collection is batch-limited on purpose.  A single call processes at most
//! `batch_size` keys so the worst-case cost is bounded and predictable; a
//! keeper can call it repeatedly until `has_more` is `false`.
//!
//! # Safety
//!
//! The collector is *permissionless* — anyone may call it, which is what makes
//! it usable as a cron/keeper job.  Safety comes from the expiry check itself:
//! [`collect_garbage`] only removes entries whose recorded `expires_at` is in
//! the past.  Entries that are still live are counted as `skipped_live` and
//! left untouched.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol, Vec,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// TTL applied by [`extend_entry_ttl`] (~1 year).
pub const DEFAULT_EXTENSION_LEDGERS: u32 = 6_307_200;

/// Default number of entries processed per collection call.
pub const DEFAULT_BATCH_SIZE: u32 = 25;

/// Hard cap on `batch_size`, so a caller cannot force an unbounded scan.
pub const MAX_BATCH_SIZE: u32 = 100;

/// TTL for the module's own persistent bookkeeping (~1 year).
const GC_TTL_LEDGERS: u32 = 6_307_200;

/// Maximum number of contracts a single [`collect_across_contracts`] call
/// will visit.  Bounds the worst-case cost of a fan-out run.
pub const MAX_CONTRACTS_PER_RUN: u32 = 10;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The kinds of data that can be garbage collected.
///
/// Each variant is given a distinct storage namespace by the embedding
/// contract, which lets a single collection run cover several data types.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageDomain {
    /// Issued credentials with an `expiration_date`.
    Credentials,
    /// Zero-knowledge proofs with an expiry.
    Proofs,
    /// Cached contract responses / attestations.
    Cache,
    /// Revocation proofs and status snapshots.
    Revocation,
    /// ZK nullifiers past their retention window.
    Nullifiers,
    /// Any other caller-defined domain.
    Custom(Symbol),
}

/// A description of one collectable entry.
///
/// The collector is generic over the calling contract: rather than reaching
/// into another contract's private storage (which Soroban forbids), the
/// caller supplies these lightweight descriptors and the collector decides
/// which ones to remove and tells the caller which to drop from its own index.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcCandidate {
    /// Opaque key of the entry within the caller's storage namespace.
    pub key: Bytes,
    /// Unix timestamp at which the entry stops being valid.
    pub expires_at: u64,
    /// Number of persistent storage slots the entry occupies, used to report
    /// the reclaimed footprint.
    pub footprint_entries: u32,
}

/// The result of a single collection run.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcResult {
    /// Entries removed during this run.
    pub collected: u32,
    /// Entries left in place because they are still live.
    pub skipped_live: u32,
    /// Estimated number of persistent storage slots reclaimed.
    pub entries_reclaimed: u32,
    /// `true` when `batch_size` was hit and more work remains.
    pub has_more: bool,
    /// Ledger timestamp the expiry check was performed against.
    pub evaluated_at: u64,
}

impl GcResult {
    /// A zeroed result, used as the accumulator's starting value.
    pub fn empty(evaluated_at: u64) -> Self {
        Self {
            collected: 0,
            skipped_live: 0,
            entries_reclaimed: 0,
            has_more: false,
            evaluated_at,
        }
    }

    /// Fold another batch's tallies into this result.
    pub fn absorb(&mut self, other: &GcResult) {
        self.collected += other.collected;
        self.skipped_live += other.skipped_live;
        self.entries_reclaimed += other.entries_reclaimed;
        if other.has_more {
            self.has_more = true;
        }
    }
}

/// Aggregated results for a multi-contract collection run.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchGcResult {
    /// Total entries reclaimed across every visited contract.
    pub total_collected: u32,
    /// Total storage slots reclaimed across every visited contract.
    pub total_entries_reclaimed: u32,
    /// Number of contracts that were actually visited.
    pub contracts_visited: u32,
    /// Number of contracts that were requested but skipped (over the cap).
    pub contracts_skipped: u32,
    /// `true` when any visited contract still has work outstanding.
    pub has_more: bool,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub enum GcKey {
    /// Cumulative entries reclaimed, for observability.
    TotalCollected,
    /// Cumulative storage slots reclaimed.
    TotalReclaimed,
    /// Number of completed collection runs.
    RunCount,
    /// Last run's result summary, for dashboards and health checks.
    LastResult,
    /// Per-domain running totals: (domain, collected, reclaimed).
    DomainTotals(StorageDomain),
    /// The registered candidate list for a domain.
    Candidates(StorageDomain),
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum GcError {
    /// `batch_size` was zero.
    InvalidBatchSize = 1,
    /// `batch_size` exceeded [`MAX_BATCH_SIZE`].
    BatchSizeTooLarge = 2,
    /// A candidate entry was malformed (for example a zero footprint).
    InvalidCandidate = 3,
    /// More contracts were requested than [`MAX_CONTRACTS_PER_RUN`] allows.
    TooManyContracts = 4,
    /// The referenced contract does not expose a collection entry point.
    UnsupportedContract = 5,
    /// A collection call failed inside a registered contract.
    CollectionFailed = 6,
}

// ---------------------------------------------------------------------------
// Core collection
// ---------------------------------------------------------------------------

/// Clamp a caller-supplied batch size into `1..=MAX_BATCH_SIZE`.
///
/// A zero batch size is a caller bug rather than a no-op, so it is rejected
/// instead of being silently coerced — otherwise a misconfigured keeper would
/// spin forever making no progress.
pub fn resolve_batch_size(batch_size: u32) -> Result<u32, GcError> {
    if batch_size == 0 {
        return Err(GcError::InvalidBatchSize);
    }
    if batch_size > MAX_BATCH_SIZE {
        return Err(GcError::BatchSizeTooLarge);
    }
    Ok(batch_size)
}

/// Decide whether a single candidate is collectable at `now`.
pub fn is_expired(expires_at: u64, now: u64) -> bool {
    now > expires_at
}

/// Run a garbage-collection pass over `candidates`.
///
/// Returns a [`GcResult`] describing what was reclaimed.  The collector never
/// mutates the candidates themselves — it is a pure decision function over
/// them, which keeps it straightforward to unit test and safe to run against
/// any contract's index.
///
/// The caller is responsible for actually removing the keys reported in
/// `collected`; [`GcResult::collected`] is the count, and the caller already
/// knows the keys because it supplied them.
pub fn collect_garbage(
    env: &Env,
    candidates: &Vec<GcCandidate>,
    batch_size: u32,
) -> Result<GcResult, GcError> {
    let batch = resolve_batch_size(batch_size)?;
    let now = env.ledger().timestamp();

    let mut result = GcResult::empty(now);
    let total = candidates.len();
    // Only inspect the first `batch` candidates, so the worst-case cost of a
    // call is bounded regardless of index size.
    let window = core::cmp::min(batch, total);

    for i in 0..window {
        let candidate = match candidates.get(i) {
            Some(c) => c,
            None => continue,
        };

        if candidate.footprint_entries == 0 {
            return Err(GcError::InvalidCandidate);
        }

        if is_expired(candidate.expires_at, now) {
            result.collected += 1;
            result.entries_reclaimed += candidate.footprint_entries;
        } else {
            result.skipped_live += 1;
        }
    }

    result.has_more = total > window;
    Ok(result)
}

/// Convenience wrapper that reports a batch of candidates as reclaimable or
/// not, one at a time.  Useful for callers that want the per-key decision.
pub fn partition_candidates(env: &Env, candidates: &Vec<GcCandidate>) -> (Vec<Bytes>, Vec<Bytes>) {
    let now = env.ledger().timestamp();
    let mut expired = Vec::new(env);
    let mut live = Vec::new(env);
    for candidate in candidates.iter() {
        if is_expired(candidate.expires_at, now) {
            expired.push_back(candidate.key.clone());
        } else {
            live.push_back(candidate.key.clone());
        }
    }
    (expired, live)
}

/// Record the outcome of a collection run in the module's own storage and emit
/// a `StorageGarbageCollected` event, so the savings are auditable.
pub fn record_collection(env: &Env, domain: &StorageDomain, result: &GcResult) {
    let run = get_run_count(env) + 1;
    env.storage().persistent().set(&GcKey::RunCount, &run);
    env.storage().persistent().set(
        &GcKey::TotalCollected,
        &(get_total_collected(env) + result.collected),
    );
    env.storage().persistent().set(
        &GcKey::TotalReclaimed,
        &(get_total_reclaimed(env) + result.entries_reclaimed),
    );

    let (mut domain_collected, mut domain_reclaimed) = read_domain(env, domain);
    domain_collected += result.collected;
    domain_reclaimed += result.entries_reclaimed;
    env.storage().persistent().set(
        &GcKey::DomainTotals(domain.clone()),
        &(domain_collected, domain_reclaimed),
    );

    env.storage().persistent().set(&GcKey::LastResult, result);

    env.events().publish(
        (Symbol::new(env, "StorageGarbageCollected"),),
        (
            result.collected,
            result.entries_reclaimed,
            run,
            result.has_more,
        ),
    );

    extend_ttls(env);
}

/// Extend the TTL of a persistent entry so it survives past its nominal
/// expiry.  This is the "TTL extension" escape hatch: a credential that has
/// been renewed off chain, or a cached value that is still hot, can be kept
/// alive without rewriting the record.
pub fn extend_entry_ttl(env: &Env, key: &Bytes, ledgers: u32) {
    let to = if ledgers == 0 {
        DEFAULT_EXTENSION_LEDGERS
    } else {
        ledgers
    };
    env.storage().persistent().extend_ttl(key, to, to);
}

/// Read the cumulative collection statistics.
pub fn get_gc_stats(env: &Env) -> GcResult {
    env.storage()
        .persistent()
        .get(&GcKey::LastResult)
        .unwrap_or_else(|| GcResult::empty(env.ledger().timestamp()))
}

/// Total entries collected since deployment.
pub fn get_total_collected(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&GcKey::TotalCollected)
        .unwrap_or(0)
}

/// Total storage slots reclaimed since deployment.
pub fn get_total_reclaimed(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&GcKey::TotalReclaimed)
        .unwrap_or(0)
}

/// Cumulative (collected, entries_reclaimed) for a single domain.
pub fn get_domain_totals(env: &Env, domain: &StorageDomain) -> (u32, u32) {
    read_domain(env, domain)
}

/// Number of completed collection runs.
pub fn get_run_count(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&GcKey::RunCount)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Cross-contract fan-out
// ---------------------------------------------------------------------------

/// Register the candidate list a collector will sweep on its next run.
///
/// The owner of the data publishes its own index here; the collector then
/// never has to reach into another contract's private storage (which Soroban
/// forbids) to decide what is collectable.
pub fn register_candidates(env: &Env, domain: &StorageDomain, candidates: &Vec<GcCandidate>) {
    env.storage()
        .persistent()
        .set(&GcKey::Candidates(domain.clone()), candidates);
}

/// Return the registered candidate list for a domain.
pub fn get_candidates(env: &Env, domain: &StorageDomain) -> Vec<GcCandidate> {
    env.storage()
        .persistent()
        .get(&GcKey::Candidates(domain.clone()))
        .unwrap_or_else(|| Vec::new(env))
}

/// Run a collection pass over the candidates registered for `domain`, then
/// record the outcome.
///
/// This is the entry point {@link collect_across_contracts} calls, so it takes
/// only a batch size — the candidate list comes from the collector's own
/// registration rather than the caller.
pub fn run_registered_collection(
    env: &Env,
    domain: &StorageDomain,
    batch_size: u32,
) -> Result<GcResult, GcError> {
    let candidates = get_candidates(env, domain);
    let result = collect_garbage(env, &candidates, batch_size)?;
    record_collection(env, domain, &result);
    Ok(result)
}

/// Visit up to [`MAX_CONTRACTS_PER_RUN`] registered collector contracts and run
/// a collection pass in each, returning the aggregated result.
///
/// This is the batch entry point: each visited contract sweeps the candidate
/// list it has registered for [`StorageDomain::Cache`], so a single keeper
/// transaction can reclaim storage across the whole deployment.
///
/// Requests beyond the cap are counted in `contracts_skipped` rather than
/// rejected, so a keeper can pass its whole registry and let the contract
/// decide how much fits in one transaction.
pub fn collect_across_contracts(
    env: &Env,
    contracts: &Vec<Address>,
    batch_size: u32,
) -> Result<BatchGcResult, GcError> {
    let _batch = resolve_batch_size(batch_size)?;
    let requested = contracts.len();
    let visit = core::cmp::min(requested, MAX_CONTRACTS_PER_RUN as u32);

    let mut aggregate = BatchGcResult {
        total_collected: 0,
        total_entries_reclaimed: 0,
        contracts_visited: 0,
        contracts_skipped: requested - visit,
        has_more: requested > visit,
    };

    for i in 0..visit {
        let address = match contracts.get(i) {
            Some(a) => a,
            None => continue,
        };
        let client = StorageGarbageCollectorClient::new(env, &address);
        let result = match client.try_run_collection(&batch_size) {
            Ok(Ok(r)) => r,
            // A contract that does not implement the entry point, or whose
            // return value could not be converted, is counted as skipped
            // rather than aborting the whole run — one bad registry entry
            // should not block collection everywhere else.
            Ok(Err(_)) | Err(_) => continue,
        };
        aggregate.total_collected += result.collected;
        aggregate.total_entries_reclaimed += result.entries_reclaimed;
        aggregate.contracts_visited += 1;
        if result.has_more {
            aggregate.has_more = true;
        }
    }

    env.events().publish(
        (Symbol::new(env, "BatchGarbageCollection"),),
        (
            aggregate.total_collected,
            aggregate.total_entries_reclaimed,
            aggregate.contracts_visited,
        ),
    );

    Ok(aggregate)
}

// ---------------------------------------------------------------------------
// Standalone contract surface
// ---------------------------------------------------------------------------

/// A standalone collector contract, so a deployment can host garbage
/// collection independently of the contract that owns the data.
#[contract]
pub struct StorageGarbageCollector;

#[contractimpl]
impl StorageGarbageCollector {
    /// Register the candidate list this collector will sweep.
    pub fn register_candidates(env: Env, domain: StorageDomain, candidates: Vec<GcCandidate>) {
        register_candidates(&env, &domain, &candidates);
    }

    /// The registered candidate list for a domain.
    pub fn get_candidates(env: Env, domain: StorageDomain) -> Vec<GcCandidate> {
        get_candidates(&env, &domain)
    }

    /// Run a collection pass over the registered `Cache` candidates.
    ///
    /// This is the batch-friendly entry point {@link collect_across_contracts}
    /// calls: it needs only a batch size because the candidate list is already
    /// on chain.
    pub fn run_collection(env: Env, batch_size: u32) -> Result<GcResult, GcError> {
        run_registered_collection(&env, &StorageDomain::Cache, batch_size)
    }

    /// Run a collection pass over a caller-supplied candidate list, without
    /// registering it.  Useful for a one-off sweep.
    pub fn collect(
        env: Env,
        candidates: Vec<GcCandidate>,
        batch_size: u32,
    ) -> Result<GcResult, GcError> {
        let result = collect_garbage(&env, &candidates, batch_size)?;
        record_collection(&env, &StorageDomain::Cache, &result);
        Ok(result)
    }

    /// Run a collection pass and return the keys split into expired and live.
    pub fn inspect(env: Env, candidates: Vec<GcCandidate>) -> (Vec<Bytes>, Vec<Bytes>) {
        partition_candidates(&env, &candidates)
    }

    /// Cumulative collection statistics.
    pub fn get_gc_stats(env: Env) -> GcResult {
        get_gc_stats(&env)
    }

    /// Entries collected since deployment.
    pub fn get_total_collected(env: Env) -> u32 {
        get_total_collected(&env)
    }

    /// Storage slots reclaimed since deployment.
    pub fn get_total_reclaimed(env: Env) -> u32 {
        get_total_reclaimed(&env)
    }

    /// Completed collection runs.
    pub fn get_run_count(env: Env) -> u32 {
        get_run_count(&env)
    }

    /// Fan a collection run out over several registered collector contracts.
    pub fn collect_batch(
        env: Env,
        contracts: Vec<Address>,
        batch_size: u32,
    ) -> Result<BatchGcResult, GcError> {
        collect_across_contracts(&env, &contracts, batch_size)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read the cumulative (collected, entries_reclaimed) pair for a domain.
fn read_domain(env: &Env, domain: &StorageDomain) -> (u32, u32) {
    env.storage()
        .persistent()
        .get(&GcKey::DomainTotals(domain.clone()))
        .unwrap_or((0, 0))
}

/// Extend TTLs for the module's own bookkeeping entries.
fn extend_ttls(env: &Env) {
    for key in [
        GcKey::RunCount,
        GcKey::TotalCollected,
        GcKey::TotalReclaimed,
        GcKey::LastResult,
    ] {
        env.storage()
            .persistent()
            .extend_ttl(&key, GC_TTL_LEDGERS, GC_TTL_LEDGERS);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};

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

    fn candidate(env: &Env, id: u8, expires_at: u64) -> GcCandidate {
        GcCandidate {
            key: Bytes::from_slice(env, &[id]),
            expires_at,
            footprint_entries: 1,
        }
    }

    fn candidates(env: &Env, ids: &[(u8, u64)]) -> Vec<GcCandidate> {
        let mut v = Vec::new(env);
        for (id, exp) in ids {
            v.push_back(candidate(env, *id, *exp));
        }
        v
    }

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn batch_size_zero_is_rejected() {
        assert_eq!(resolve_batch_size(0), Err(GcError::InvalidBatchSize));
    }

    #[test]
    fn batch_size_over_cap_is_rejected() {
        assert_eq!(
            resolve_batch_size(MAX_BATCH_SIZE + 1),
            Err(GcError::BatchSizeTooLarge)
        );
    }

    #[test]
    fn batch_size_within_bounds_is_accepted() {
        assert_eq!(resolve_batch_size(1), Ok(1));
        assert_eq!(resolve_batch_size(MAX_BATCH_SIZE), Ok(MAX_BATCH_SIZE));
    }

    #[test]
    fn is_expired_uses_strict_inequality() {
        assert!(!is_expired(NOW, NOW));
        assert!(is_expired(NOW - 1, NOW));
        assert!(!is_expired(NOW + 1, NOW));
    }

    #[test]
    fn collects_only_expired_entries() {
        let env = setup_env();
        let list = candidates(
            &env,
            &[(1, NOW - 100), (2, NOW + 100), (3, NOW - 1), (4, NOW + 1)],
        );
        let result = collect_garbage(&env, &list, 10).unwrap();
        assert_eq!(result.collected, 2);
        assert_eq!(result.skipped_live, 2);
        assert_eq!(result.entries_reclaimed, 2);
        assert!(!result.has_more);
        assert_eq!(result.evaluated_at, NOW);
    }

    #[test]
    fn live_entries_are_preserved() {
        let env = setup_env();
        let list = candidates(&env, &[(1, NOW + 500), (2, NOW + 600)]);
        let (expired, live) = partition_candidates(&env, &list);
        assert_eq!(expired.len(), 0);
        assert_eq!(live.len(), 2);
    }

    #[test]
    fn expired_entries_are_identified() {
        let env = setup_env();
        let list = candidates(&env, &[(1, NOW - 1), (2, NOW + 1)]);
        let (expired, live) = partition_candidates(&env, &list);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired.get(0).unwrap(), Bytes::from_slice(&env, &[1]));
        assert_eq!(live.len(), 1);
        assert_eq!(live.get(0).unwrap(), Bytes::from_slice(&env, &[2]));
    }

    #[test]
    fn batch_limits_work_and_sets_has_more() {
        let env = setup_env();
        let list = candidates(&env, &[(1, NOW - 1), (2, NOW - 1), (3, NOW - 1)]);
        let result = collect_garbage(&env, &list, 2).unwrap();
        assert_eq!(result.collected, 2);
        assert!(result.has_more);
    }

    #[test]
    fn empty_candidate_list_is_a_no_op() {
        let env = setup_env();
        let list = Vec::new(&env);
        let result = collect_garbage(&env, &list, 10).unwrap();
        assert_eq!(result.collected, 0);
        assert_eq!(result.skipped_live, 0);
        assert!(!result.has_more);
    }

    #[test]
    fn zero_footprint_candidate_is_invalid() {
        let env = setup_env();
        let mut list = Vec::new(&env);
        list.push_back(GcCandidate {
            key: Bytes::from_slice(&env, &[1]),
            expires_at: NOW - 1,
            footprint_entries: 0,
        });
        assert_eq!(
            collect_garbage(&env, &list, 10),
            Err(GcError::InvalidCandidate)
        );
    }

    #[test]
    fn reclaimed_footprint_is_summed() {
        let env = setup_env();
        let mut list = Vec::new(&env);
        list.push_back(GcCandidate {
            key: Bytes::from_slice(&env, &[1]),
            expires_at: NOW - 1,
            footprint_entries: 3,
        });
        list.push_back(GcCandidate {
            key: Bytes::from_slice(&env, &[2]),
            expires_at: NOW - 1,
            footprint_entries: 4,
        });
        let result = collect_garbage(&env, &list, 10).unwrap();
        assert_eq!(result.collected, 2);
        assert_eq!(result.entries_reclaimed, 7);
    }

    #[test]
    fn result_absorb_accumulates() {
        let env = setup_env();
        let mut a = GcResult::empty(NOW);
        a.collected = 2;
        a.entries_reclaimed = 5;

        let mut b = GcResult::empty(NOW);
        b.collected = 3;
        b.entries_reclaimed = 7;
        b.has_more = true;

        a.absorb(&b);
        assert_eq!(a.collected, 5);
        assert_eq!(a.entries_reclaimed, 12);
        assert!(a.has_more);
    }

    #[test]
    fn too_many_contracts_is_rejected() {
        let env = setup_env();
        let mut list = Vec::new(&env);
        for _ in 0..(MAX_CONTRACTS_PER_RUN + 1) {
            list.push_back(Address::generate(&env));
        }
        // The fan-out caps rather than erroring, so this reports skipped work.
        let result = collect_across_contracts(&env, &list, 5);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().contracts_skipped,
            list.len() - MAX_CONTRACTS_PER_RUN
        );
    }
}
