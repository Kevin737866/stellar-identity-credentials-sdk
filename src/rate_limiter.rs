/// Rate limiting for critical contract functions.
///
/// Uses a sliding-window approach stored in Soroban temporary storage.
/// Each caller gets a per-function bucket tracking (count, window_start).
/// If `count` exceeds the configured limit within the window, the call is rejected.
///
/// # Design
/// - Window duration and max requests are configurable per call site.
/// - Limits are **admin configurable at runtime**: a limit is stored in
///   instance storage keyed by operation symbol and overrides the compiled-in
///   default from [`defaults`]. Setting a limit to `enabled = false` disables
///   throttling for that operation entirely.
/// - Trusted issuers can be exempted per address via [`exempt_address`], so
///   an audited, high-volume issuer is never throttled.
/// - State is stored in **temporary** storage (auto-expires) to avoid bloating
///   persistent storage with rate-limit bookkeeping.
/// - Rejections emit `RateLimitRejected` carrying the reset time so callers
///   receive a clear, actionable error instead of a bare `limit exceeded`.
use soroban_sdk::{contracterror, contracttype, Address, Env, Symbol, Vec};

use crate::admin;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum RateLimitError {
    /// Caller has exceeded the allowed request rate.
    RateLimitExceeded = 1,
    /// Caller tried to change rate-limit configuration without being admin.
    NotAdmin = 2,
}

// ---------------------------------------------------------------------------
// Storage key
// ---------------------------------------------------------------------------

/// Namespaced key for per-caller rate-limit buckets.
#[contracttype]
#[derive(Clone)]
pub struct RateLimitKey {
    pub caller: Address,
    pub function: Symbol,
}

/// Sliding-window bucket stored per `(caller, function)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitBucket {
    /// Number of calls within the current window.
    pub count: u32,
    /// Ledger timestamp at which the current window started.
    pub window_start: u64,
}

/// Instance-storage keys for admin-managed configuration.
#[contracttype]
#[derive(Clone)]
enum ConfigKey {
    /// Admin-managed limit override for an operation.
    Limit(Symbol),
    /// List of addresses exempt from throttling.
    Exempt,
}

// ---------------------------------------------------------------------------
// Admin-configurable limits stored in instance storage
// ---------------------------------------------------------------------------

/// Admin-configurable rate-limit parameters for a given operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Window duration in seconds.
    pub window_secs: u64,
    /// Maximum calls allowed per window. `0` means "block all".
    pub max_calls: u32,
    /// When `false` the operation is not throttled at all.
    pub enabled: bool,
}

impl RateLimitConfig {
    /// Build an enabled configuration.
    pub fn new(window_secs: u64, max_calls: u32) -> Self {
        Self {
            window_secs,
            max_calls,
            enabled: true,
        }
    }

    /// Build a disabled configuration (throttling off).
    pub fn disabled() -> Self {
        Self {
            window_secs: 0,
            max_calls: 0,
            enabled: false,
        }
    }
}

/// Snapshot of a caller's current bucket, returned to callers so a rejection
/// carries enough context to schedule a retry without a second round-trip.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitStatus {
    /// Operation the status refers to.
    pub operation: Symbol,
    /// Calls consumed in the current window.
    pub count: u32,
    /// Configured ceiling for the window.
    pub limit: u32,
    /// Whether throttling is active for this operation.
    pub enabled: bool,
    /// Calls still available in this window.
    pub remaining: u32,
    /// Timestamp at which the current window rolls over.
    pub reset_at: u64,
    /// Seconds the caller must wait before the next attempt is accepted.
    pub retry_after_secs: u64,
    /// Whether the caller is exempt from throttling.
    pub exempt: bool,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Default limits for each guarded function.
///
/// These are the fallbacks used when an admin has not installed an override.
pub mod defaults {
    /// DID creation: 5 per 300 seconds per caller.
    pub const CREATE_DID_MAX: u32 = 5;
    pub const CREATE_DID_WINDOW: u64 = 300;

    /// Credential issuance: 10 per 60 seconds per issuer.
    pub const ISSUE_CREDENTIAL_MAX: u32 = 10;
    pub const ISSUE_CREDENTIAL_WINDOW: u64 = 60;

    /// Single credential verification: 60 per 60 seconds per caller.
    pub const VERIFY_CREDENTIAL_MAX: u32 = 60;
    pub const VERIFY_CREDENTIAL_WINDOW: u64 = 60;

    /// Batch verification: 10 batch calls per 60 seconds per caller.
    pub const BATCH_VERIFY_MAX: u32 = 10;
    pub const BATCH_VERIFY_WINDOW: u64 = 60;

    /// Batch issuance: 5 batch calls per 300 seconds per issuer.
    pub const BATCH_ISSUE_MAX: u32 = 5;
    pub const BATCH_ISSUE_WINDOW: u64 = 300;

    /// Reputation score update: 20 per 60 seconds per caller.
    pub const UPDATE_REPUTATION_MAX: u32 = 20;
    pub const UPDATE_REPUTATION_WINDOW: u64 = 60;

    /// Compliance screening: 120 per 60 seconds per caller.
    pub const SCREEN_ADDRESS_MAX: u32 = 120;
    pub const SCREEN_ADDRESS_WINDOW: u64 = 60;
}

/// Hard upper bound on `max_calls` so a mis-configured admin value cannot
/// brick a contract by making the limit effectively unreachable.
pub const MAX_CALLS_CEILING: u32 = 1_000_000;

/// Hard upper bound on `window_secs`.
pub const MAX_WINDOW_CEILING: u64 = 86_400;

// ---------------------------------------------------------------------------
// Admin configuration
// ---------------------------------------------------------------------------

/// Set (or clear) the runtime limit for an operation. Admin only.
///
/// `max_calls` is clamped to [`MAX_CALLS_CEILING`] and `window_secs` to
/// [`MAX_WINDOW_CEILING`]. A `window_secs` of `0` is rejected because it would
/// make every call land in a fresh window (i.e. disable throttling silently);
/// use `RateLimitConfig::disabled()` for that intent instead.
pub fn set_limit(
    env: &Env,
    admin: &Address,
    operation: Symbol,
    config: RateLimitConfig,
) -> Result<(), RateLimitError> {
    admin::only_admin(env, admin).map_err(|_| RateLimitError::NotAdmin)?;

    let mut normalized = config;
    if normalized.max_calls > MAX_CALLS_CEILING {
        normalized.max_calls = MAX_CALLS_CEILING;
    }
    if normalized.window_secs > MAX_WINDOW_CEILING {
        normalized.window_secs = MAX_WINDOW_CEILING;
    }
    if normalized.enabled && normalized.window_secs == 0 {
        normalized.window_secs = 1;
    }

    env.storage()
        .instance()
        .set(&ConfigKey::Limit(operation), &normalized);
    Ok(())
}

/// Effective limit for an operation: the admin override when present,
/// otherwise `fallback`.
pub fn get_limit(env: &Env, operation: &Symbol, fallback: RateLimitConfig) -> RateLimitConfig {
    env.storage()
        .instance()
        .get(&ConfigKey::Limit(operation.clone()))
        .unwrap_or(fallback)
}

/// Remove an admin override so the compiled-in default applies again.
pub fn clear_limit(env: &Env, admin: &Address, operation: Symbol) -> Result<(), RateLimitError> {
    admin::only_admin(env, admin).map_err(|_| RateLimitError::NotAdmin)?;
    env.storage()
        .instance()
        .remove(&ConfigKey::Limit(operation));
    Ok(())
}

// ---------------------------------------------------------------------------
// Trusted-party exemptions
// ---------------------------------------------------------------------------

/// Add `address` to the exemption list. Admin only.
///
/// Exempt addresses bypass throttling entirely, which lets an audited issuer
/// or an operational oracle service run at full throughput.
pub fn exempt_address(env: &Env, admin: &Address, address: Address) -> Result<(), RateLimitError> {
    admin::only_admin(env, admin).map_err(|_| RateLimitError::NotAdmin)?;

    let mut list: Vec<Address> = exempt_list(env);
    if !list.iter().any(|a| a == address) {
        list.push_back(address);
        env.storage().instance().set(&ConfigKey::Exempt, &list);
    }
    Ok(())
}

/// Remove `address` from the exemption list. Admin only.
pub fn unexempt_address(
    env: &Env,
    admin: &Address,
    address: Address,
) -> Result<(), RateLimitError> {
    admin::only_admin(env, admin).map_err(|_| RateLimitError::NotAdmin)?;

    let current = exempt_list(env);
    let mut next: Vec<Address> = Vec::new(env);
    for a in current.iter() {
        if a != address {
            next.push_back(a);
        }
    }
    env.storage().instance().set(&ConfigKey::Exempt, &next);
    Ok(())
}

/// Whether `address` is exempt from throttling.
pub fn is_exempt(env: &Env, address: &Address) -> bool {
    exempt_list(env).iter().any(|a| a == *address)
}

/// All currently exempt addresses.
pub fn exempt_list(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&ConfigKey::Exempt)
        .unwrap_or_else(|| Vec::new(env))
}

// ---------------------------------------------------------------------------
// Core check-and-increment logic
// ---------------------------------------------------------------------------

/// Check and increment rate-limit counter for `(caller, function)`.
///
/// Uses per-caller temporary storage so limits apply per address.
/// Returns `Err(RateLimitError::RateLimitExceeded)` if the limit is breached.
/// Emits a `RateLimitHit` event when a caller is rejected.
///
/// # Arguments
/// * `env`          â€“ Soroban environment.
/// * `caller`       â€“ Address performing the call.
/// * `function`     â€“ Short symbol identifying the function (e.g. `"create_did"`).
/// * `max_calls`    â€“ Max allowed calls per window.
/// * `window_secs`  â€“ Window duration in seconds.
pub fn check_rate_limit(
    env: &Env,
    caller: &Address,
    function: Symbol,
    max_calls: u32,
    window_secs: u64,
) -> Result<(), RateLimitError> {
    let key = RateLimitKey {
        caller: caller.clone(),
        function: function.clone(),
    };

    let now = env.ledger().timestamp();

    let mut bucket: RateLimitBucket =
        env.storage()
            .temporary()
            .get(&key)
            .unwrap_or(RateLimitBucket {
                count: 0,
                window_start: now,
            });

    // Reset window if expired
    if now.saturating_sub(bucket.window_start) >= window_secs {
        bucket.count = 0;
        bucket.window_start = now;
    }

    if bucket.count >= max_calls {
        // Emit event so off-chain monitoring can detect abuse
        env.events().publish(
            (Symbol::new(env, "RateLimitHit"),),
            (caller.clone(), function),
        );
        return Err(RateLimitError::RateLimitExceeded);
    }

    bucket.count += 1;
    // TTL: keep bucket alive for the window duration (in ledgers, ~5s each)
    let ttl_ledgers = ((window_secs / 5) + 1) as u32;
    env.storage().temporary().set(&key, &bucket);
    env.storage()
        .temporary()
        .extend_ttl(&key, ttl_ledgers, ttl_ledgers);

    Ok(())
}

// ---------------------------------------------------------------------------
// Config-aware entry point
// ---------------------------------------------------------------------------

/// Check and increment a bucket using the admin-configured limit for
/// `operation`, falling back to `fallback` when no override is installed.
///
/// Exempt addresses and disabled operations short-circuit to `Ok(())` without
/// touching storage, so a trusted issuer pays no throttling overhead.
pub fn check_operation(
    env: &Env,
    caller: &Address,
    operation: &Symbol,
    fallback: RateLimitConfig,
) -> Result<RateLimitStatus, RateLimitError> {
    let config = get_limit(env, operation, fallback);

    if !config.enabled || is_exempt(env, caller) {
        return Ok(RateLimitStatus {
            operation: operation.clone(),
            count: 0,
            limit: config.max_calls,
            enabled: config.enabled,
            remaining: config.max_calls,
            reset_at: env.ledger().timestamp(),
            retry_after_secs: 0,
            exempt: is_exempt(env, caller),
        });
    }

    let key = RateLimitKey {
        caller: caller.clone(),
        function: operation.clone(),
    };
    let now = env.ledger().timestamp();

    let mut bucket: RateLimitBucket =
        env.storage()
            .temporary()
            .get(&key)
            .unwrap_or(RateLimitBucket {
                count: 0,
                window_start: now,
            });

    if now.saturating_sub(bucket.window_start) >= config.window_secs {
        bucket.count = 0;
        bucket.window_start = now;
    }

    let reset_at = bucket.window_start.saturating_add(config.window_secs);

    if bucket.count >= config.max_calls {
        let status = RateLimitStatus {
            operation: operation.clone(),
            count: bucket.count,
            limit: config.max_calls,
            enabled: true,
            remaining: 0,
            reset_at,
            retry_after_secs: reset_at.saturating_sub(now),
            exempt: false,
        };
        env.events().publish(
            (Symbol::new(env, "RateLimitRejected"),),
            (caller.clone(), operation.clone(), status.retry_after_secs),
        );
        return Err(RateLimitError::RateLimitExceeded);
    }

    bucket.count += 1;
    let ttl_ledgers = ((config.window_secs / 5) + 1) as u32;
    env.storage().temporary().set(&key, &bucket);
    env.storage()
        .temporary()
        .extend_ttl(&key, ttl_ledgers, ttl_ledgers);

    Ok(RateLimitStatus {
        operation: operation.clone(),
        count: bucket.count,
        limit: config.max_calls,
        enabled: true,
        remaining: config.max_calls.saturating_sub(bucket.count),
        reset_at,
        retry_after_secs: 0,
        exempt: false,
    })
}

/// Read the current bucket for `(caller, operation)` without incrementing it.
///
/// Lets a client check its remaining quota before submitting a transaction.
pub fn status(env: &Env, caller: &Address, operation: &Symbol) -> RateLimitStatus {
    let key = RateLimitKey {
        caller: caller.clone(),
        function: operation.clone(),
    };
    let now = env.ledger().timestamp();
    let bucket: RateLimitBucket = env
        .storage()
        .temporary()
        .get(&key)
        .unwrap_or(RateLimitBucket {
            count: 0,
            window_start: now,
        });
    let limit: RateLimitConfig = env
        .storage()
        .instance()
        .get(&ConfigKey::Limit(operation.clone()))
        .unwrap_or(RateLimitConfig::new(0, 0));
    let reset_at = bucket.window_start.saturating_add(limit.window_secs);

    RateLimitStatus {
        operation: operation.clone(),
        count: bucket.count,
        limit: limit.max_calls,
        enabled: limit.enabled,
        remaining: limit.max_calls.saturating_sub(bucket.count),
        reset_at,
        retry_after_secs: if bucket.count >= limit.max_calls {
            reset_at.saturating_sub(now)
        } else {
            0
        },
        exempt: is_exempt(env, caller),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Address as _, Events, Ledger, LedgerInfo},
        TryFromVal,
    };

    /// Minimal host contract. The admin/limit/exemption configuration lives in
    /// instance storage, which is only reachable from inside a contract frame,
    /// so tests register this and run their body with [`Env::as_contract`].
    #[contract]
    pub struct RateLimitHost;

    #[contractimpl]
    impl RateLimitHost {
        pub fn noop() {}
    }

    struct Harness {
        env: Env,
        host: Address,
    }

    impl Harness {
        fn new() -> Self {
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
            let host = env.register(RateLimitHost, ());
            Harness { env, host }
        }

        /// Register `admin` as the contract admin. Returns the admin address.
        fn with_admin(&self) -> Address {
            let admin = Address::generate(&self.env);
            self.run(|| admin::init(&self.env, admin.clone()).unwrap());
            admin
        }

        /// Run `body` inside the host contract's frame.
        fn run<R>(&self, body: impl FnOnce() -> R) -> R {
            self.env.as_contract(&self.host, body)
        }

        /// Advance ledger time without leaving the contract frame.
        fn advance(&self, secs: u64) {
            let mut info = self.env.ledger().get();
            info.timestamp += secs;
            self.env.ledger().set(info);
        }
    }

    fn has_topic(env: &Env, name: &str) -> bool {
        let symbol = Symbol::new(env, name);
        env.events().all().iter().any(|(_c, topics, _d)| {
            topics.iter().any(|t| {
                Symbol::try_from_val(env, &t)
                    .map(|s| s == symbol)
                    .unwrap_or(false)
            })
        })
    }

    fn op(env: &Env, name: &str) -> Symbol {
        Symbol::new(env, name)
    }

    // ── Original sliding-window behaviour ───────────────────────────────

    #[test]
    fn test_rate_limit_allows_within_limit() {
        let h = Harness::new();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let func = op(&h.env, "create_did");
            for _ in 0..3 {
                assert!(check_rate_limit(&h.env, &caller, func.clone(), 3, 60).is_ok());
            }
        });
    }

    #[test]
    fn test_rate_limit_blocks_over_limit() {
        let h = Harness::new();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let func = op(&h.env, "create_did");
            for _ in 0..3 {
                check_rate_limit(&h.env, &caller, func.clone(), 3, 60).unwrap();
            }
            assert_eq!(
                check_rate_limit(&h.env, &caller, func, 3, 60).unwrap_err(),
                RateLimitError::RateLimitExceeded
            );
        });
    }

    #[test]
    fn test_rate_limit_resets_after_window() {
        let h = Harness::new();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let func = op(&h.env, "create_did");
            for _ in 0..3 {
                check_rate_limit(&h.env, &caller, func.clone(), 3, 60).unwrap();
            }
            h.advance(61);
            assert!(check_rate_limit(&h.env, &caller, func, 3, 60).is_ok());
        });
    }

    #[test]
    fn test_rate_limit_independent_per_caller() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            let func = op(&h.env, "create_did");
            for _ in 0..3 {
                check_rate_limit(&h.env, &a, func.clone(), 3, 60).unwrap();
            }
            assert!(check_rate_limit(&h.env, &a, func.clone(), 3, 60).is_err());
            assert!(check_rate_limit(&h.env, &b, func, 3, 60).is_ok());
        });
    }

    // ── Admin-configurable limits (#201) ─────────────────────────────────

    #[test]
    fn get_limit_falls_back_to_default_when_unset() {
        let h = Harness::new();
        h.run(|| {
            let fallback = RateLimitConfig::new(60, 10);
            assert_eq!(
                get_limit(&h.env, &op(&h.env, "issue_cred"), fallback.clone()),
                fallback
            );
        });
    }

    #[test]
    fn set_limit_overrides_default() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let operation = op(&h.env, "issue_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::new(120, 3),
            )
            .unwrap();

            let cfg = get_limit(&h.env, &operation, RateLimitConfig::new(60, 10));
            assert_eq!(cfg.max_calls, 3);
            assert_eq!(cfg.window_secs, 120);
        });
    }

    #[test]
    fn set_limit_requires_admin() {
        let h = Harness::new();
        h.with_admin();
        h.run(|| {
            let intruder = Address::generate(&h.env);
            assert_eq!(
                set_limit(
                    &h.env,
                    &intruder,
                    op(&h.env, "issue_cred"),
                    RateLimitConfig::new(60, 1)
                )
                .unwrap_err(),
                RateLimitError::NotAdmin
            );
        });
    }

    #[test]
    fn set_limit_requires_initialised_admin() {
        let h = Harness::new();
        h.run(|| {
            let someone = Address::generate(&h.env);
            assert_eq!(
                set_limit(
                    &h.env,
                    &someone,
                    op(&h.env, "issue_cred"),
                    RateLimitConfig::new(60, 1)
                )
                .unwrap_err(),
                RateLimitError::NotAdmin
            );
        });
    }

    #[test]
    fn set_limit_clamps_out_of_range_values() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let operation = op(&h.env, "issue_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::new(999_999_999, 99_999_999),
            )
            .unwrap();

            let cfg = get_limit(&h.env, &operation, RateLimitConfig::new(60, 10));
            assert_eq!(cfg.max_calls, MAX_CALLS_CEILING);
            assert_eq!(cfg.window_secs, MAX_WINDOW_CEILING);
        });
    }

    #[test]
    fn set_limit_never_leaves_enabled_window_at_zero() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let operation = op(&h.env, "issue_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig {
                    window_secs: 0,
                    max_calls: 5,
                    enabled: true,
                },
            )
            .unwrap();

            let cfg = get_limit(&h.env, &operation, RateLimitConfig::new(60, 10));
            assert_eq!(cfg.window_secs, 1);
        });
    }

    #[test]
    fn clear_limit_restores_default() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let operation = op(&h.env, "issue_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::new(120, 3),
            )
            .unwrap();
            clear_limit(&h.env, &admin, operation.clone()).unwrap();

            let fallback = RateLimitConfig::new(60, 10);
            assert_eq!(get_limit(&h.env, &operation, fallback.clone()), fallback);
        });
    }

    #[test]
    fn admin_configured_limit_is_enforced() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let operation = op(&h.env, "verify_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::new(60, 2),
            )
            .unwrap();

            let fallback = RateLimitConfig::new(60, 100);
            assert!(check_operation(&h.env, &caller, &operation, fallback.clone()).is_ok());
            assert!(check_operation(&h.env, &caller, &operation, fallback.clone()).is_ok());
            assert_eq!(
                check_operation(&h.env, &caller, &operation, fallback).unwrap_err(),
                RateLimitError::RateLimitExceeded
            );
        });
    }

    #[test]
    fn disabled_limit_never_throttles() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let operation = op(&h.env, "verify_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::disabled(),
            )
            .unwrap();

            for _ in 0..25 {
                let status =
                    check_operation(&h.env, &caller, &operation, RateLimitConfig::new(60, 1))
                        .expect("disabled limits must not reject");
                assert!(!status.enabled);
            }
        });
    }

    // ── Trusted-party exemptions (#201) ─────────────────────────────────

    #[test]
    fn exempt_address_bypasses_throttling() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let trusted = Address::generate(&h.env);
            exempt_address(&h.env, &admin, trusted.clone()).unwrap();
            assert!(is_exempt(&h.env, &trusted));

            let operation = op(&h.env, "issue_cred");
            let fallback = RateLimitConfig::new(60, 1);
            for _ in 0..10 {
                let status =
                    check_operation(&h.env, &trusted, &operation, fallback.clone()).unwrap();
                assert!(status.exempt);
            }
        });
    }

    #[test]
    fn exemption_does_not_affect_other_addresses() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let trusted = Address::generate(&h.env);
            let other = Address::generate(&h.env);
            exempt_address(&h.env, &admin, trusted).unwrap();

            let operation = op(&h.env, "issue_cred");
            let fallback = RateLimitConfig::new(60, 1);
            check_operation(&h.env, &other, &operation, fallback.clone()).unwrap();
            assert!(check_operation(&h.env, &other, &operation, fallback).is_err());
        });
    }

    #[test]
    fn exempting_twice_is_idempotent() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let trusted = Address::generate(&h.env);
            exempt_address(&h.env, &admin, trusted.clone()).unwrap();
            exempt_address(&h.env, &admin, trusted.clone()).unwrap();
            assert_eq!(exempt_list(&h.env).len(), 1);
        });
    }

    #[test]
    fn unexempt_restores_throttling() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let trusted = Address::generate(&h.env);
            exempt_address(&h.env, &admin, trusted.clone()).unwrap();
            unexempt_address(&h.env, &admin, trusted.clone()).unwrap();
            assert!(!is_exempt(&h.env, &trusted));

            let operation = op(&h.env, "issue_cred");
            let fallback = RateLimitConfig::new(60, 1);
            check_operation(&h.env, &trusted, &operation, fallback.clone()).unwrap();
            assert!(check_operation(&h.env, &trusted, &operation, fallback).is_err());
        });
    }

    #[test]
    fn exemption_admin_only() {
        let h = Harness::new();
        h.with_admin();
        h.run(|| {
            let intruder = Address::generate(&h.env);
            let target = Address::generate(&h.env);
            assert_eq!(
                exempt_address(&h.env, &intruder, target.clone()).unwrap_err(),
                RateLimitError::NotAdmin
            );
            assert_eq!(
                unexempt_address(&h.env, &intruder, target).unwrap_err(),
                RateLimitError::NotAdmin
            );
        });
    }

    // ── Status reporting (#201) ─────────────────────────────────────────

    #[test]
    fn status_reports_remaining_quota() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let operation = op(&h.env, "verify_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::new(60, 3),
            )
            .unwrap();

            check_operation(&h.env, &caller, &operation, RateLimitConfig::new(60, 99)).unwrap();
            check_operation(&h.env, &caller, &operation, RateLimitConfig::new(60, 99)).unwrap();

            let s = status(&h.env, &caller, &operation);
            assert_eq!(s.count, 2);
            assert_eq!(s.remaining, 1);
            assert_eq!(s.retry_after_secs, 0);
        });
    }

    #[test]
    fn status_reports_retry_after_once_exhausted() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let operation = op(&h.env, "verify_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::new(60, 1),
            )
            .unwrap();

            check_operation(&h.env, &caller, &operation, RateLimitConfig::new(60, 99)).unwrap();
            check_operation(&h.env, &caller, &operation, RateLimitConfig::new(60, 99)).unwrap_err();

            let s = status(&h.env, &caller, &operation);
            assert_eq!(s.remaining, 0);
            assert!(s.retry_after_secs > 0);
            assert_eq!(s.reset_at, h.env.ledger().timestamp() + 60);
        });
    }

    #[test]
    fn status_is_per_caller_and_per_operation() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let alice = Address::generate(&h.env);
            let bob = Address::generate(&h.env);

            let issue = op(&h.env, "issue_cred");
            let verify = op(&h.env, "verify_cred");
            set_limit(&h.env, &admin, issue.clone(), RateLimitConfig::new(60, 5)).unwrap();
            set_limit(&h.env, &admin, verify.clone(), RateLimitConfig::new(60, 5)).unwrap();

            check_operation(&h.env, &alice, &issue, RateLimitConfig::new(60, 5)).unwrap();

            assert_eq!(status(&h.env, &alice, &issue).count, 1);
            assert_eq!(status(&h.env, &alice, &verify).count, 0);
            assert_eq!(status(&h.env, &bob, &issue).count, 0);
        });
    }

    #[test]
    fn rejection_emits_event_with_reset_time() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let operation = op(&h.env, "verify_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::new(60, 1),
            )
            .unwrap();
            check_operation(&h.env, &caller, &operation, RateLimitConfig::new(60, 1)).unwrap();
            check_operation(&h.env, &caller, &operation, RateLimitConfig::new(60, 1)).unwrap_err();

            assert!(
                has_topic(&h.env, "RateLimitRejected"),
                "rejection must be observable by off-chain monitoring"
            );
        });
    }

    #[test]
    fn bucket_rolls_over_after_the_window() {
        let h = Harness::new();
        let admin = h.with_admin();
        h.run(|| {
            let caller = Address::generate(&h.env);
            let operation = op(&h.env, "verify_cred");
            set_limit(
                &h.env,
                &admin,
                operation.clone(),
                RateLimitConfig::new(60, 1),
            )
            .unwrap();
            let fallback = RateLimitConfig::new(60, 1);

            check_operation(&h.env, &caller, &operation, fallback.clone()).unwrap();
            assert!(check_operation(&h.env, &caller, &operation, fallback.clone()).is_err());

            h.advance(61);
            let s = check_operation(&h.env, &caller, &operation, fallback).unwrap();
            assert_eq!(s.count, 1);
        });
    }
}
