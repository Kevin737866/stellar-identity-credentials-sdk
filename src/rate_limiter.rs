/// Rate limiting for critical contract functions.
///
/// Uses a sliding-window approach stored in Soroban temporary storage.
/// Each caller gets a per-function bucket tracking (count, window_start).
/// If `count` exceeds the configured limit within the window, the call is rejected.
///
/// # Design
/// - Window duration and max requests are configurable per call site.
/// - State is stored in **temporary** storage (auto-expires) to avoid bloating
///   persistent storage with rate-limit bookkeeping.
/// - Admin can update limits via contract-level storage; defaults are applied
///   when no admin config exists.

use soroban_sdk::{contracterror, contracttype, Address, Env, Symbol};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum RateLimitError {
    /// Caller has exceeded the allowed request rate.
    RateLimitExceeded = 1,
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

// ---------------------------------------------------------------------------
// Admin-configurable limits stored in instance storage
// ---------------------------------------------------------------------------

/// Admin-configurable rate-limit parameters for a given function.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Window duration in seconds.
    pub window_secs: u64,
    /// Maximum calls allowed per window.
    pub max_calls: u32,
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
/// * `env`          – Soroban environment.
/// * `caller`       – Address performing the call.
/// * `function`     – Short symbol identifying the function (e.g. `"create_did"`).
/// * `max_calls`    – Max allowed calls per window.
/// * `window_secs`  – Window duration in seconds.
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

    let mut bucket: RateLimitBucket = env
        .storage()
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
    env.storage()
        .temporary()
        .set(&key, &bucket);
    env.storage()
        .temporary()
        .extend_ttl(&key, ttl_ledgers, ttl_ledgers);

    Ok(())
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Default limits for each guarded function.
pub mod defaults {
    /// DID creation: 5 per 300 seconds per caller.
    pub const CREATE_DID_MAX: u32 = 5;
    pub const CREATE_DID_WINDOW: u64 = 300;

    /// Credential issuance: 10 per 60 seconds per issuer.
    pub const ISSUE_CREDENTIAL_MAX: u32 = 10;
    pub const ISSUE_CREDENTIAL_WINDOW: u64 = 60;

    /// Reputation score update: 20 per 60 seconds per caller.
    pub const UPDATE_REPUTATION_MAX: u32 = 20;
    pub const UPDATE_REPUTATION_WINDOW: u64 = 60;
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Env,
    };

    fn setup_env() -> Env {
        let env = Env::default();
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000,
            protocol_version: 22,
            sequence_number: 1000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50000,
            min_persistent_entry_ttl: 50000,
            max_entry_ttl: 50000,
        });
        env
    }

    #[test]
    fn test_rate_limit_allows_within_limit() {
        let env = setup_env();
        let caller = Address::generate(&env);
        let func = Symbol::new(&env, "create_did");

        for _ in 0..3 {
            assert!(check_rate_limit(&env, &caller, func.clone(), 3, 60).is_ok());
        }
    }

    #[test]
    fn test_rate_limit_blocks_over_limit() {
        let env = setup_env();
        let caller = Address::generate(&env);
        let func = Symbol::new(&env, "create_did");

        for _ in 0..3 {
            check_rate_limit(&env, &caller, func.clone(), 3, 60).unwrap();
        }

        let result = check_rate_limit(&env, &caller, func, 3, 60);
        assert_eq!(result.err().unwrap(), RateLimitError::RateLimitExceeded);
    }

    #[test]
    fn test_rate_limit_resets_after_window() {
        let env = setup_env();
        let caller = Address::generate(&env);
        let func = Symbol::new(&env, "create_did");

        for _ in 0..3 {
            check_rate_limit(&env, &caller, func.clone(), 3, 60).unwrap();
        }

        // Advance time past the window
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000 + 61,
            protocol_version: 22,
            sequence_number: 1012,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50000,
            min_persistent_entry_ttl: 50000,
            max_entry_ttl: 50000,
        });

        assert!(check_rate_limit(&env, &caller, func, 3, 60).is_ok());
    }

    #[test]
    fn test_rate_limit_independent_per_caller() {
        let env = setup_env();
        let caller_a = Address::generate(&env);
        let caller_b = Address::generate(&env);
        let func = Symbol::new(&env, "create_did");

        for _ in 0..3 {
            check_rate_limit(&env, &caller_a, func.clone(), 3, 60).unwrap();
        }
        // caller_a is blocked
        assert!(check_rate_limit(&env, &caller_a, func.clone(), 3, 60).is_err());
        // caller_b is unaffected
        assert!(check_rate_limit(&env, &caller_b, func, 3, 60).is_ok());
    }
}
