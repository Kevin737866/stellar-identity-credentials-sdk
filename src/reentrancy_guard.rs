/// Reentrancy guard for Soroban contracts.
///
/// # Background
/// Although Soroban's execution model differs from the EVM, cross-contract
/// calls can still trigger callback-style reentrancy if a malicious contract
/// calls back into a function before the first invocation completes.
///
/// # Design
/// A boolean lock is stored in **instance storage** under a fixed key.
/// - `acquire` sets the lock; returns `Err` if already locked.
/// - `release` clears the lock unconditionally.
///
/// Usage pattern (within a guarded function):
/// ```ignore
/// ReentrancyGuard::acquire(&env, "my_func").map_err(|_| MyError::Reentrant)?;
/// // ... perform state changes + external call ...
/// ReentrancyGuard::release(&env, "my_func");
/// ```
///
/// # Audit findings
/// The following cross-contract call sites were reviewed:
/// | Contract            | Function                        | Risk   | Mitigation |
/// |---------------------|---------------------------------|--------|------------|
/// | DID Registry        | `create_did`                    | Low    | No external calls; guard not required |
/// | Credential Issuer   | `issue_credential`              | Medium | Writes state before event publish; guard added as defence-in-depth |
/// | ZK Attestation      | `verify_proof`                  | Low    | Read-only external calls; state change is atomic |
/// | Compliance Filter   | `screen_address`                | Low    | No mutable callbacks |
/// | Reputation Score    | `update_transaction_reputation` | Medium | Guard added to prevent score inflation via callback loops |

use soroban_sdk::{contracterror, Env, Symbol};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReentrancyError {
    /// A reentrant call was detected and rejected.
    Reentrant = 1,
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

pub struct ReentrancyGuard;

impl ReentrancyGuard {
    /// Acquire the reentrancy lock for `scope`.
    ///
    /// Returns `Err(ReentrancyError::Reentrant)` if already locked.
    pub fn acquire(env: &Env, scope: &str) -> Result<(), ReentrancyError> {
        let key = Symbol::new(env, scope);
        if env.storage().instance().get::<Symbol, bool>(&key).unwrap_or(false) {
            return Err(ReentrancyError::Reentrant);
        }
        env.storage().instance().set(&key, &true);
        Ok(())
    }

    /// Release the reentrancy lock for `scope`. Always succeeds.
    pub fn release(env: &Env, scope: &str) {
        let key = Symbol::new(env, scope);
        env.storage().instance().remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Ledger, LedgerInfo},
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
    fn test_guard_acquires_and_releases() {
        let env = setup_env();
        assert!(ReentrancyGuard::acquire(&env, "scope_a").is_ok());
        ReentrancyGuard::release(&env, "scope_a");
        // After release, can acquire again
        assert!(ReentrancyGuard::acquire(&env, "scope_a").is_ok());
        ReentrancyGuard::release(&env, "scope_a");
    }

    #[test]
    fn test_guard_rejects_reentrant_call() {
        let env = setup_env();
        ReentrancyGuard::acquire(&env, "scope_b").unwrap();
        let result = ReentrancyGuard::acquire(&env, "scope_b");
        assert_eq!(result.err().unwrap(), ReentrancyError::Reentrant);
        ReentrancyGuard::release(&env, "scope_b");
    }

    #[test]
    fn test_guard_scopes_are_independent() {
        let env = setup_env();
        ReentrancyGuard::acquire(&env, "scope_c").unwrap();
        // Different scope is unaffected
        assert!(ReentrancyGuard::acquire(&env, "scope_d").is_ok());
        ReentrancyGuard::release(&env, "scope_c");
        ReentrancyGuard::release(&env, "scope_d");
    }

    #[test]
    fn test_guard_release_without_acquire_is_safe() {
        let env = setup_env();
        // Should not panic
        ReentrancyGuard::release(&env, "scope_e");
    }
}
