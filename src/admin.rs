//! Admin Role & Access Control System (#42)
//!
//! Provides a unified `Ownable`-style admin pattern that every contract can
//! embed.  The module stores a single `admin: Option<Address>` in instance
//! storage and exposes guards, role-transfer, and renunciation helpers.
//!
//! # Usage (within a contract)
//! ```ignore
//! use crate::admin::{self, Admin};
//!
//! pub fn initialize(env: Env, admin: Address) {
//!     admin::init(&env, admin);
//! }
//!
//! pub fn admin_only_function(env: Env, caller: Address) -> Result<(), MyError> {
//!     caller.require_auth();
//!     admin::only_admin(&env, &caller)?;  // returns Err(Unauthorized) if not admin
//!     // … privileged logic …
//!     Ok(())
//! }
//! ```

use soroban_sdk::{Address, Env, Symbol};

// ---------------------------------------------------------------------------
// Storage key
// ---------------------------------------------------------------------------

const KEY_ADMIN: &str = "admin";

// ---------------------------------------------------------------------------
// Error type — each contract re-exports its own variant, but the module
// returns a simple result so contracts can map it.
// ---------------------------------------------------------------------------

/// Initialise the admin for a contract.  Must be called **once** during
/// contract initialisation.
///
/// Returns:
/// - `Ok(())` on success.
/// - `Err(AdminError::AlreadyInitialized)` if already initialised.
pub fn init(env: &Env, admin: Address) -> Result<(), AdminError> {
    let key = Symbol::new(env, KEY_ADMIN);
    if env.storage().instance().has(&key) {
        return Err(AdminError::AlreadyInitialized);
    }
    env.storage().instance().set(&key, &admin);
    env.events()
        .publish((Symbol::new(env, "AdminTransferred"),), ((), admin));
    Ok(())
}

/// Transfer admin role from the current admin to `new_admin`.
///
/// Caller **must** have authenticated as the current admin (`require_auth`
/// called before this function).
///
/// Returns:
/// - `Ok(())` on success.
/// - `Err(AdminError::NotInitialized)` if the contract has no admin.
/// - `Err(AdminError::Unauthorized)` if `caller` is not the current admin.
pub fn transfer_admin(
    env: &Env,
    caller: &Address,
    new_admin: Address,
) -> Result<(), AdminError> {
    let key = Symbol::new(env, KEY_ADMIN);
    let current: Address = env
        .storage()
        .instance()
        .get(&key)
        .ok_or(AdminError::NotInitialized)?;

    if *caller != current {
        return Err(AdminError::Unauthorized);
    }

    env.storage().instance().set(&key, &new_admin);
    env.events().publish(
        (Symbol::new(env, "AdminTransferred"), current),
        new_admin,
    );
    Ok(())
}

/// Allow the admin to renounce the role (set to `None`-equivalent).
///
/// After renunciation the contract has no admin, and no further privileged
/// operations can be performed unless the contract supports a separate
/// governance mechanism.
///
/// Caller **must** have authenticated as the current admin.
pub fn renounce_admin(env: &Env, caller: &Address) -> Result<(), AdminError> {
    let key = Symbol::new(env, KEY_ADMIN);
    let current: Address = env
        .storage()
        .instance()
        .get(&key)
        .ok_or(AdminError::NotInitialized)?;

    if *caller != current {
        return Err(AdminError::Unauthorized);
    }

    env.storage().instance().remove(&key);
    env.events()
        .publish((Symbol::new(env, "AdminRenounced"), current), ());
    Ok(())
}

/// Return the current admin address, if any.
pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage()
        .instance()
        .get(&Symbol::new(env, KEY_ADMIN))
}

/// Guard: returns `Ok(())` if `caller` is the admin, `Err(AdminError::Unauthorized)` otherwise.
/// Returns `Err(AdminError::NotInitialized)` if the contract has no admin set.
pub fn only_admin(env: &Env, caller: &Address) -> Result<(), AdminError> {
    let key = Symbol::new(env, KEY_ADMIN);
    let admin: Address = env
        .storage()
        .instance()
        .get(&key)
        .ok_or(AdminError::NotInitialized)?;

    if *caller != admin {
        return Err(AdminError::Unauthorized);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by admin operations.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AdminError {
    /// Contract's admin was never initialised.
    NotInitialized = 1,
    /// Caller is not the current admin.
    Unauthorized = 2,
    /// Contract admin has already been initialised.
    AlreadyInitialized = 3,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Env,
    };

    fn setup() -> Env {
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

    #[test]
    fn init_sets_admin() {
        let env = setup();
        let admin = Address::generate(&env);
        assert!(init(&env, admin.clone()).is_ok());
        assert_eq!(get_admin(&env), Some(admin));
    }

    #[test]
    fn double_init_returns_error() {
        let env = setup();
        let a1 = Address::generate(&env);
        let a2 = Address::generate(&env);
        assert!(init(&env, a1).is_ok());
        assert_eq!(init(&env, a2), Err(AdminError::AlreadyInitialized));
    }

    #[test]
    fn only_admin_passes_for_admin() {
        let env = setup();
        let admin = Address::generate(&env);
        init(&env, admin.clone()).unwrap();
        assert!(only_admin(&env, &admin).is_ok());
    }

    #[test]
    fn only_admin_rejects_non_admin() {
        let env = setup();
        let admin = Address::generate(&env);
        let intruder = Address::generate(&env);
        init(&env, admin).unwrap();
        assert_eq!(only_admin(&env, &intruder), Err(AdminError::Unauthorized));
    }

    #[test]
    fn transfer_admin_works() {
        let env = setup();
        let admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        init(&env, admin.clone()).unwrap();

        transfer_admin(&env, &admin, new_admin.clone()).unwrap();
        assert_eq!(get_admin(&env), Some(new_admin.clone()));

        // Old admin is locked out
        assert_eq!(only_admin(&env, &admin), Err(AdminError::Unauthorized));
        assert!(only_admin(&env, &new_admin).is_ok());
    }

    #[test]
    fn transfer_admin_by_non_admin_fails() {
        let env = setup();
        let admin = Address::generate(&env);
        let intruder = Address::generate(&env);
        let target = Address::generate(&env);
        init(&env, admin).unwrap();
        assert_eq!(
            transfer_admin(&env, &intruder, target),
            Err(AdminError::Unauthorized)
        );
    }

    #[test]
    fn renounce_admin_works() {
        let env = setup();
        let admin = Address::generate(&env);
        init(&env, admin.clone()).unwrap();

        renounce_admin(&env, &admin).unwrap();
        assert!(get_admin(&env).is_none());
    }

    #[test]
    fn renounce_by_non_admin_fails() {
        let env = setup();
        let admin = Address::generate(&env);
        let intruder = Address::generate(&env);
        init(&env, admin).unwrap();
        assert_eq!(
            renounce_admin(&env, &intruder),
            Err(AdminError::Unauthorized)
        );
    }

    #[test]
    fn not_initialized_returns_error() {
        let env = setup();
        let someone = Address::generate(&env);
        assert_eq!(only_admin(&env, &someone), Err(AdminError::NotInitialized));
        assert_eq!(
            transfer_admin(&env, &someone, Address::generate(&env)),
            Err(AdminError::NotInitialized)
        );
        assert_eq!(
            renounce_admin(&env, &someone),
            Err(AdminError::NotInitialized)
        );
    }
}
