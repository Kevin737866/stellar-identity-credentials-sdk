//! DID Recovery Mechanism (#96, #97)
//!
//! Allows DID holders to regain control of their identity if they lose access
//! to their private keys. Supports social recovery with n-of-m guardians,
//! time-locked recovery, and trusted third-party recovery methods.
//!
//! ## Recovery Methods
//!
//! 1. **Social Recovery** – The DID holder designates n-of-m guardians who can
//!    collectively approve a recovery request.
//! 2. **Time-Locked Recovery** – Recovery automatically triggers after a
//!    configurable time delay with optional cancellation window.
//! 3. **Trusted Third-Party Recovery** – A designated recovery service can
//!    initiate recovery on behalf of the DID holder.
//!
//! ## Storage Schema
//!
//! | Variant                     | Value type               | Storage tier |
//! |-----------------------------|--------------------------|-------------|
//! | `RecoveryConfig(Bytes)`     | `RecoveryConfig`         | Persistent  |
//! | `Guardian(Bytes, Address)`  | `GuardianRecord`         | Persistent  |
//! | `RecoveryRequest(Bytes)`    | `RecoveryRequest`        | Persistent  |
//! | `DidRequests(Bytes)`        | `Vec<Bytes>`             | Persistent  |
//! | `RecoveryIndex`             | `Vec<Bytes>`             | Persistent  |

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol, Vec,
};

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum RecoveryKey {
    RecoveryConfig(Bytes),
    Guardian(Bytes, Address),
    RecoveryRequest(Bytes),
    DidRequests(Bytes),
    RecoveryIndex,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DIDRecoveryError {
    Unauthorized = 1,
    NotFound = 2,
    AlreadyConfigured = 3,
    InvalidGuardianCount = 4,
    InvalidThreshold = 5,
    GuardianAlreadyExists = 6,
    RequestAlreadyExists = 7,
    InsufficientApprovals = 8,
    RecoveryNotConfigured = 9,
    AlreadyRecovered = 10,
    RecoveryCancelled = 11,
    TimeLockNotElapsed = 12,
    InvalidGuardian = 13,
    GuardianNotAuthorized = 14,
    RecoveryWindowExpired = 15,
    InvalidRecoveryMethod = 16,
    AlreadyApproved = 17,
    RecoveryAlreadyInitiated = 18,
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryMethod {
    SocialRecovery,
    TimeLockedRecovery,
    TrustedThirdParty,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryConfig {
    pub did: Bytes,
    pub recovery_method: RecoveryMethod,
    /// Number of guardians required for social recovery (n-of-m)
    pub guardian_threshold: u32,
    /// Total number of guardians
    pub total_guardians: u32,
    /// Time lock duration in seconds (for time-locked recovery)
    pub time_lock_duration: u64,
    /// Address of trusted third-party recovery service
    pub trusted_third_party: Option<Address>,
    /// Whether the recovery config is active
    pub active: bool,
    /// When this config was created
    pub created_at: u64,
    /// When this config was last updated
    pub updated_at: u64,
    /// Number of recovery requests made
    pub recovery_count: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianRecord {
    pub guardian: Address,
    pub did: Bytes,
    pub weight: u32,
    pub added_at: u64,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryRequestStatus {
    Pending,
    Approved,
    Executed,
    Cancelled,
    Expired,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRequest {
    pub id: Bytes,
    pub did: Bytes,
    pub new_controller: Address,
    pub method: RecoveryMethod,
    pub status: RecoveryRequestStatus,
    /// Approval addresses from guardians
    pub approvals: Vec<Address>,
    /// When the recovery was initiated
    pub initiated_at: u64,
    /// When the time lock expires (for time-locked recovery)
    pub time_lock_expires_at: Option<u64>,
    /// When the recovery was completed
    pub completed_at: Option<u64>,
    /// Who cancelled (if cancelled)
    pub cancelled_by: Option<Address>,
    /// Reason for cancellation or notes
    pub note: Option<Bytes>,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct DIDRecovery;

#[contractimpl]
impl DIDRecovery {
    /// Configure recovery for a DID.
    ///
    /// Only the DID controller can call this. For social recovery, you must
    /// specify a threshold and later add guardians. For time-locked recovery,
    /// specify the time_lock_duration. For trusted third-party, provide the
    /// address of the recovery service.
    pub fn configure_recovery(
        env: Env,
        controller: Address,
        did: Bytes,
        recovery_method: RecoveryMethod,
        guardian_threshold: u32,
        time_lock_duration: u64,
        trusted_third_party: Option<Address>,
    ) -> Result<(), DIDRecoveryError> {
        controller.require_auth();

        if env
            .storage()
            .persistent()
            .has(&RecoveryKey::RecoveryConfig(did.clone()))
        {
            return Err(DIDRecoveryError::AlreadyConfigured);
        }

        match recovery_method {
            RecoveryMethod::SocialRecovery => {
                if guardian_threshold == 0 {
                    return Err(DIDRecoveryError::InvalidThreshold);
                }
            }
            RecoveryMethod::TimeLockedRecovery => {
                if time_lock_duration == 0 {
                    return Err(DIDRecoveryError::InvalidThreshold);
                }
            }
            RecoveryMethod::TrustedThirdParty => {
                if trusted_third_party.is_none() {
                    return Err(DIDRecoveryError::InvalidGuardian);
                }
            }
        }

        let now = env.ledger().timestamp();

        let config = RecoveryConfig {
            did: did.clone(),
            recovery_method,
            guardian_threshold,
            total_guardians: 0,
            time_lock_duration,
            trusted_third_party,
            active: true,
            created_at: now,
            updated_at: now,
            recovery_count: 0,
        };

        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryConfig(did.clone()), &config);

        env.events().publish(
            (Symbol::new(&env, "RecoveryConfigured"),),
            (did, controller),
        );

        Ok(())
    }

    /// Get the recovery configuration for a DID.
    pub fn get_recovery_config(env: Env, did: Bytes) -> Result<RecoveryConfig, DIDRecoveryError> {
        env.storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(did))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)
    }

    /// Add a guardian for social recovery.
    ///
    /// Only the DID controller can add guardians.
    pub fn add_guardian(
        env: Env,
        controller: Address,
        did: Bytes,
        guardian: Address,
        weight: u32,
    ) -> Result<(), DIDRecoveryError> {
        controller.require_auth();

        let mut config: RecoveryConfig = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(did.clone()))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)?;

        if config.recovery_method != RecoveryMethod::SocialRecovery {
            return Err(DIDRecoveryError::InvalidRecoveryMethod);
        }

        if !config.active {
            return Err(DIDRecoveryError::RecoveryNotConfigured);
        }

        if env
            .storage()
            .persistent()
            .has(&RecoveryKey::Guardian(did.clone(), guardian.clone()))
        {
            return Err(DIDRecoveryError::GuardianAlreadyExists);
        }

        let record = GuardianRecord {
            guardian: guardian.clone(),
            did: did.clone(),
            weight,
            added_at: env.ledger().timestamp(),
            active: true,
        };

        env.storage().persistent().set(
            &RecoveryKey::Guardian(did.clone(), guardian.clone()),
            &record,
        );

        config.total_guardians += 1;
        config.updated_at = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryConfig(did.clone()), &config);

        env.events()
            .publish((Symbol::new(&env, "GuardianAdded"),), (did, guardian));

        Ok(())
    }

    /// Remove a guardian from social recovery.
    pub fn remove_guardian(
        env: Env,
        controller: Address,
        did: Bytes,
        guardian: Address,
    ) -> Result<(), DIDRecoveryError> {
        controller.require_auth();

        let mut config: RecoveryConfig = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(did.clone()))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)?;

        let mut record: GuardianRecord = env
            .storage()
            .persistent()
            .get(&RecoveryKey::Guardian(did.clone(), guardian.clone()))
            .ok_or(DIDRecoveryError::NotFound)?;

        record.active = false;
        env.storage().persistent().set(
            &RecoveryKey::Guardian(did.clone(), guardian.clone()),
            &record,
        );

        if config.total_guardians > 0 {
            config.total_guardians -= 1;
        }
        config.updated_at = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryConfig(did.clone()), &config);

        env.events()
            .publish((Symbol::new(&env, "GuardianRemoved"),), (did, guardian));

        Ok(())
    }

    /// Get a guardian record.
    pub fn get_guardian(
        env: Env,
        did: Bytes,
        guardian: Address,
    ) -> Result<GuardianRecord, DIDRecoveryError> {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Guardian(did, guardian))
            .ok_or(DIDRecoveryError::NotFound)
    }

    /// Initiate a recovery request.
    ///
    /// For social recovery: any guardian can initiate. For time-locked: the
    /// controller initiates. For trusted third-party: the TTP initiates.
    pub fn initiate_recovery(
        env: Env,
        initiator: Address,
        did: Bytes,
        new_controller: Address,
        note: Option<Bytes>,
    ) -> Result<Bytes, DIDRecoveryError> {
        initiator.require_auth();

        let config: RecoveryConfig = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(did.clone()))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)?;

        if !config.active {
            return Err(DIDRecoveryError::RecoveryNotConfigured);
        }

        // Check for existing pending request
        let existing_requests: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&RecoveryKey::DidRequests(did.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        for req_id in existing_requests.iter() {
            if let Some(req) = env
                .storage()
                .persistent()
                .get::<RecoveryKey, RecoveryRequest>(&RecoveryKey::RecoveryRequest(req_id.clone()))
            {
                if req.status == RecoveryRequestStatus::Pending {
                    return Err(DIDRecoveryError::RecoveryAlreadyInitiated);
                }
            }
        }

        let now = env.ledger().timestamp();
        let request_id = Self::generate_request_id(&env, &did);

        let time_lock_expires_at = match config.recovery_method {
            RecoveryMethod::TimeLockedRecovery => Some(now + config.time_lock_duration),
            _ => None,
        };

        let request = RecoveryRequest {
            id: request_id.clone(),
            did: did.clone(),
            new_controller: new_controller.clone(),
            method: config.recovery_method.clone(),
            status: RecoveryRequestStatus::Pending,
            approvals: Vec::new(&env),
            initiated_at: now,
            time_lock_expires_at,
            completed_at: None,
            cancelled_by: None,
            note,
        };

        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryRequest(request_id.clone()), &request);

        // Add to DID's request list
        let mut requests: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&RecoveryKey::DidRequests(did.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        requests.push_back(request_id.clone());
        env.storage()
            .persistent()
            .set(&RecoveryKey::DidRequests(did.clone()), &requests);

        // Add to global index
        let mut index: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryIndex)
            .unwrap_or_else(|| Vec::new(&env));
        index.push_back(request_id.clone());
        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryIndex, &index);

        env.events().publish(
            (Symbol::new(&env, "RecoveryInitiated"),),
            (request_id.clone(), did, initiator, new_controller),
        );

        Ok(request_id)
    }

    /// Approve a recovery request as a guardian (social recovery).
    ///
    /// Each guardian can only approve once. Once enough guardians have
    /// approved (>= threshold), the recovery can be executed.
    pub fn approve_recovery(
        env: Env,
        guardian: Address,
        request_id: Bytes,
    ) -> Result<(), DIDRecoveryError> {
        guardian.require_auth();

        let mut request: RecoveryRequest = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryRequest(request_id.clone()))
            .ok_or(DIDRecoveryError::NotFound)?;

        if request.status != RecoveryRequestStatus::Pending {
            return Err(DIDRecoveryError::RequestAlreadyExists);
        }

        let config: RecoveryConfig = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(request.did.clone()))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)?;

        // Verify guardian exists and is active
        let guardian_record: GuardianRecord = env
            .storage()
            .persistent()
            .get(&RecoveryKey::Guardian(
                request.did.clone(),
                guardian.clone(),
            ))
            .ok_or(DIDRecoveryError::GuardianNotAuthorized)?;

        if !guardian_record.active {
            return Err(DIDRecoveryError::GuardianNotAuthorized);
        }

        // Check if already approved
        for approval in request.approvals.iter() {
            if approval == guardian {
                return Err(DIDRecoveryError::AlreadyApproved);
            }
        }

        request.approvals.push_back(guardian.clone());

        // Check if threshold is met
        if request.approvals.len() as u32 >= config.guardian_threshold {
            request.status = RecoveryRequestStatus::Approved;
        }

        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryRequest(request_id.clone()), &request);

        env.events().publish(
            (Symbol::new(&env, "RecoveryApproved"),),
            (request_id, guardian),
        );

        Ok(())
    }

    /// Execute an approved recovery request.
    ///
    /// For social recovery: requires threshold of guardian approvals.
    /// For time-locked recovery: requires the time lock to have elapsed.
    /// For trusted third-party: the TTP can execute directly.
    ///
    /// Returns the new controller address.
    pub fn execute_recovery(
        env: Env,
        executor: Address,
        request_id: Bytes,
    ) -> Result<Address, DIDRecoveryError> {
        executor.require_auth();

        let mut request: RecoveryRequest = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryRequest(request_id.clone()))
            .ok_or(DIDRecoveryError::NotFound)?;

        match request.status {
            RecoveryRequestStatus::Cancelled => return Err(DIDRecoveryError::RecoveryCancelled),
            RecoveryRequestStatus::Expired => return Err(DIDRecoveryError::RecoveryWindowExpired),
            RecoveryRequestStatus::Executed => return Err(DIDRecoveryError::AlreadyRecovered),
            _ => {}
        }

        let config: RecoveryConfig = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(request.did.clone()))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)?;

        match config.recovery_method {
            RecoveryMethod::SocialRecovery => {
                if request.status != RecoveryRequestStatus::Approved {
                    return Err(DIDRecoveryError::InsufficientApprovals);
                }
            }
            RecoveryMethod::TimeLockedRecovery => {
                if let Some(expires_at) = request.time_lock_expires_at {
                    if env.ledger().timestamp() < expires_at {
                        return Err(DIDRecoveryError::TimeLockNotElapsed);
                    }
                }
            }
            RecoveryMethod::TrustedThirdParty => {
                let ttp = config
                    .trusted_third_party
                    .ok_or(DIDRecoveryError::InvalidGuardian)?;
                if executor != ttp {
                    return Err(DIDRecoveryError::Unauthorized);
                }
            }
        }

        let now = env.ledger().timestamp();
        let new_controller = request.new_controller.clone();

        request.status = RecoveryRequestStatus::Executed;
        request.completed_at = Some(now);

        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryRequest(request_id.clone()), &request);

        // Update recovery config count
        let mut config: RecoveryConfig = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(request.did.clone()))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)?;
        config.recovery_count += 1;
        config.updated_at = now;
        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryConfig(request.did.clone()), &config);

        env.events().publish(
            (Symbol::new(&env, "RecoveryExecuted"),),
            (request_id, request.did.clone(), new_controller.clone()),
        );

        Ok(new_controller)
    }

    /// Cancel a pending recovery request.
    ///
    /// Only the original initiator or the DID controller can cancel.
    pub fn cancel_recovery(
        env: Env,
        canceller: Address,
        request_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<(), DIDRecoveryError> {
        canceller.require_auth();

        let mut request: RecoveryRequest = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryRequest(request_id.clone()))
            .ok_or(DIDRecoveryError::NotFound)?;

        if request.status == RecoveryRequestStatus::Executed {
            return Err(DIDRecoveryError::AlreadyRecovered);
        }

        if request.status == RecoveryRequestStatus::Cancelled {
            return Err(DIDRecoveryError::RecoveryCancelled);
        }

        request.status = RecoveryRequestStatus::Cancelled;
        request.cancelled_by = Some(canceller.clone());
        request.note = reason;

        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryRequest(request_id.clone()), &request);

        env.events().publish(
            (Symbol::new(&env, "RecoveryCancelled"),),
            (request_id, canceller),
        );

        Ok(())
    }

    /// Get a recovery request by ID.
    pub fn get_recovery_request(
        env: Env,
        request_id: Bytes,
    ) -> Result<RecoveryRequest, DIDRecoveryError> {
        env.storage()
            .persistent()
            .get(&RecoveryKey::RecoveryRequest(request_id))
            .ok_or(DIDRecoveryError::NotFound)
    }

    /// Get all recovery requests for a DID.
    pub fn get_did_recovery_requests(env: Env, did: Bytes) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&RecoveryKey::DidRequests(did))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get pending recovery request for a DID (if any).
    pub fn get_pending_recovery(env: Env, did: Bytes) -> Option<RecoveryRequest> {
        let requests: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&RecoveryKey::DidRequests(did))
            .unwrap_or_else(|| Vec::new(&env));

        for req_id in requests.iter() {
            if let Some(req) = env
                .storage()
                .persistent()
                .get::<RecoveryKey, RecoveryRequest>(&RecoveryKey::RecoveryRequest(req_id))
            {
                if req.status == RecoveryRequestStatus::Pending
                    || req.status == RecoveryRequestStatus::Approved
                {
                    return Some(req);
                }
            }
        }

        None
    }

    /// Update the recovery configuration (change threshold, time lock, etc.).
    pub fn update_recovery_config(
        env: Env,
        controller: Address,
        did: Bytes,
        new_threshold: Option<u32>,
        new_time_lock_duration: Option<u64>,
        new_trusted_third_party: Option<Address>,
    ) -> Result<(), DIDRecoveryError> {
        controller.require_auth();

        let mut config: RecoveryConfig = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(did.clone()))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)?;

        if !config.active {
            return Err(DIDRecoveryError::RecoveryNotConfigured);
        }

        if let Some(threshold) = new_threshold {
            if threshold == 0 || threshold > config.total_guardians {
                return Err(DIDRecoveryError::InvalidThreshold);
            }
            config.guardian_threshold = threshold;
        }

        if let Some(duration) = new_time_lock_duration {
            config.time_lock_duration = duration;
        }

        if let Some(ttp) = new_trusted_third_party {
            config.trusted_third_party = Some(ttp);
        }

        config.updated_at = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryConfig(did.clone()), &config);

        env.events().publish(
            (Symbol::new(&env, "RecoveryConfigUpdated"),),
            (did, controller),
        );

        Ok(())
    }

    /// Deactivate the recovery configuration for a DID.
    pub fn deactivate_recovery(
        env: Env,
        controller: Address,
        did: Bytes,
    ) -> Result<(), DIDRecoveryError> {
        controller.require_auth();

        let mut config: RecoveryConfig = env
            .storage()
            .persistent()
            .get(&RecoveryKey::RecoveryConfig(did.clone()))
            .ok_or(DIDRecoveryError::RecoveryNotConfigured)?;

        config.active = false;
        config.updated_at = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&RecoveryKey::RecoveryConfig(did.clone()), &config);

        env.events().publish(
            (Symbol::new(&env, "RecoveryDeactivated"),),
            (did, controller),
        );

        Ok(())
    }

    /// Check if a DID has an active recovery configuration.
    pub fn has_recovery_configured(env: Env, did: Bytes) -> bool {
        env.storage()
            .persistent()
            .has(&RecoveryKey::RecoveryConfig(did))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn generate_request_id(env: &Env, _did: &Bytes) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"rec:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Address, Bytes, Env,
    };

    fn setup_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
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

    fn make_did(env: &Env) -> Bytes {
        Bytes::from_slice(env, b"did:stellar:GABCDEF123456789")
    }

    #[test]
    fn test_configure_social_recovery() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);

        let result = DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            2,
            0,
            None,
        );
        assert!(result.is_ok());

        let config = DIDRecovery::get_recovery_config(env.clone(), did.clone()).unwrap();
        assert_eq!(config.guardian_threshold, 2);
        assert_eq!(config.recovery_method, RecoveryMethod::SocialRecovery);
        assert!(config.active);
    }

    #[test]
    fn test_configure_duplicate_fails() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            2,
            0,
            None,
        )
        .unwrap();

        let result = DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did,
            RecoveryMethod::SocialRecovery,
            1,
            0,
            None,
        );
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), DIDRecoveryError::AlreadyConfigured);
    }

    #[test]
    fn test_add_and_remove_guardian() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);
        let guardian = Address::generate(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            2,
            0,
            None,
        )
        .unwrap();

        // Add guardian
        DIDRecovery::add_guardian(
            env.clone(),
            controller.clone(),
            did.clone(),
            guardian.clone(),
            1,
        )
        .unwrap();

        let record = DIDRecovery::get_guardian(env.clone(), did.clone(), guardian.clone()).unwrap();
        assert!(record.active);
        assert_eq!(record.guardian, guardian);

        let config = DIDRecovery::get_recovery_config(env.clone(), did.clone()).unwrap();
        assert_eq!(config.total_guardians, 1);

        // Remove guardian
        DIDRecovery::remove_guardian(env.clone(), controller.clone(), did.clone(), guardian.clone())
            .unwrap();

        let record = DIDRecovery::get_guardian(env.clone(), did, guardian).unwrap();
        assert!(!record.active);
    }

    #[test]
    fn test_full_social_recovery_flow() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);
        let guardian1 = Address::generate(&env);
        let guardian2 = Address::generate(&env);
        let guardian3 = Address::generate(&env);
        let new_controller = Address::generate(&env);

        // Configure social recovery with 2-of-3 guardians
        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            2,
            0,
            None,
        )
        .unwrap();

        // Add guardians
        DIDRecovery::add_guardian(
            env.clone(),
            controller.clone(),
            did.clone(),
            guardian1.clone(),
            1,
        )
        .unwrap();
        DIDRecovery::add_guardian(
            env.clone(),
            controller.clone(),
            did.clone(),
            guardian2.clone(),
            1,
        )
        .unwrap();
        DIDRecovery::add_guardian(
            env.clone(),
            controller.clone(),
            did.clone(),
            guardian3.clone(),
            1,
        )
        .unwrap();

        // Guardian1 initiates recovery
        let request_id = DIDRecovery::initiate_recovery(
            env.clone(),
            guardian1.clone(),
            did.clone(),
            new_controller.clone(),
            Some(Bytes::from_slice(&env, b"Lost my keys")),
        )
        .unwrap();

        // Guardian1 approves
        DIDRecovery::approve_recovery(env.clone(), guardian1.clone(), request_id.clone()).unwrap();

        // Guardian2 approves (meets threshold of 2)
        DIDRecovery::approve_recovery(env.clone(), guardian2, request_id.clone()).unwrap();

        // Execute recovery
        let result =
            DIDRecovery::execute_recovery(env.clone(), guardian1.clone(), request_id.clone())
                .unwrap();
        assert_eq!(result, new_controller);

        // Request should now be executed
        let request = DIDRecovery::get_recovery_request(env.clone(), request_id).unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Executed);
    }

    #[test]
    fn test_insufficient_approvals_fails() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);
        let guardian1 = Address::generate(&env);
        let guardian2 = Address::generate(&env);
        let new_controller = Address::generate(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            3, // Requires 3 approvals
            0,
            None,
        )
        .unwrap();

        DIDRecovery::add_guardian(
            env.clone(),
            controller.clone(),
            did.clone(),
            guardian1.clone(),
            1,
        )
        .unwrap();
        DIDRecovery::add_guardian(
            env.clone(),
            controller.clone(),
            did.clone(),
            guardian2.clone(),
            1,
        )
        .unwrap();

        let request_id = DIDRecovery::initiate_recovery(
            env.clone(),
            guardian1.clone(),
            did.clone(),
            new_controller.clone(),
            None,
        )
        .unwrap();

        // Only 1 approval - should be pending
        DIDRecovery::approve_recovery(env.clone(), guardian1.clone(), request_id.clone()).unwrap();

        let request = DIDRecovery::get_recovery_request(env.clone(), request_id.clone()).unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Pending);

        // Execute without enough approvals
        let result = DIDRecovery::execute_recovery(env.clone(), guardian2, request_id);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            DIDRecoveryError::InsufficientApprovals
        );
    }

    #[test]
    fn test_time_locked_recovery() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);
        let new_controller = Address::generate(&env);

        // Configure time-locked recovery with 1 hour lock
        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::TimeLockedRecovery,
            0,
            3600, // 1 hour
            None,
        )
        .unwrap();

        // Initiate time-locked recovery
        let request_id = DIDRecovery::initiate_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            new_controller.clone(),
            None,
        )
        .unwrap();

        // Try to execute before time lock expires
        let result =
            DIDRecovery::execute_recovery(env.clone(), controller.clone(), request_id.clone());
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), DIDRecoveryError::TimeLockNotElapsed);

        // Advance time past the lock
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_004_000, // 4000 seconds later
            protocol_version: 22,
            sequence_number: 2000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50000,
            min_persistent_entry_ttl: 50000,
            max_entry_ttl: 50000,
        });

        // Now execution should succeed
        let result = DIDRecovery::execute_recovery(env.clone(), controller.clone(), request_id).unwrap();
        assert_eq!(result, new_controller);
    }

    #[test]
    fn test_cancel_recovery() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);
        let guardian = Address::generate(&env);
        let new_controller = Address::generate(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            1,
            0,
            None,
        )
        .unwrap();

        DIDRecovery::add_guardian(
            env.clone(),
            controller.clone(),
            did.clone(),
            guardian.clone(),
            1,
        )
        .unwrap();

        let request_id = DIDRecovery::initiate_recovery(
            env.clone(),
            guardian,
            did.clone(),
            new_controller.clone(),
            None,
        )
        .unwrap();

        // Cancel the recovery
        DIDRecovery::cancel_recovery(
            env.clone(),
            controller.clone(),
            request_id.clone(),
            Some(Bytes::from_slice(&env, b"Found my keys")),
        )
        .unwrap();

        let request = DIDRecovery::get_recovery_request(env.clone(), request_id).unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Cancelled);
    }

    #[test]
    fn test_trusted_third_party_recovery() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);
        let ttp = Address::generate(&env);
        let new_controller = Address::generate(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::TrustedThirdParty,
            0,
            0,
            Some(ttp.clone()),
        )
        .unwrap();

        // TTP initiates recovery
        let request_id = DIDRecovery::initiate_recovery(
            env.clone(),
            ttp.clone(),
            did.clone(),
            new_controller.clone(),
            None,
        )
        .unwrap();

        // TTP executes recovery
        let result = DIDRecovery::execute_recovery(env.clone(), ttp, request_id).unwrap();
        assert_eq!(result, new_controller);
    }

    #[test]
    fn test_unauthorized_ttp_execution_fails() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);
        let ttp = Address::generate(&env);
        let attacker = Address::generate(&env);
        let new_controller = Address::generate(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::TrustedThirdParty,
            0,
            0,
            Some(ttp.clone()),
        )
        .unwrap();

        let request_id =
            DIDRecovery::initiate_recovery(env.clone(), ttp.clone(), did.clone(), new_controller.clone(), None)
                .unwrap();

        // Attacker tries to execute
        let result = DIDRecovery::execute_recovery(env.clone(), attacker, request_id);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), DIDRecoveryError::Unauthorized);
    }

    #[test]
    fn test_duplicate_approval_fails() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);
        let guardian = Address::generate(&env);
        let new_controller = Address::generate(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            2,
            0,
            None,
        )
        .unwrap();

        DIDRecovery::add_guardian(
            env.clone(),
            controller.clone(),
            did.clone(),
            guardian.clone(),
            1,
        )
        .unwrap();

        let request_id = DIDRecovery::initiate_recovery(
            env.clone(),
            guardian.clone(),
            did.clone(),
            new_controller.clone(),
            None,
        )
        .unwrap();

        DIDRecovery::approve_recovery(env.clone(), guardian.clone(), request_id.clone()).unwrap();

        // Same guardian trying again
        let result = DIDRecovery::approve_recovery(env.clone(), guardian, request_id);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), DIDRecoveryError::AlreadyApproved);
    }

    #[test]
    fn test_deactivate_recovery() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            1,
            0,
            None,
        )
        .unwrap();

        assert!(DIDRecovery::has_recovery_configured(
            env.clone(),
            did.clone()
        ));

        DIDRecovery::deactivate_recovery(env.clone(), controller.clone(), did.clone()).unwrap();

        let config = DIDRecovery::get_recovery_config(env.clone(), did).unwrap();
        assert!(!config.active);
    }

    #[test]
    fn test_update_recovery_config() {
        let env = setup_env();
        let controller = Address::generate(&env);
        let did = make_did(&env);

        DIDRecovery::configure_recovery(
            env.clone(),
            controller.clone(),
            did.clone(),
            RecoveryMethod::SocialRecovery,
            2,
            0,
            None,
        )
        .unwrap();

        // Update threshold to 3
        DIDRecovery::update_recovery_config(
            env.clone(),
            controller.clone(),
            did.clone(),
            Some(3),
            None,
            None,
        )
        .unwrap();

        let config = DIDRecovery::get_recovery_config(env.clone(), did).unwrap();
        assert_eq!(config.guardian_threshold, 3);
    }
}
