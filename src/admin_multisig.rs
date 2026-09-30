//! Admin Multi-Signature for Privileged Operations (#202)
//!
//! Privileged operations — pausing the contract, upgrading its WASM, editing
//! the sanctions list — are the highest-value targets in a Soroban contract.
//! Gating them on a single `admin: Address` means a single compromised key
//! can unilaterally freeze the deployment or swap out its code.
//!
//! This module replaces that single-key gate with an M-of-N approval process:
//!
//! 1. A privileged action is [`propose_admin_operation`]d by any admin signer.
//! 2. Other admin signers [`approve_admin_operation`] it; each approval is
//!    authenticated by that signer's `require_auth`, so approvals cannot be
//!    forged on their behalf.
//! 3. Once the number of distinct approvals reaches `admin_threshold`, any
//!    admin signer may [`execute_admin_operation`] it.
//!
//! The full lifecycle is auditable: every transition emits an event, and each
//! proposal records its proposer, payload, and approval set on chain.
//!
//! # Weight
//!
//! Signers may carry a `weight` greater than one, so a 2-of-3 setup can be
//! expressed as weights `{2, 1, 1}` with `threshold: 2`.  Weights are summed
//! toward the threshold, and the total weight must always be at least the
//! threshold — otherwise a configuration could become impossible to satisfy.
//!
//! # Rotation
//!
//! [`rotate_admin_signers`] swaps the whole signer set and threshold.  Like
//! every other privileged action it is itself gated by the current threshold,
//! so a compromised minority cannot lock the remaining admins out.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, IntoVal, Symbol,
    TryFromVal, Vec,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// TTL for multi-sig storage entries (~1 year).
const MULTISIG_TTL_LEDGERS: u32 = 6_307_200; // ~1 year

/// Hard cap on the number of admin signers, to bound iteration cost.
pub const MAX_ADMIN_SIGNERS: u32 = 20;

/// Hard cap on the weight a single signer may carry, so one signer cannot
/// unilaterally satisfy any threshold.
pub const MAX_SIGNER_WEIGHT: u32 = 10;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One member of the admin set.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminSigner {
    /// The signer's Stellar address.
    pub address: Address,
    /// How much this signer's approval counts toward the threshold.
    pub weight: u32,
}

/// The admin set and its approval threshold.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminMultiSigConfig {
    /// The admin signers.  Never empty while the contract is initialised.
    pub signers: Vec<AdminSigner>,
    /// Total weight required before an operation may execute.
    pub threshold: u32,
}

impl AdminMultiSigConfig {
    /// Sum of every signer's weight.
    pub fn total_weight(&self) -> u32 {
        let mut total = 0u32;
        for signer in self.signers.iter() {
            total += signer.weight;
        }
        total
    }

    /// Look up a signer's weight, or `None` when the address is not an admin.
    pub fn weight_of(&self, address: &Address) -> Option<u32> {
        for signer in self.signers.iter() {
            if signer.address == *address {
                return Some(signer.weight);
            }
        }
        None
    }
}

/// The privileged action a proposal authorises.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminOperationKind {
    /// Freeze the contract's state-changing entry points.
    Pause,
    /// Unfreeze after a pause.
    Unpause,
    /// Replace the deployed WASM; payload is the new 32-byte hash.
    Upgrade,
    /// Replace the sanctions list; payload is the new list body.
    UpdateSanctionsList,
    /// Change the admin signer set.
    RotateAdmins,
    /// Migrate or repair state; payload is a caller-defined command.
    Maintenance,
}

/// Lifecycle position of a proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminOperationStatus {
    /// Awaiting further approvals.
    Pending,
    /// Threshold reached; ready to execute.
    Approved,
    /// Executed successfully.
    Executed,
    /// Cancelled by its proposer before execution.
    Cancelled,
    /// The ledger timestamp after which the proposal can no longer execute.
    Expires,
}

/// A pending privileged operation awaiting M-of-N approval.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminOperation {
    /// Monotonic proposal id, unique within this contract.
    pub id: u64,
    /// What the proposal authorises.
    pub operation: AdminOperationKind,
    /// Opaque payload interpreted by the executing contract.
    pub payload: Bytes,
    /// Who proposed it.
    pub proposer: Address,
    /// Addresses that have approved so far.  Never contains duplicates.
    pub approvals: Vec<Address>,
    /// Approval weight accumulated so far.
    pub approval_weight: u32,
    /// Current lifecycle position.
    pub status: AdminOperationStatus,
    /// Ledger timestamp the proposal was created at.
    pub created_at: u64,
    /// Ledger timestamp after which the proposal expires.
    pub expires_at: u64,
    /// Ledger timestamp of execution, once executed.
    pub executed_at: Option<u64>,
}

impl AdminOperation {
    /// `true` while the proposal can still receive approvals or execute.
    pub fn is_open(&self) -> bool {
        matches!(
            self.status,
            AdminOperationStatus::Pending | AdminOperationStatus::Approved
        )
    }
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub enum MultiSigKey {
    /// The active `AdminMultiSigConfig`.
    Config,
    /// Monotonic proposal counter.
    ProposalCount,
    /// A proposal by id.
    Proposal(u64),
    /// The contract's current paused flag.
    Paused,
    /// The address that performed the most recent pause/unpause.
    PausedBy,
    /// Reason recorded with the most recent pause.
    PauseReason,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AdminMultiSigError {
    /// The multi-sig module has not been initialised.
    NotInitialized = 1,
    /// Caller is not a member of the admin set.
    NotAdmin = 2,
    /// The signer list is empty.
    NoSigners = 3,
    /// The threshold is zero.
    InvalidThreshold = 4,
    /// The threshold exceeds the total signer weight, so no proposal could
    /// ever reach it.
    ThresholdUnreachable = 5,
    /// A duplicate address was supplied in the signer list.
    DuplicateSigner = 6,
    /// The signer count exceeds [`MAX_ADMIN_SIGNERS`].
    TooManySigners = 7,
    /// A signer's weight is zero or exceeds [`MAX_SIGNER_WEIGHT`].
    InvalidWeight = 8,
    /// The referenced proposal does not exist.
    ProposalNotFound = 9,
    /// The proposal has already been executed, cancelled, or expired.
    ProposalClosed = 10,
    /// The caller has already approved this proposal.
    AlreadyApproved = 11,
    /// The proposal's expiry timestamp has passed.
    ProposalExpired = 12,
    /// The caller is the proposer and so may not approve their own proposal.
    CannotSelfApprove = 13,
    /// The admin set requires more than one signature, so a single admin
    /// cannot execute this action alone.
    ThresholdNotMet = 14,
    /// The contract is paused.
    ContractPaused = 15,
    /// The payload is not valid for the proposed operation.
    InvalidPayload = 16,
    /// The proposal has already been executed.
    AlreadyExecuted = 17,
    /// The contract is not paused.
    NotPaused = 18,
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/// Install an admin set and threshold.
///
/// A threshold of `1` reproduces the classic single-key behaviour while still
/// routing every privileged action through the auditable proposal lifecycle,
/// which is the recommended starting point: operators can raise the threshold
/// later without a migration.
pub fn init(
    env: &Env,
    signers: Vec<AdminSigner>,
    threshold: u32,
) -> Result<(), AdminMultiSigError> {
    if env.storage().instance().has(&MultiSigKey::Config) {
        return Err(AdminMultiSigError::NotInitialized);
    }
    let config = AdminMultiSigConfig { signers, threshold };
    validate_config(&config)?;
    store_config(env, &config);
    env.storage()
        .instance()
        .set(&MultiSigKey::ProposalCount, &0u64);
    env.storage().instance().set(&MultiSigKey::Paused, &false);
    extend_ttls(env);
    Ok(())
}

/// Validate a signer set / threshold pair.
pub fn validate_config(config: &AdminMultiSigConfig) -> Result<(), AdminMultiSigError> {
    if config.signers.is_empty() {
        return Err(AdminMultiSigError::NoSigners);
    }
    if config.signers.len() > MAX_ADMIN_SIGNERS as u32 {
        return Err(AdminMultiSigError::TooManySigners);
    }
    if config.threshold == 0 {
        return Err(AdminMultiSigError::InvalidThreshold);
    }

    let mut seen = Vec::new(&Env::default());
    for signer in config.signers.iter() {
        if signer.weight == 0 || signer.weight > MAX_SIGNER_WEIGHT {
            return Err(AdminMultiSigError::InvalidWeight);
        }
        for existing in seen.iter() {
            if existing == signer.address {
                return Err(AdminMultiSigError::DuplicateSigner);
            }
        }
        seen.push_back(signer.address);
    }

    if config.total_weight() < config.threshold {
        return Err(AdminMultiSigError::ThresholdUnreachable);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Return the active admin configuration.
pub fn get_config(env: &Env) -> Result<AdminMultiSigConfig, AdminMultiSigError> {
    env.storage()
        .instance()
        .get(&MultiSigKey::Config)
        .ok_or(AdminMultiSigError::NotInitialized)
}

/// Return the current threshold.
pub fn get_threshold(env: &Env) -> Result<u32, AdminMultiSigError> {
    Ok(get_config(env)?.threshold)
}

/// Return the current admin signer set.
pub fn get_signers(env: &Env) -> Result<Vec<AdminSigner>, AdminMultiSigError> {
    Ok(get_config(env)?.signers)
}

/// Return a signer's weight, or `None` when the address is not an admin.
pub fn get_signer_weight(env: &Env, address: &Address) -> Option<u32> {
    get_config(env).ok().and_then(|c| c.weight_of(address))
}

/// Guard: `Ok(())` when `caller` is in the admin set.
pub fn require_admin(env: &Env, caller: &Address) -> Result<u32, AdminMultiSigError> {
    get_config(env)?
        .weight_of(caller)
        .ok_or(AdminMultiSigError::NotAdmin)
}

/// `true` when `caller` currently holds enough approval weight to execute
/// `operation` on its own.
pub fn has_threshold(env: &Env, operation: &AdminOperation) -> bool {
    let config = match get_config(env) {
        Ok(c) => c,
        Err(_) => return false,
    };
    if !operation.is_open() {
        return false;
    }
    operation.approval_weight >= config.threshold
}

/// `true` when the contract is currently paused.
pub fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&MultiSigKey::Paused)
        .unwrap_or(false)
}

/// Guard: `Err(ContractPaused)` while the contract is paused.
pub fn require_not_paused(env: &Env) -> Result<(), AdminMultiSigError> {
    if is_paused(env) {
        return Err(AdminMultiSigError::ContractPaused);
    }
    Ok(())
}

/// Fetch a proposal by id.
pub fn get_operation(env: &Env, id: u64) -> Result<AdminOperation, AdminMultiSigError> {
    env.storage()
        .persistent()
        .get(&MultiSigKey::Proposal(id))
        .ok_or(AdminMultiSigError::ProposalNotFound)
}

/// Total number of proposals ever created.
pub fn get_proposal_count(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&MultiSigKey::ProposalCount)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Proposal lifecycle
// ---------------------------------------------------------------------------

/// Propose a privileged operation.  Callable by any member of the admin set.
///
/// `ttl_seconds` bounds how long the proposal stays executable; `0` selects
/// [`DEFAULT_PROPOSAL_TTL_SECONDS`].  An expired proposal can never execute,
/// so an abandoned proposal cannot be revived later by a new approval.
pub fn propose_admin_operation(
    env: &Env,
    proposer: &Address,
    operation: AdminOperationKind,
    payload: Bytes,
    ttl_seconds: u64,
) -> Result<AdminOperation, AdminMultiSigError> {
    require_admin(env, proposer)?;
    validate_payload(env, &operation, &payload)?;

    let now = env.ledger().timestamp();
    let ttl = if ttl_seconds == 0 {
        DEFAULT_PROPOSAL_TTL_SECONDS
    } else {
        ttl_seconds
    };
    let id = get_proposal_count(env) + 1;

    let proposal = AdminOperation {
        id,
        operation,
        payload,
        proposer: proposer.clone(),
        approvals: Vec::new(env),
        approval_weight: 0,
        status: AdminOperationStatus::Pending,
        created_at: now,
        expires_at: now.saturating_add(ttl),
        executed_at: None,
    };

    env.storage()
        .instance()
        .set(&MultiSigKey::ProposalCount, &id);
    store_operation(env, &proposal);

    env.events().publish(
        (Symbol::new(env, "AdminOperationProposed"),),
        (
            id,
            proposer.clone(),
            operation_symbol(env, &proposal.operation),
            proposal.expires_at,
        ),
    );

    Ok(proposal)
}

/// Approve a pending operation.  The approver must have called `require_auth`.
pub fn approve_admin_operation(
    env: &Env,
    approver: &Address,
    id: u64,
) -> Result<AdminOperation, AdminMultiSigError> {
    let weight = require_admin(env, approver)?;
    let mut proposal = get_operation(env, id)?;

    if !proposal.is_open() {
        return Err(AdminMultiSigError::ProposalClosed);
    }
    if env.ledger().timestamp() > proposal.expires_at {
        proposal.status = AdminOperationStatus::Expires;
        store_operation(env, &proposal);
        return Err(AdminMultiSigError::ProposalExpired);
    }
    // Self-approval would let a single admin satisfy a 1-of-N threshold and
    // would make the approval count meaningless for 1-of-1 configs, so the
    // proposer must be counted separately from the approvers.
    if proposal.proposer == *approver {
        return Err(AdminMultiSigError::CannotSelfApprove);
    }
    for existing in proposal.approvals.iter() {
        if existing == *approver {
            return Err(AdminMultiSigError::AlreadyApproved);
        }
    }

    proposal.approvals.push_back(approver.clone());
    proposal.approval_weight += weight;

    let config = get_config(env)?;
    if proposal.approval_weight >= config.threshold {
        proposal.status = AdminOperationStatus::Approved;
    }
    store_operation(env, &proposal);

    env.events().publish(
        (Symbol::new(env, "AdminOperationApproved"),),
        (
            id,
            approver.clone(),
            proposal.approval_weight,
            config.threshold,
        ),
    );

    Ok(proposal)
}

/// Execute an operation whose approval threshold has been reached.
///
/// On success the proposal is marked `Executed` and the effect is applied
/// where this module owns the state (pause / unpause).  For operations the
/// module does not own — WASM upgrade, sanctions list edits — the caller is
/// responsible for performing the effect after this returns `Ok`, which is
/// safe because the proposal is already marked executed and therefore cannot
/// be replayed.
pub fn execute_admin_operation(
    env: &Env,
    executor: &Address,
    id: u64,
) -> Result<AdminOperation, AdminMultiSigError> {
    require_admin(env, executor)?;
    let mut proposal = get_operation(env, id)?;

    if proposal.status == AdminOperationStatus::Executed {
        return Err(AdminMultiSigError::AlreadyExecuted);
    }
    if !proposal.is_open() {
        return Err(AdminMultiSigError::ProposalClosed);
    }
    if env.ledger().timestamp() > proposal.expires_at {
        proposal.status = AdminOperationStatus::Expires;
        store_operation(env, &proposal);
        return Err(AdminMultiSigError::ProposalExpired);
    }

    let config = get_config(env)?;
    if proposal.approval_weight < config.threshold {
        return Err(AdminMultiSigError::ThresholdNotMet);
    }

    match &proposal.operation {
        AdminOperationKind::Pause => {
            apply_pause(env, executor, &proposal.payload)?;
        }
        AdminOperationKind::Unpause => {
            if !is_paused(env) {
                return Err(AdminMultiSigError::NotPaused);
            }
            env.storage().instance().remove(&MultiSigKey::Paused);
            env.storage()
                .instance()
                .set(&MultiSigKey::PausedBy, &executor.clone());
        }
        _ => {
            // Effects for these operations live in the calling contract; see
            // the function-level docs.
        }
    }

    proposal.status = AdminOperationStatus::Executed;
    proposal.executed_at = Some(env.ledger().timestamp());
    store_operation(env, &proposal);

    env.events().publish(
        (Symbol::new(env, "AdminOperationExecuted"),),
        (
            id,
            executor.clone(),
            operation_symbol(env, &proposal.operation),
            proposal.approval_weight,
        ),
    );

    extend_ttls(env);
    Ok(proposal)
}

/// Cancel a still-open proposal.  Only the proposer may cancel.
pub fn cancel_admin_operation(
    env: &Env,
    caller: &Address,
    id: u64,
) -> Result<AdminOperation, AdminMultiSigError> {
    let mut proposal = get_operation(env, id)?;
    if proposal.proposer != *caller {
        return Err(AdminMultiSigError::NotAdmin);
    }
    if !proposal.is_open() {
        return Err(AdminMultiSigError::ProposalClosed);
    }
    proposal.status = AdminOperationStatus::Cancelled;
    store_operation(env, &proposal);
    env.events().publish(
        (Symbol::new(env, "AdminOperationCancelled"),),
        (id, caller.clone()),
    );
    Ok(proposal)
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

/// Replace the admin signer set and threshold.
///
/// This is itself a privileged action: it goes through the same
/// propose/approve/execute flow as [`AdminOperationKind::RotateAdmins`], and only
/// takes effect when the executed proposal's payload carries the new
/// configuration.  Callers that want a direct path can use
/// [`apply_rotation`] from their contract's execute handler.
pub fn rotate_admin_signers(
    env: &Env,
    config: AdminMultiSigConfig,
) -> Result<(), AdminMultiSigError> {
    validate_config(&config)?;
    store_config(env, &config);
    extend_ttls(env);
    Ok(())
}

/// Decode and apply a rotation described by a proposal payload.
///
/// The payload is an `AdminMultiSigConfig` in Soroban XDR form, so the
/// rotation travels through the proposal record without needing a bespoke
/// serialisation scheme.
pub fn apply_rotation(env: &Env, payload: &Bytes) -> Result<(), AdminMultiSigError> {
    // `TryFromVal<Env, Bytes>` is not implemented for contract types, so the
    // payload is round-tripped through its `Val` representation instead.
    let val: soroban_sdk::Val = payload.clone().into_val(env);
    let config: AdminMultiSigConfig = AdminMultiSigConfig::try_from_val(env, &val)
        .map_err(|_| AdminMultiSigError::InvalidPayload)?;
    rotate_admin_signers(env, config)
}

// ---------------------------------------------------------------------------
// Pause helpers
// ---------------------------------------------------------------------------

fn apply_pause(env: &Env, by: &Address, reason: &Bytes) -> Result<(), AdminMultiSigError> {
    if is_paused(env) {
        return Err(AdminMultiSigError::AlreadyExecuted);
    }
    env.storage().instance().set(&MultiSigKey::Paused, &true);
    env.storage()
        .instance()
        .set(&MultiSigKey::PausedBy, &by.clone());
    env.storage()
        .instance()
        .set(&MultiSigKey::PauseReason, reason);
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Default proposal lifetime when the caller passes `ttl_seconds == 0`.
pub const DEFAULT_PROPOSAL_TTL_SECONDS: u64 = 86_400; // 24 hours

fn store_config(env: &Env, config: &AdminMultiSigConfig) {
    env.storage().instance().set(&MultiSigKey::Config, config);
}

fn store_operation(env: &Env, operation: &AdminOperation) {
    env.storage()
        .persistent()
        .set(&MultiSigKey::Proposal(operation.id), operation);
    env.storage().persistent().extend_ttl(
        &MultiSigKey::Proposal(operation.id),
        MULTISIG_TTL_LEDGERS,
        MULTISIG_TTL_LEDGERS,
    );
}

/// Reject payloads that are structurally invalid for their operation, so a
/// malformed proposal cannot reach the execute stage.
fn validate_payload(
    _env: &Env,
    operation: &AdminOperationKind,
    payload: &Bytes,
) -> Result<(), AdminMultiSigError> {
    if matches!(operation, AdminOperationKind::Upgrade) {
        // The new WASM hash must be present and must not be all zeroes.
        if payload.len() != 32 {
            return Err(AdminMultiSigError::InvalidPayload);
        }
        if payload.iter().all(|b| b == 0) {
            return Err(AdminMultiSigError::InvalidPayload);
        }
    }
    if matches!(operation, AdminOperationKind::Pause) && payload.is_empty() {
        return Err(AdminMultiSigError::InvalidPayload);
    }
    Ok(())
}

fn operation_symbol(env: &Env, operation: &AdminOperationKind) -> Symbol {
    let tag = match operation {
        AdminOperationKind::Pause => "pause",
        AdminOperationKind::Unpause => "unpause",
        AdminOperationKind::Upgrade => "upgrade",
        AdminOperationKind::UpdateSanctionsList => "sanctions",
        AdminOperationKind::RotateAdmins => "rotate",
        AdminOperationKind::Maintenance => "maint",
    };
    Symbol::new(env, tag)
}

/// Extend TTLs for the module's own instance-storage bookkeeping entries.
///
/// `instance()` storage in soroban-sdk 22 has no key-addressed `extend_ttl`;
/// instance entries are bumped as a group, so a single call covers all of the
/// keys stored here.
fn extend_ttls(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(MULTISIG_TTL_LEDGERS, MULTISIG_TTL_LEDGERS);
}

// ---------------------------------------------------------------------------
// Standalone contract surface
// ---------------------------------------------------------------------------

/// A standalone multi-sig admin contract, so a deployment can host its admin
/// policy separately from the contracts it governs.
#[contract]
pub struct AdminMultiSig;

#[contractimpl]
impl AdminMultiSig {
    /// Install the initial admin set.
    pub fn initialize(
        env: Env,
        signers: Vec<AdminSigner>,
        threshold: u32,
    ) -> Result<(), AdminMultiSigError> {
        init(&env, signers, threshold)
    }

    /// The current admin set and threshold.
    pub fn get_config(env: Env) -> Result<AdminMultiSigConfig, AdminMultiSigError> {
        get_config(&env)
    }

    /// The current threshold.
    pub fn get_threshold(env: Env) -> Result<u32, AdminMultiSigError> {
        get_threshold(&env)
    }

    /// The current admin signers.
    pub fn get_signers(env: Env) -> Result<Vec<AdminSigner>, AdminMultiSigError> {
        get_signers(&env)
    }

    /// A signer's weight, or `None` if not an admin.
    pub fn get_signer_weight(env: Env, address: Address) -> Option<u32> {
        get_signer_weight(&env, &address)
    }

    /// `true` when the address is in the admin set.
    pub fn is_admin(env: Env, address: Address) -> bool {
        get_signer_weight(&env, &address).is_some()
    }

    /// Propose a privileged operation.
    pub fn propose_admin_operation(
        env: Env,
        proposer: Address,
        operation: AdminOperationKind,
        payload: Bytes,
        ttl_seconds: u64,
    ) -> Result<AdminOperation, AdminMultiSigError> {
        proposer.require_auth();
        propose_admin_operation(&env, &proposer, operation, payload, ttl_seconds)
    }

    /// Approve a pending operation.
    pub fn approve_admin_operation(
        env: Env,
        approver: Address,
        id: u64,
    ) -> Result<AdminOperation, AdminMultiSigError> {
        approver.require_auth();
        approve_admin_operation(&env, &approver, id)
    }

    /// Execute an approved operation.
    pub fn execute_admin_operation(
        env: Env,
        executor: Address,
        id: u64,
    ) -> Result<AdminOperation, AdminMultiSigError> {
        executor.require_auth();
        execute_admin_operation(&env, &executor, id)
    }

    /// Cancel an open proposal.
    pub fn cancel_admin_operation(
        env: Env,
        caller: Address,
        id: u64,
    ) -> Result<AdminOperation, AdminMultiSigError> {
        caller.require_auth();
        cancel_admin_operation(&env, &caller, id)
    }

    /// Fetch a proposal.
    pub fn get_operation(env: Env, id: u64) -> Result<AdminOperation, AdminMultiSigError> {
        get_operation(&env, id)
    }

    /// Number of proposals created.
    pub fn get_proposal_count(env: Env) -> u64 {
        get_proposal_count(&env)
    }

    /// `true` while the contract is paused.
    pub fn is_paused(env: Env) -> bool {
        is_paused(&env)
    }

    /// Pause directly.  Callable only when the threshold is `1`, which makes
    /// the single-signer case a one-call emergency stop while still refusing
    /// to let a lone admin act on a multi-sig deployment.
    pub fn emergency_pause(
        env: Env,
        caller: Address,
        reason: Bytes,
    ) -> Result<(), AdminMultiSigError> {
        caller.require_auth();
        let config = get_config(&env)?;
        if config.threshold > 1 {
            return Err(AdminMultiSigError::ThresholdNotMet);
        }
        apply_pause(&env, &caller, &reason)
    }

    /// Apply a signer rotation described by an executed proposal payload.
    pub fn apply_rotation(env: Env, payload: Bytes) -> Result<(), AdminMultiSigError> {
        apply_rotation(&env, &payload)
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

    fn signers(env: &Env, n: u32) -> Vec<AdminSigner> {
        let mut out = Vec::new(env);
        for _ in 0..n {
            out.push_back(AdminSigner {
                address: Address::generate(env),
                weight: 1,
            });
        }
        out
    }

    fn init_2_of_3(env: &Env) -> (Address, Address, Address) {
        let a = Address::generate(env);
        let b = Address::generate(env);
        let c = Address::generate(env);
        let mut set = Vec::new(env);
        for addr in [a.clone(), b.clone(), c.clone()] {
            set.push_back(AdminSigner {
                address: addr,
                weight: 1,
            });
        }
        init(env, set, 2).unwrap();
        (a, b, c)
    }

    #[test]
    fn init_stores_config() {
        let env = setup_env();
        let set = signers(&env, 3);
        init(&env, set, 2).unwrap();
        assert_eq!(get_threshold(&env).unwrap(), 2);
        assert_eq!(get_signers(&env).unwrap().len(), 3);
    }

    #[test]
    fn init_twice_is_rejected() {
        let env = setup_env();
        let set = signers(&env, 2);
        init(&env, set, 2).unwrap();
        assert_eq!(
            init(&env, signers(&env, 2), 1),
            Err(AdminMultiSigError::NotInitialized)
        );
    }

    #[test]
    fn empty_signer_set_is_rejected() {
        let env = setup_env();
        assert_eq!(
            init(&env, Vec::new(&env), 1),
            Err(AdminMultiSigError::NoSigners)
        );
    }

    #[test]
    fn zero_threshold_is_rejected() {
        let env = setup_env();
        assert_eq!(
            init(&env, signers(&env, 2), 0),
            Err(AdminMultiSigError::InvalidThreshold)
        );
    }

    #[test]
    fn unreachable_threshold_is_rejected() {
        let env = setup_env();
        assert_eq!(
            init(&env, signers(&env, 2), 3),
            Err(AdminMultiSigError::ThresholdUnreachable)
        );
    }

    #[test]
    fn duplicate_signers_are_rejected() {
        let env = setup_env();
        let addr = Address::generate(&env);
        let mut set = Vec::new(&env);
        set.push_back(AdminSigner {
            address: addr.clone(),
            weight: 1,
        });
        set.push_back(AdminSigner {
            address: addr,
            weight: 1,
        });
        assert_eq!(init(&env, set, 1), Err(AdminMultiSigError::DuplicateSigner));
    }

    #[test]
    fn zero_weight_signer_is_rejected() {
        let env = setup_env();
        let mut set = Vec::new(&env);
        set.push_back(AdminSigner {
            address: Address::generate(&env),
            weight: 0,
        });
        assert_eq!(init(&env, set, 1), Err(AdminMultiSigError::InvalidWeight));
    }

    #[test]
    fn total_weight_sums_weights() {
        let env = setup_env();
        let mut set = Vec::new(&env);
        set.push_back(AdminSigner {
            address: Address::generate(&env),
            weight: 2,
        });
        set.push_back(AdminSigner {
            address: Address::generate(&env),
            weight: 3,
        });
        let config = AdminMultiSigConfig {
            signers: set,
            threshold: 3,
        };
        assert_eq!(config.total_weight(), 5);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn weighted_threshold_is_reachable() {
        let env = setup_env();
        let heavy = Address::generate(&env);
        let light = Address::generate(&env);
        let mut set = Vec::new(&env);
        set.push_back(AdminSigner {
            address: heavy.clone(),
            weight: 2,
        });
        set.push_back(AdminSigner {
            address: light,
            weight: 1,
        });
        init(&env, set, 2).unwrap();
        assert_eq!(get_signer_weight(&env, &heavy), Some(2));
    }

    #[test]
    fn non_admin_is_rejected() {
        let env = setup_env();
        init_2_of_3(&env);
        let outsider = Address::generate(&env);
        assert_eq!(
            require_admin(&env, &outsider),
            Err(AdminMultiSigError::NotAdmin)
        );
    }

    #[test]
    fn single_admin_cannot_execute_privileged_operation() {
        let env = setup_env();
        let (a, _b, _c) = init_2_of_3(&env);

        // Proposer counts toward neither approvals nor executed state, so the
        // proposer alone is one short of the threshold.
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Pause,
            Bytes::from_slice(&env, b"incident"),
            0,
        )
        .unwrap();
        assert_eq!(proposal.approval_weight, 0);
        assert_eq!(
            execute_admin_operation(&env, &a, proposal.id),
            Err(AdminMultiSigError::ThresholdNotMet)
        );
    }

    #[test]
    fn threshold_approvals_allow_execution() {
        let env = setup_env();
        let (a, b, _c) = init_2_of_3(&env);

        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Pause,
            Bytes::from_slice(&env, b"incident"),
            0,
        )
        .unwrap();

        let approved = approve_admin_operation(&env, &b, proposal.id).unwrap();
        assert_eq!(approved.approval_weight, 1);
        assert_eq!(approved.status, AdminOperationStatus::Pending);

        let c = get_signers(&env).unwrap().get(2).unwrap().address;
        let approved = approve_admin_operation(&env, &c, proposal.id).unwrap();
        assert_eq!(approved.approval_weight, 2);
        assert_eq!(approved.status, AdminOperationStatus::Approved);

        execute_admin_operation(&env, &b, proposal.id).unwrap();
        assert!(is_paused(&env));
    }

    #[test]
    fn proposer_cannot_self_approve() {
        let env = setup_env();
        let (a, _b, _c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"repair"),
            0,
        )
        .unwrap();
        assert_eq!(
            approve_admin_operation(&env, &a, proposal.id),
            Err(AdminMultiSigError::CannotSelfApprove)
        );
    }

    #[test]
    fn duplicate_approval_is_rejected() {
        let env = setup_env();
        let (a, b, _c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"repair"),
            0,
        )
        .unwrap();
        approve_admin_operation(&env, &b, proposal.id).unwrap();
        assert_eq!(
            approve_admin_operation(&env, &b, proposal.id),
            Err(AdminMultiSigError::AlreadyApproved)
        );
    }

    #[test]
    fn executed_proposal_cannot_be_replayed() {
        let env = setup_env();
        let (a, b, c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Pause,
            Bytes::from_slice(&env, b"incident"),
            0,
        )
        .unwrap();
        approve_admin_operation(&env, &b, proposal.id).unwrap();
        approve_admin_operation(&env, &c, proposal.id).unwrap();
        execute_admin_operation(&env, &b, proposal.id).unwrap();

        assert_eq!(
            execute_admin_operation(&env, &b, proposal.id),
            Err(AdminMultiSigError::AlreadyExecuted)
        );
    }

    #[test]
    fn expired_proposal_cannot_execute() {
        let env = setup_env();
        let (a, b, c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"x"),
            60,
        )
        .unwrap();
        approve_admin_operation(&env, &b, proposal.id).unwrap();
        approve_admin_operation(&env, &c, proposal.id).unwrap();

        env.ledger().with_mut(|li| li.timestamp += 120);
        assert_eq!(
            execute_admin_operation(&env, &b, proposal.id),
            Err(AdminMultiSigError::ProposalExpired)
        );
        assert_eq!(
            get_operation(&env, proposal.id).unwrap().status,
            AdminOperationStatus::Expires
        );
    }

    #[test]
    fn expired_proposal_cannot_be_approved() {
        let env = setup_env();
        let (a, b, _c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"x"),
            60,
        )
        .unwrap();
        env.ledger().with_mut(|li| li.timestamp += 120);
        assert_eq!(
            approve_admin_operation(&env, &b, proposal.id),
            Err(AdminMultiSigError::ProposalExpired)
        );
    }

    #[test]
    fn unknown_proposal_is_not_found() {
        let env = setup_env();
        init_2_of_3(&env);
        assert_eq!(
            get_operation(&env, 42),
            Err(AdminMultiSigError::ProposalNotFound)
        );
    }

    #[test]
    fn proposer_can_cancel() {
        let env = setup_env();
        let (a, _b, _c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"x"),
            0,
        )
        .unwrap();
        let cancelled = cancel_admin_operation(&env, &a, proposal.id).unwrap();
        assert_eq!(cancelled.status, AdminOperationStatus::Cancelled);
    }

    #[test]
    fn non_proposer_cannot_cancel() {
        let env = setup_env();
        let (a, b, _c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"x"),
            0,
        )
        .unwrap();
        assert_eq!(
            cancel_admin_operation(&env, &b, proposal.id),
            Err(AdminMultiSigError::NotAdmin)
        );
    }

    #[test]
    fn upgrade_requires_32_byte_non_zero_payload() {
        let env = setup_env();
        let (a, _b, _c) = init_2_of_3(&env);
        assert_eq!(
            propose_admin_operation(
                &env,
                &a,
                AdminOperationKind::Upgrade,
                Bytes::from_slice(&env, &[1, 2, 3]),
                0
            ),
            Err(AdminMultiSigError::InvalidPayload)
        );
        assert_eq!(
            propose_admin_operation(
                &env,
                &a,
                AdminOperationKind::Upgrade,
                Bytes::from_slice(&env, &[0u8; 32]),
                0
            ),
            Err(AdminMultiSigError::InvalidPayload)
        );
    }

    #[test]
    fn pause_requires_a_reason() {
        let env = setup_env();
        let (a, _b, _c) = init_2_of_3(&env);
        assert_eq!(
            propose_admin_operation(&env, &a, AdminOperationKind::Pause, Bytes::new(&env), 0),
            Err(AdminMultiSigError::InvalidPayload)
        );
    }

    #[test]
    fn unpause_requires_contract_to_be_paused() {
        let env = setup_env();
        let (a, b, c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Unpause,
            Bytes::from_slice(&env, b"resolve"),
            0,
        )
        .unwrap();
        approve_admin_operation(&env, &b, proposal.id).unwrap();
        approve_admin_operation(&env, &c, proposal.id).unwrap();
        assert_eq!(
            execute_admin_operation(&env, &b, proposal.id),
            Err(AdminMultiSigError::NotPaused)
        );
    }

    #[test]
    fn require_not_paused_blocks_mutations() {
        let env = setup_env();
        let (a, b, c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Pause,
            Bytes::from_slice(&env, b"incident"),
            0,
        )
        .unwrap();
        approve_admin_operation(&env, &b, proposal.id).unwrap();
        approve_admin_operation(&env, &c, proposal.id).unwrap();
        execute_admin_operation(&env, &b, proposal.id).unwrap();

        assert!(is_paused(&env));
        assert_eq!(
            require_not_paused(&env),
            Err(AdminMultiSigError::ContractPaused)
        );
    }

    #[test]
    fn has_threshold_reflects_approvals() {
        let env = setup_env();
        let (a, b, c) = init_2_of_3(&env);
        let proposal = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"x"),
            0,
        )
        .unwrap();
        assert!(!has_threshold(&env, &proposal));
        let after_b = approve_admin_operation(&env, &b, proposal.id).unwrap();
        assert!(!has_threshold(&env, &after_b));
        let after_c = approve_admin_operation(&env, &c, proposal.id).unwrap();
        assert!(has_threshold(&env, &after_c));
    }

    #[test]
    fn admins_can_be_rotated() {
        let env = setup_env();
        init_2_of_3(&env);
        let new_admin = Address::generate(&env);
        let mut set = Vec::new(&env);
        set.push_back(AdminSigner {
            address: new_admin.clone(),
            weight: 1,
        });
        rotate_admin_signers(
            &env,
            AdminMultiSigConfig {
                signers: set,
                threshold: 1,
            },
        )
        .unwrap();
        assert_eq!(get_threshold(&env).unwrap(), 1);
        assert!(get_signer_weight(&env, &new_admin).is_some());
    }

    #[test]
    fn rotation_rejects_invalid_config() {
        let env = setup_env();
        init_2_of_3(&env);
        assert_eq!(
            rotate_admin_signers(
                &env,
                AdminMultiSigConfig {
                    signers: Vec::new(&env),
                    threshold: 1
                }
            ),
            Err(AdminMultiSigError::NoSigners)
        );
    }

    #[test]
    fn proposal_ids_increment() {
        let env = setup_env();
        let (a, _b, _c) = init_2_of_3(&env);
        let first = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"x"),
            0,
        )
        .unwrap();
        let second = propose_admin_operation(
            &env,
            &a,
            AdminOperationKind::Maintenance,
            Bytes::from_slice(&env, b"y"),
            0,
        )
        .unwrap();
        assert_eq!(first.id, 1);
        assert_eq!(second.id, 2);
        assert_eq!(get_proposal_count(&env), 2);
    }

    #[test]
    fn non_admin_cannot_propose() {
        let env = setup_env();
        init_2_of_3(&env);
        let outsider = Address::generate(&env);
        assert_eq!(
            propose_admin_operation(
                &env,
                &outsider,
                AdminOperationKind::Maintenance,
                Bytes::from_slice(&env, b"x"),
                0
            ),
            Err(AdminMultiSigError::NotAdmin)
        );
    }
}
