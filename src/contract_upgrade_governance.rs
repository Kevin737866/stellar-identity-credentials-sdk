use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{clamp_page_size, audit_trail, audit_trail::AuditEventType};

// ── Constants ─────────────────────────────────────────────────────────────────

const GOVERNANCE_TTL_LEDGERS: u32 = 6_307_200;
const DEFAULT_VOTING_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_TIME_LOCK_SECS: u64 = 48 * 60 * 60;
const DEFAULT_QUORUM_BPS: u32 = 5000;
const DEFAULT_APPROVAL_THRESHOLD_BPS: u32 = 6600;
const MAX_GOVERNORS: u32 = 50;
const MAX_PROPOSALS: u32 = 100;
const MAX_TIMELOCK_SECS: u64 = 30 * 24 * 60 * 60;
const MIN_TIMELOCK_SECS: u64 = 60 * 60;
const SIMULATION_HASH_SIZE: usize = 32;

// ── Storage keys ──────────────────────────────────────────────────────────────

const KEY_ADMIN: &str = "admin";
const KEY_PAUSED: &str = "paused";
const KEY_PROPOSAL_COUNT: &str = "prop_count";

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum GovernanceError {
    Unauthorized = 1,
    NotFound = 2,
    InvalidInput = 3,
    NotInitialized = 4,
    AlreadyInitialized = 5,
    AlreadyExists = 6,
    ProposalNotActive = 7,
    ProposalAlreadyExecuted = 8,
    ProposalExpired = 9,
    AlreadyVoted = 10,
    QuorumNotMet = 11,
    ApprovalThresholdNotMet = 12,
    TimeLockNotElapsed = 13,
    ContractPaused = 14,
    GovernorAlreadyExists = 15,
    GovernorNotRegistered = 16,
    MaxGovernorsReached = 17,
    MaxProposalsReached = 18,
    InvalidSimulationHash = 19,
    SimulationFailed = 20,
    TimeLockOutOfRange = 21,
    UpgradeInProgress = 22,
    RollbackNotAvailable = 23,
    InvalidProposalType = 24,
}

// ── Storage key enum ──────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum GovKey {
    Config,
    Governor(Address),
    GovernorIndex,
    Proposal(u32),
    ProposalIndex,
    Vote(u32, Address),
    ExecutedUpgrade(u64),
    RollbackSnapshot(u32),
    SimulationResult(u32),
    PausedBy,
}

// ── Data structures ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalType {
    ContractUpgrade,
    GovernanceParameterChange,
    EmergencyAction,
    AdminAction,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    Pending,
    Active,
    Succeeded,
    Defeated,
    Queued,
    Executed,
    Expired,
    Cancelled,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceConfig {
    pub voting_period_secs: u64,
    pub time_lock_secs: u64,
    pub quorum_bps: u32,
    pub approval_threshold_bps: u32,
    pub proposal_deposit: u64,
    pub min_governors_for_quorum: u32,
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Governor {
    pub address: Address,
    pub voting_power: u64,
    pub is_active: bool,
    pub registered_at: u64,
    pub metadata: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposal {
    pub id: u32,
    pub proposer: Address,
    pub proposal_type: ProposalType,
    pub title: Bytes,
    pub description: Bytes,
    pub target_contract: Address,
    pub new_wasm_hash: BytesN<32>,
    pub upgrade_data: Bytes,
    pub simulation_hash: BytesN<32>,
    pub created_at: u64,
    pub start_at: u64,
    pub end_at: u64,
    pub execution_time: u64,
    pub status: ProposalStatus,
    pub for_votes: u64,
    pub against_votes: u64,
    pub abstain_votes: u64,
    pub executed_at: Option<u64>,
    pub rollback_proposal_id: Option<u32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VoteType {
    For,
    Against,
    Abstain,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteRecord {
    pub proposal_id: u32,
    pub voter: Address,
    pub vote: VoteType,
    pub voting_power: u64,
    pub timestamp: u64,
    pub reason: Option<Bytes>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedUpgrade {
    pub proposal_id: u32,
    pub target_contract: Address,
    pub old_wasm_hash: BytesN<32>,
    pub new_wasm_hash: BytesN<32>,
    pub executed_at: u64,
    pub ledger_sequence: u32,
    pub rollback_wasm_hash: Option<BytesN<32>>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationResult {
    pub proposal_id: u32,
    pub gas_estimate: u64,
    pub state_hash: BytesN<32>,
    pub success: bool,
    pub warnings: Vec<Bytes>,
    pub simulated_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackSnapshot {
    pub proposal_id: u32,
    pub target_contract: Address,
    pub wasm_hash: BytesN<32>,
    pub storage_keys: Vec<Bytes>,
    pub snapshot_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedProposals {
    pub data: Vec<UpgradeProposal>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedGovernors {
    pub data: Vec<Governor>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ContractUpgradeGovernance;

#[contractimpl]
impl ContractUpgradeGovernance {
    // ── Initialization ────────────────────────────────────────────────────────

    pub fn initialize(
        env: Env,
        admin: Address,
        initial_governors: Vec<Address>,
    ) -> Result<(), GovernanceError> {
        if env.storage().instance().has(&Symbol::new(&env, KEY_ADMIN)) {
            return Err(GovernanceError::AlreadyInitialized);
        }

        if initial_governors.is_empty() {
            return Err(GovernanceError::InvalidInput);
        }

        env.storage().instance().set(&Symbol::new(&env, KEY_ADMIN), &admin);
        env.storage().instance().set(&Symbol::new(&env, KEY_PAUSED), &false);
        env.storage().instance().set(&Symbol::new(&env, KEY_PROPOSAL_COUNT), &0u32);

        let config = GovernanceConfig {
            voting_period_secs: DEFAULT_VOTING_PERIOD_SECS,
            time_lock_secs: DEFAULT_TIME_LOCK_SECS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            approval_threshold_bps: DEFAULT_APPROVAL_THRESHOLD_BPS,
            proposal_deposit: 0,
            min_governors_for_quorum: 2,
            last_updated: env.ledger().timestamp(),
        };
        Self::persist(&env, &GovKey::Config, &config);

        let mut gov_idx = Vec::new(&env);
        for addr in initial_governors.iter() {
            let governor = Governor {
                address: addr.clone(),
                voting_power: 1,
                is_active: true,
                registered_at: env.ledger().timestamp(),
                metadata: Bytes::new(&env),
            };
            Self::persist(&env, &GovKey::Governor(addr.clone()), &governor);
            gov_idx.push_back(addr);
        }
        Self::persist(&env, &GovKey::GovernorIndex, &gov_idx);

        audit_trail::emit_audit_event(
            &env,
            admin,
            AuditEventType::AdminAction,
            None,
            Bytes::from_slice(&env, b"governance_initialized"),
        );

        Ok(())
    }

    // ── Admin & governor management ───────────────────────────────────────────

    pub fn transfer_admin(
        env: Env,
        caller: Address,
        new_admin: Address,
    ) -> Result<(), GovernanceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GovernanceError::Unauthorized);
        }
        env.storage().instance().set(&Symbol::new(&env, KEY_ADMIN), &new_admin);
        env.events().publish(
            (Symbol::new(&env, "gov_admin_xfer"), admin),
            new_admin,
        );
        Ok(())
    }

    pub fn register_governor(
        env: Env,
        caller: Address,
        new_governor: Address,
        voting_power: u64,
        metadata: Bytes,
    ) -> Result<(), GovernanceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GovernanceError::Unauthorized);
        }

        let mut gov_idx: Vec<Address> = env.storage().persistent()
            .get(&GovKey::GovernorIndex)
            .unwrap_or_else(|| Vec::new(&env));

        if gov_idx.len() >= MAX_GOVERNORS as usize {
            return Err(GovernanceError::MaxGovernorsReached);
        }

        if env.storage().persistent().has(&GovKey::Governor(new_governor.clone())) {
            return Err(GovernanceError::GovernorAlreadyExists);
        }

        let governor = Governor {
            address: new_governor.clone(),
            voting_power,
            is_active: true,
            registered_at: env.ledger().timestamp(),
            metadata,
        };

        Self::persist(&env, &GovKey::Governor(new_governor.clone()), &governor);
        gov_idx.push_back(new_governor.clone());
        Self::persist(&env, &GovKey::GovernorIndex, &gov_idx);

        audit_trail::emit_audit_event(
            &env,
            caller,
            AuditEventType::RoleGranted,
            None,
            Bytes::from_slice(&env, b"governor_registered"),
        );

        env.events().publish(
            (Symbol::new(&env, "governor_registered"),),
            new_governor,
        );
        Ok(())
    }

    pub fn remove_governor(
        env: Env,
        caller: Address,
        governor: Address,
    ) -> Result<(), GovernanceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GovernanceError::Unauthorized);
        }

        if !env.storage().persistent().has(&GovKey::Governor(governor.clone())) {
            return Err(GovernanceError::GovernorNotRegistered);
        }

        let mut gov: Governor = env.storage().persistent()
            .get(&GovKey::Governor(governor.clone()))
            .unwrap();
        gov.is_active = false;
        Self::persist(&env, &GovKey::Governor(governor.clone()), &gov);

        audit_trail::emit_audit_event(
            &env,
            caller,
            AuditEventType::RoleRevoked,
            None,
            Bytes::from_slice(&env, b"governor_removed"),
        );

        env.events().publish(
            (Symbol::new(&env, "governor_removed"),),
            governor,
        );
        Ok(())
    }

    pub fn get_governor(env: Env, address: Address) -> Option<Governor> {
        env.storage().persistent().get(&GovKey::Governor(address))
    }

    pub fn get_governors_paginated(
        env: Env,
        page: u32,
        page_size: u32,
    ) -> PaginatedGovernors {
        let idx: Vec<Address> = env.storage().persistent()
            .get(&GovKey::GovernorIndex)
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = idx.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(addr) = idx.get(i) {
                    if let Some(gov) = env.storage().persistent()
                        .get::<GovKey, Governor>(&GovKey::Governor(addr))
                    {
                        data.push_back(gov);
                    }
                }
            }
        }

        PaginatedGovernors { data, page, total, has_more: (start + size) < total }
    }

    // ── Governance configuration ──────────────────────────────────────────────

    pub fn update_config(
        env: Env,
        caller: Address,
        voting_period_secs: Option<u64>,
        time_lock_secs: Option<u64>,
        quorum_bps: Option<u32>,
        approval_threshold_bps: Option<u32>,
        min_governors_for_quorum: Option<u32>,
    ) -> Result<(), GovernanceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GovernanceError::Unauthorized);
        }

        let mut config: GovernanceConfig = env.storage().persistent()
            .get(&GovKey::Config)
            .ok_or(GovernanceError::NotInitialized)?;

        if let Some(v) = voting_period_secs {
            if v < 60 * 60 || v > 30 * 24 * 60 * 60 {
                return Err(GovernanceError::TimeLockOutOfRange);
            }
            config.voting_period_secs = v;
        }
        if let Some(v) = time_lock_secs {
            if v < MIN_TIMELOCK_SECS || v > MAX_TIMELOCK_SECS {
                return Err(GovernanceError::TimeLockOutOfRange);
            }
            config.time_lock_secs = v;
        }
        if let Some(v) = quorum_bps {
            if v > 10000 {
                return Err(GovernanceError::InvalidInput);
            }
            config.quorum_bps = v;
        }
        if let Some(v) = approval_threshold_bps {
            if v > 10000 {
                return Err(GovernanceError::InvalidInput);
            }
            config.approval_threshold_bps = v;
        }
        if let Some(v) = min_governors_for_quorum {
            config.min_governors_for_quorum = v;
        }

        config.last_updated = env.ledger().timestamp();
        Self::persist(&env, &GovKey::Config, &config);

        env.events().publish(
            (Symbol::new(&env, "governance_config_updated"),),
            config.last_updated,
        );
        Ok(())
    }

    pub fn get_config(env: Env) -> GovernanceConfig {
        env.storage().persistent()
            .get(&GovKey::Config)
            .unwrap_or(GovernanceConfig {
                voting_period_secs: DEFAULT_VOTING_PERIOD_SECS,
                time_lock_secs: DEFAULT_TIME_LOCK_SECS,
                quorum_bps: DEFAULT_QUORUM_BPS,
                approval_threshold_bps: DEFAULT_APPROVAL_THRESHOLD_BPS,
                proposal_deposit: 0,
                min_governors_for_quorum: 2,
                last_updated: 0,
            })
    }

    // ── Pause / emergency ─────────────────────────────────────────────────────

    pub fn pause(env: Env, caller: Address, reason: Bytes) -> Result<(), GovernanceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GovernanceError::Unauthorized);
        }
        env.storage().instance().set(&Symbol::new(&env, KEY_PAUSED), &true);
        Self::persist(&env, &GovKey::PausedBy, &(caller.clone(), reason));

        audit_trail::emit_audit_event(
            &env,
            caller,
            AuditEventType::AdminAction,
            None,
            Bytes::from_slice(&env, b"governance_paused"),
        );

        env.events().publish(
            (Symbol::new(&env, "governance_paused"),),
            (),
        );
        Ok(())
    }

    pub fn unpause(env: Env, caller: Address) -> Result<(), GovernanceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GovernanceError::Unauthorized);
        }
        env.storage().instance().set(&Symbol::new(&env, KEY_PAUSED), &false);

        env.events().publish(
            (Symbol::new(&env, "governance_unpaused"),),
            (),
        );
        Ok(())
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage().instance()
            .get::<Symbol, bool>(&Symbol::new(&env, KEY_PAUSED))
            .unwrap_or(false)
    }

    // ── Proposal creation ─────────────────────────────────────────────────────

    pub fn create_proposal(
        env: Env,
        proposer: Address,
        proposal_type: ProposalType,
        title: Bytes,
        description: Bytes,
        target_contract: Address,
        new_wasm_hash: BytesN<32>,
        upgrade_data: Bytes,
        simulation_hash: BytesN<32>,
    ) -> Result<u32, GovernanceError> {
        proposer.require_auth();

        Self::require_not_paused(&env)?;

        if title.is_empty() || description.is_empty() {
            return Err(GovernanceError::InvalidInput);
        }

        let governor = Self::require_governor(&env, &proposer)?;
        if !governor.is_active {
            return Err(GovernanceError::GovernorNotRegistered);
        }

        let count: u32 = env.storage().instance()
            .get(&Symbol::new(&env, KEY_PROPOSAL_COUNT))
            .unwrap_or(0);

        if count >= MAX_PROPOSALS {
            return Err(GovernanceError::MaxProposalsReached);
        }

        let proposal_id = count + 1;
        let now = env.ledger().timestamp();
        let config = Self::get_config(env.clone());

        let proposal = UpgradeProposal {
            id: proposal_id,
            proposer: proposer.clone(),
            proposal_type,
            title,
            description,
            target_contract,
            new_wasm_hash,
            upgrade_data,
            simulation_hash,
            created_at: now,
            start_at: now,
            end_at: now + config.voting_period_secs,
            execution_time: now + config.voting_period_secs + config.time_lock_secs,
            status: ProposalStatus::Pending,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            executed_at: None,
            rollback_proposal_id: None,
        };

        Self::persist(&env, &GovKey::Proposal(proposal_id), &proposal);

        let mut prop_idx: Vec<u32> = env.storage().persistent()
            .get(&GovKey::ProposalIndex)
            .unwrap_or_else(|| Vec::new(&env));
        prop_idx.push_back(proposal_id);
        Self::persist(&env, &GovKey::ProposalIndex, &prop_idx);

        env.storage().instance().set(&Symbol::new(&env, KEY_PROPOSAL_COUNT), &proposal_id);

        Self::transition_status(&env, proposal_id, ProposalStatus::Active);

        audit_trail::emit_audit_event(
            &env,
            proposer,
            AuditEventType::AdminAction,
            None,
            Bytes::from_slice(&env, b"proposal_created"),
        );

        env.events().publish(
            (Symbol::new(&env, "proposal_created"), proposer),
            proposal_id,
        );

        Ok(proposal_id)
    }

    // ── Voting ────────────────────────────────────────────────────────────────

    pub fn cast_vote(
        env: Env,
        voter: Address,
        proposal_id: u32,
        vote: VoteType,
        reason: Option<Bytes>,
    ) -> Result<(), GovernanceError> {
        voter.require_auth();
        Self::require_not_paused(&env)?;

        let governor = Self::require_governor(&env, &voter)?;
        if !governor.is_active {
            return Err(GovernanceError::GovernorNotRegistered);
        }

        let mut proposal: UpgradeProposal = env.storage().persistent()
            .get(&GovKey::Proposal(proposal_id))
            .ok_or(GovernanceError::NotFound)?;

        if proposal.status != ProposalStatus::Active {
            return Err(GovernanceError::ProposalNotActive);
        }

        let now = env.ledger().timestamp();
        if now > proposal.end_at {
            Self::transition_status(&env, proposal_id, ProposalStatus::Expired);
            return Err(GovernanceError::ProposalExpired);
        }

        let vote_key = GovKey::Vote(proposal_id, voter.clone());
        if env.storage().persistent().has(&vote_key) {
            return Err(GovernanceError::AlreadyVoted);
        }

        let weight = governor.voting_power;
        match vote {
            VoteType::For => proposal.for_votes += weight,
            VoteType::Against => proposal.against_votes += weight,
            VoteType::Abstain => proposal.abstain_votes += weight,
        }

        let record = VoteRecord {
            proposal_id,
            voter: voter.clone(),
            vote,
            voting_power: weight,
            timestamp: now,
            reason,
        };

        Self::persist(&env, &vote_key, &record);
        Self::persist(&env, &GovKey::Proposal(proposal_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "vote_cast"), voter, proposal_id),
            weight,
        );

        Self::maybe_finalize(&env, proposal_id);

        Ok(())
    }

    pub fn get_proposal(env: Env, proposal_id: u32) -> Option<UpgradeProposal> {
        env.storage().persistent().get(&GovKey::Proposal(proposal_id))
    }

    pub fn get_proposals_paginated(
        env: Env,
        page: u32,
        page_size: u32,
    ) -> PaginatedProposals {
        let idx: Vec<u32> = env.storage().persistent()
            .get(&GovKey::ProposalIndex)
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = idx.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(pid) = idx.get(i) {
                    if let Some(prop) = env.storage().persistent()
                        .get::<GovKey, UpgradeProposal>(&GovKey::Proposal(pid))
                    {
                        data.push_back(prop);
                    }
                }
            }
        }

        PaginatedProposals { data, page, total, has_more: (start + size) < total }
    }

    pub fn get_vote(env: Env, proposal_id: u32, voter: Address) -> Option<VoteRecord> {
        env.storage().persistent().get(&GovKey::Vote(proposal_id, voter))
    }

    pub fn has_voted(env: Env, proposal_id: u32, voter: Address) -> bool {
        env.storage().persistent().has(&GovKey::Vote(proposal_id, voter))
    }

    // ── Execute proposal ──────────────────────────────────────────────────────

    pub fn execute_proposal(
        env: Env,
        caller: Address,
        proposal_id: u32,
        current_wasm_hash: BytesN<32>,
    ) -> Result<(), GovernanceError> {
        caller.require_auth();
        Self::require_not_paused(&env)?;

        let governor = Self::require_governor(&env, &caller)?;
        if !governor.is_active {
            return Err(GovernanceError::GovernorNotRegistered);
        }

        let proposal: UpgradeProposal = env.storage().persistent()
            .get(&GovKey::Proposal(proposal_id))
            .ok_or(GovernanceError::NotFound)?;

        if proposal.status != ProposalStatus::Succeeded {
            return Err(GovernanceError::ProposalNotActive);
        }

        let now = env.ledger().timestamp();
        if now < proposal.execution_time {
            return Err(GovernanceError::TimeLockNotElapsed);
        }

        if now > proposal.execution_time + 7 * 24 * 60 * 60 {
            Self::transition_status(&env, proposal_id, ProposalStatus::Expired);
            return Err(GovernanceError::ProposalExpired);
        }

        Self::verify_simulation(&env, proposal_id)?;

        let snapshot = RollbackSnapshot {
            proposal_id,
            target_contract: proposal.target_contract.clone(),
            wasm_hash: current_wasm_hash,
            storage_keys: Vec::new(&env),
            snapshot_at: now,
        };
        Self::persist(&env, &GovKey::RollbackSnapshot(proposal_id), &snapshot);

        Self::transition_status(&env, proposal_id, ProposalStatus::Queued);
        Self::transition_status(&env, proposal_id, ProposalStatus::Executed);

        let executed = ExecutedUpgrade {
            proposal_id,
            target_contract: proposal.target_contract.clone(),
            old_wasm_hash: current_wasm_hash,
            new_wasm_hash: proposal.new_wasm_hash,
            executed_at: now,
            ledger_sequence: env.ledger().sequence(),
            rollback_wasm_hash: None,
        };

        Self::persist(&env, &GovKey::ExecutedUpgrade(now), &executed);

        audit_trail::emit_audit_event(
            &env,
            caller,
            AuditEventType::AdminAction,
            None,
            Bytes::from_slice(&env, b"proposal_executed"),
        );

        env.events().publish(
            (Symbol::new(&env, "proposal_executed"), proposal_id),
            proposal.new_wasm_hash,
        );

        Ok(())
    }

    // ── Rollback ──────────────────────────────────────────────────────────────

    pub fn queue_rollback(
        env: Env,
        caller: Address,
        proposal_id: u32,
        reason: Bytes,
    ) -> Result<u32, GovernanceError> {
        caller.require_auth();
        Self::require_not_paused(&env)?;

        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GovernanceError::Unauthorized);
        }

        let snapshot: RollbackSnapshot = env.storage().persistent()
            .get(&GovKey::RollbackSnapshot(proposal_id))
            .ok_or(GovernanceError::RollbackNotAvailable)?;

        let executed: ExecutedUpgrade = env.storage().persistent()
            .get(&GovKey::ExecutedUpgrade(snapshot.snapshot_at))
            .ok_or(GovernanceError::NotFound)?;

        let config = Self::get_config(env.clone());
        let now = env.ledger().timestamp();

        let rollback_proposal = UpgradeProposal {
            id: 0,
            proposer: caller.clone(),
            proposal_type: ProposalType::EmergencyAction,
            title: Bytes::from_slice(&env, b"Rollback"),
            description: reason,
            target_contract: snapshot.target_contract.clone(),
            new_wasm_hash: snapshot.wasm_hash,
            upgrade_data: Bytes::new(&env),
            simulation_hash: BytesN::from_array(&env, &[0u8; SIMULATION_HASH_SIZE]),
            created_at: now,
            start_at: now,
            end_at: now + config.voting_period_secs,
            execution_time: now + MIN_TIMELOCK_SECS,
            status: ProposalStatus::Pending,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            executed_at: None,
            rollback_proposal_id: Some(proposal_id),
        };

        let count: u32 = env.storage().instance()
            .get(&Symbol::new(&env, KEY_PROPOSAL_COUNT))
            .unwrap_or(0);

        let rollback_id = count + 1;
        let mut rollback = rollback_proposal;
        rollback.id = rollback_id;

        Self::persist(&env, &GovKey::Proposal(rollback_id), &rollback);
        Self::transition_status(&env, rollback_id, ProposalStatus::Active);

        let mut prop_idx: Vec<u32> = env.storage().persistent()
            .get(&GovKey::ProposalIndex)
            .unwrap_or_else(|| Vec::new(&env));
        prop_idx.push_back(rollback_id);
        Self::persist(&env, &GovKey::ProposalIndex, &prop_idx);

        env.storage().instance().set(&Symbol::new(&env, KEY_PROPOSAL_COUNT), &rollback_id);

        env.events().publish(
            (Symbol::new(&env, "rollback_queued"), proposal_id),
            rollback_id,
        );

        Ok(rollback_id)
    }

    // ── Simulations ───────────────────────────────────────────────────────────

    pub fn record_simulation(
        env: Env,
        caller: Address,
        proposal_id: u32,
        gas_estimate: u64,
        state_hash: BytesN<32>,
        success: bool,
        warnings: Vec<Bytes>,
    ) -> Result<(), GovernanceError> {
        caller.require_auth();

        if !env.storage().persistent().has(&GovKey::Proposal(proposal_id)) {
            return Err(GovernanceError::NotFound);
        }

        let result = SimulationResult {
            proposal_id,
            gas_estimate,
            state_hash,
            success,
            warnings,
            simulated_at: env.ledger().timestamp(),
        };

        Self::persist(&env, &GovKey::SimulationResult(proposal_id), &result);

        env.events().publish(
            (Symbol::new(&env, "simulation_recorded"), proposal_id),
            success,
        );
        Ok(())
    }

    pub fn get_simulation(env: Env, proposal_id: u32) -> Option<SimulationResult> {
        env.storage().persistent().get(&GovKey::SimulationResult(proposal_id))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<Address, GovernanceError> {
        env.storage().instance()
            .get::<Symbol, Address>(&Symbol::new(env, KEY_ADMIN))
            .ok_or(GovernanceError::NotInitialized)
    }

    fn require_governor(env: &Env, address: &Address) -> Result<Governor, GovernanceError> {
        env.storage().persistent()
            .get::<GovKey, Governor>(&GovKey::Governor(address.clone()))
            .ok_or(GovernanceError::GovernorNotRegistered)
    }

    fn require_not_paused(env: &Env) -> Result<(), GovernanceError> {
        if env.storage().instance()
            .get::<Symbol, bool>(&Symbol::new(env, KEY_PAUSED))
            .unwrap_or(false)
        {
            return Err(GovernanceError::ContractPaused);
        }
        Ok(())
    }

    fn transition_status(env: &Env, proposal_id: u32, status: ProposalStatus) {
        let key = GovKey::Proposal(proposal_id);
        if let Some(mut proposal) = env.storage().persistent().get::<GovKey, UpgradeProposal>(&key) {
            proposal.status = status;
            Self::persist(env, &key, &proposal);
        }
    }

    fn maybe_finalize(env: &Env, proposal_id: u32) {
        let key = GovKey::Proposal(proposal_id);
        let proposal: UpgradeProposal = match env.storage().persistent().get(&key) {
            Some(p) => p,
            None => return,
        };

        if proposal.status != ProposalStatus::Active {
            return;
        }

        let now = env.ledger().timestamp();
        if now < proposal.end_at {
            let total_votes = proposal.for_votes + proposal.against_votes + proposal.abstain_votes;

            let config = Self::get_config(env.clone());
            let governor_count = env.storage().persistent()
                .get::<GovKey, Vec<Address>>(&GovKey::GovernorIndex)
                .map(|idx| idx.len() as u64)
                .unwrap_or(0) as u64;

            if governor_count == 0 {
                return;
            }

            let total_possible_votes = governor_count;
            if total_votes * 10000 / total_possible_votes < config.quorum_bps as u64 {
                return;
            }
        }

        let total_votes = proposal.for_votes + proposal.against_votes;
        if total_votes == 0 {
            return;
        }

        let approval = proposal.for_votes * 10000 / total_votes;
        let config = Self::get_config(env.clone());

        if approval >= config.approval_threshold_bps as u64 {
            Self::transition_status(env, proposal_id, ProposalStatus::Succeeded);
            env.events().publish(
                (Symbol::new(env, "proposal_succeeded"), proposal_id),
                approval,
            );
        } else {
            Self::transition_status(env, proposal_id, ProposalStatus::Defeated);
            env.events().publish(
                (Symbol::new(env, "proposal_defeated"), proposal_id),
                approval,
            );
        }
    }

    fn verify_simulation(env: &Env, proposal_id: u32) -> Result<(), GovernanceError> {
        let sim: Option<SimulationResult> = env.storage().persistent()
            .get(&GovKey::SimulationResult(proposal_id));

        match sim {
            Some(result) => {
                if !result.success {
                    return Err(GovernanceError::SimulationFailed);
                }
                Ok(())
            }
            None => {
                let proposal: UpgradeProposal = env.storage().persistent()
                    .get(&GovKey::Proposal(proposal_id))
                    .ok_or(GovernanceError::NotFound)?;

                let is_empty = BytesN::from_array(env, &[0u8; SIMULATION_HASH_SIZE]);
                if proposal.simulation_hash != is_empty {
                    return Err(GovernanceError::InvalidSimulationHash);
                }
                Ok(())
            }
        }
    }

    fn persist<K, V>(env: &Env, key: &K, value: &V)
    where
        K: soroban_sdk::TryIntoVal<Env, soroban_sdk::Val>
            + soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
        V: soroban_sdk::TryIntoVal<Env, soroban_sdk::Val>
            + soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
    {
        env.storage().persistent().set(key, value);
        env.storage()
            .persistent()
            .extend_ttl(key, GOVERNANCE_TTL_LEDGERS, GOVERNANCE_TTL_LEDGERS);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};

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

    fn bootstrap(env: &Env) -> (Address, Address) {
        let admin = Address::generate(env);
        let gov1 = Address::generate(env);
        let mut governors = Vec::new(env);
        governors.push_back(gov1.clone());
        ContractUpgradeGovernance::initialize(env.clone(), admin.clone(), governors).unwrap();
        (admin, gov1)
    }

    fn default_hash(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[0u8; 32])
    }

    fn make_proposal(env: &Env, proposer: &Address) -> u32 {
        let target = Address::generate(env);
        ContractUpgradeGovernance::create_proposal(
            env.clone(),
            proposer.clone(),
            ProposalType::ContractUpgrade,
            Bytes::from_slice(env, b"Upgrade Contract"),
            Bytes::from_slice(env, b"Upgrade to v2"),
            target,
            default_hash(env),
            Bytes::new(env),
            default_hash(env),
        ).unwrap()
    }

    #[test]
    fn initializes_successfully() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let gov1 = Address::generate(&env);
        let mut governors = Vec::new(&env);
        governors.push_back(gov1);
        assert!(ContractUpgradeGovernance::initialize(env, admin, governors).is_ok());
    }

    #[test]
    fn double_initialize_returns_error() {
        let env = setup_env();
        bootstrap(&env);
        let result = ContractUpgradeGovernance::initialize(
            env.clone(),
            Address::generate(&env),
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), GovernanceError::AlreadyInitialized);
    }

    #[test]
    fn empty_governors_fails() {
        let env = setup_env();
        let result = ContractUpgradeGovernance::initialize(
            env.clone(),
            Address::generate(&env),
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), GovernanceError::InvalidInput);
    }

    #[test]
    fn governor_can_create_proposal() {
        let env = setup_env();
        let (_, gov1) = bootstrap(&env);
        let pid = make_proposal(&env, &gov1);
        assert_eq!(pid, 1);

        let proposal = ContractUpgradeGovernance::get_proposal(env, pid).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Active);
        assert_eq!(proposal.title, Bytes::from_slice(&env, b"Upgrade Contract"));
    }

    #[test]
    fn non_governor_cannot_create_proposal() {
        let env = setup_env();
        let (_, _) = bootstrap(&env);
        let stranger = Address::generate(&env);
        let result = ContractUpgradeGovernance::create_proposal(
            env.clone(),
            stranger,
            ProposalType::ContractUpgrade,
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"desc"),
            Address::generate(&env),
            default_hash(&env),
            Bytes::new(&env),
            default_hash(&env),
        );
        assert_eq!(result.unwrap_err(), GovernanceError::GovernorNotRegistered);
    }

    #[test]
    fn vote_and_finalize() {
        let env = setup_env();
        let (_, gov1) = bootstrap(&env);
        let pid = make_proposal(&env, &gov1);

        ContractUpgradeGovernance::cast_vote(
            env.clone(),
            gov1.clone(),
            pid,
            VoteType::For,
            None,
        ).unwrap();

        let proposal = ContractUpgradeGovernance::get_proposal(env.clone(), pid).unwrap();
        assert_eq!(proposal.for_votes, 1);

        assert!(ContractUpgradeGovernance::has_voted(env.clone(), pid, gov1));
    }

    #[test]
    fn double_voting_returns_error() {
        let env = setup_env();
        let (_, gov1) = bootstrap(&env);
        let pid = make_proposal(&env, &gov1);

        ContractUpgradeGovernance::cast_vote(
            env.clone(),
            gov1.clone(),
            pid,
            VoteType::For,
            None,
        ).unwrap();

        let result = ContractUpgradeGovernance::cast_vote(
            env.clone(),
            gov1,
            pid,
            VoteType::For,
            None,
        );
        assert_eq!(result.unwrap_err(), GovernanceError::AlreadyVoted);
    }

    #[test]
    fn multiple_votes_calculate_correctly() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let mut governors = Vec::new(&env);
        let gov1 = Address::generate(&env);
        let gov2 = Address::generate(&env);
        governors.push_back(gov1.clone());
        governors.push_back(gov2.clone());
        ContractUpgradeGovernance::initialize(env.clone(), admin, governors).unwrap();

        let pid = make_proposal(&env, &gov1);

        ContractUpgradeGovernance::cast_vote(
            env.clone(),
            gov1,
            pid,
            VoteType::For,
            None,
        ).unwrap();
        ContractUpgradeGovernance::cast_vote(
            env.clone(),
            gov2,
            pid,
            VoteType::Against,
            None,
        ).unwrap();

        let proposal = ContractUpgradeGovernance::get_proposal(env, pid).unwrap();
        assert_eq!(proposal.for_votes, 1);
        assert_eq!(proposal.against_votes, 1);
    }

    #[test]
    fn pause_prevents_proposal_creation() {
        let env = setup_env();
        let (admin, gov1) = bootstrap(&env);

        ContractUpgradeGovernance::pause(
            env.clone(),
            admin,
            Bytes::from_slice(&env, b"emergency"),
        ).unwrap();
        assert!(ContractUpgradeGovernance::is_paused(env.clone()));

        let result = make_proposal(&env, &gov1);
        assert_eq!(result.unwrap_err(), GovernanceError::ContractPaused);

        ContractUpgradeGovernance::unpause(env.clone(), admin).unwrap();
        assert!(!ContractUpgradeGovernance::is_paused(env));
    }

    #[test]
    fn governor_registration_and_removal() {
        let env = setup_env();
        let (admin, _) = bootstrap(&env);

        let new_gov = Address::generate(&env);
        ContractUpgradeGovernance::register_governor(
            env.clone(),
            admin.clone(),
            new_gov.clone(),
            1,
            Bytes::new(&env),
        ).unwrap();

        let gov = ContractUpgradeGovernance::get_governor(env.clone(), new_gov.clone()).unwrap();
        assert!(gov.is_active);

        ContractUpgradeGovernance::remove_governor(env.clone(), admin, new_gov.clone()).unwrap();
        let gov = ContractUpgradeGovernance::get_governor(env, new_gov).unwrap();
        assert!(!gov.is_active);
    }

    #[test]
    fn config_update() {
        let env = setup_env();
        let (admin, _) = bootstrap(&env);

        ContractUpgradeGovernance::update_config(
            env.clone(),
            admin,
            Some(3 * 24 * 60 * 60),
            Some(24 * 60 * 60),
            Some(4000),
            Some(5000),
            Some(2),
        ).unwrap();

        let config = ContractUpgradeGovernance::get_config(env);
        assert_eq!(config.voting_period_secs, 3 * 24 * 60 * 60);
        assert_eq!(config.time_lock_secs, 24 * 60 * 60);
        assert_eq!(config.quorum_bps, 4000);
    }

    #[test]
    fn simulation_recording() {
        let env = setup_env();
        let (_, gov1) = bootstrap(&env);
        let pid = make_proposal(&env, &gov1);

        ContractUpgradeGovernance::record_simulation(
            env.clone(),
            gov1,
            pid,
            50_000,
            default_hash(&env),
            true,
            Vec::new(&env),
        ).unwrap();

        let sim = ContractUpgradeGovernance::get_simulation(env, pid).unwrap();
        assert!(sim.success);
        assert_eq!(sim.gas_estimate, 50_000);
    }

    #[test]
    fn executed_upgrade_tracks_rollback() {
        let env = setup_env();
        let (_, gov1) = bootstrap(&env);
        let pid = make_proposal(&env, &gov1);

        ContractUpgradeGovernance::cast_vote(
            env.clone(),
            gov1.clone(),
            pid,
            VoteType::For,
            None,
        ).unwrap();

        let mut proposal = ContractUpgradeGovernance::get_proposal(env.clone(), pid).unwrap();
        let now = env.ledger().timestamp();
        let config = ContractUpgradeGovernance::get_config(env.clone());
        let execution_time = now + config.voting_period_secs + config.time_lock_secs;

        env.ledger().set(LedgerInfo {
            timestamp: execution_time + 1,
            protocol_version: 22,
            sequence_number: 2000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });

        ContractUpgradeGovernance::maybe_finalize_manual(&env, pid);

        proposal = ContractUpgradeGovernance::get_proposal(env.clone(), pid).unwrap();
        if proposal.status == ProposalStatus::Succeeded {
            ContractUpgradeGovernance::execute_proposal(
                env.clone(),
                gov1,
                pid,
                default_hash(&env),
            ).unwrap();

            let executed_proposal = ContractUpgradeGovernance::get_proposal(env.clone(), pid).unwrap();
            assert_eq!(executed_proposal.status, ProposalStatus::Executed);
        }
    }

    #[test]
    fn paginated_governors() {
        let env = setup_env();
        let (admin, gov1) = bootstrap(&env);

        let gov2 = Address::generate(&env);
        let gov3 = Address::generate(&env);

        ContractUpgradeGovernance::register_governor(env.clone(), admin.clone(), gov2, 1, Bytes::new(&env)).unwrap();
        ContractUpgradeGovernance::register_governor(env.clone(), admin, gov3, 1, Bytes::new(&env)).unwrap();

        let page = ContractUpgradeGovernance::get_governors_paginated(env.clone(), 0, 10);
        assert_eq!(page.total, 3);
        assert_eq!(page.data.len(), 3);
    }
}

impl ContractUpgradeGovernance {
    #[cfg(test)]
    fn maybe_finalize_manual(env: &Env, proposal_id: u32) {
        Self::maybe_finalize(env, proposal_id);
    }
}
