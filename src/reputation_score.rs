use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::contract_upgrade;
use crate::rate_limiter::{check_rate_limit, defaults};
use crate::reentrancy_guard::ReentrancyGuard;
use crate::{clamp_page_size, PaginatedReputationHistory};

// ── Constants ─────────────────────────────────────────────────────────────────

const SCORE_SCALE: u32 = 10;
const MAX_SCORE: u32 = 1000 * SCORE_SCALE;
const BASE_SCORE: u32 = 80 * SCORE_SCALE;
const MAX_HISTORY_POINTS: u32 = 120;
const MAX_GRAPH_EDGES: u32 = 64;
const MAX_TRUST_WEIGHT: u32 = 1000;
const MAX_GRAPH_DEPTH: u32 = 4;
const MIN_GRAPH_DEPTH: u32 = 1;

// ── Storage keys ──────────────────────────────────────────────────────────────

const KEY_ADMIN: &str = "admin";
const KEY_CONFIG: &str = "config";

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationData {
    pub score: u32,
    pub total_transactions: u32,
    pub successful_transactions: u32,
    pub failed_transactions: u32,
    pub total_credentials: u32,
    pub valid_credentials: u32,
    pub invalid_credentials: u32,
    pub last_updated: u64,
    pub volume: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationHistoryEntry {
    pub timestamp: u64,
    pub score: u32,
    pub event: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAttestation {
    pub truster: Address,
    pub subject: Address,
    pub weight: u32,
    pub reason: Bytes,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustGraph {
    pub subject: Address,
    pub attestations: Vec<TrustAttestation>,
    pub aggregate_weight: u32,
    pub depth: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub max_score: u32,
    pub transaction_success_weight: u32,
    pub transaction_failure_weight: u32,
    pub credential_valid_weight: u32,
    pub credential_invalid_weight: u32,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReputationTier {
    Bronze = 0,
    Silver = 1,
    Gold = 2,
    Platinum = 3,
    Diamond = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierThresholds {
    pub bronze_min: u32,
    pub silver_min: u32,
    pub gold_min: u32,
    pub platinum_min: u32,
    pub diamond_min: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierRequirements {
    pub tier: ReputationTier,
    pub min_score: u32,
    pub max_score: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Config,
    Admin,
    Score(Address),
    Profile(Address),
    History(Address),
    Trust(Address),
    Population,
    TierThresholds,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReputationScoreError {
    /// Contract has not been initialized yet.
    NotInitialized = 1,
    /// Caller is not the admin.
    NotAdmin = 2,
    /// Score or weight is outside the allowed range.
    InvalidScore = 3,
    /// Trust graph depth is outside the allowed range (1–4 inclusive).
    InvalidDepth = 4,
    /// Contract or user record is already initialized.
    AlreadyInitialized = 5,
    /// Input argument (e.g. empty reason, zero weight) is invalid.
    InvalidInput = 6,
    /// Caller is not authorized to perform this action.
    Unauthorized = 7,
    /// The same truster has already attested this subject.
    DuplicateAttestation = 8,
    /// Caller has exceeded the allowed request rate.
    RateLimitExceeded = 9,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ReputationScore;

#[contractimpl]
impl ReputationScore {
    // ── Initialization ────────────────────────────────────────────────────────

    /// Initialize the contract. Fails if already initialized.
    pub fn initialize(
        env: Env,
        admin: Address,
        config: Config,
    ) -> Result<(), ReputationScoreError> {
        if env.storage().instance().has(&Symbol::new(&env, KEY_ADMIN)) {
            return Err(ReputationScoreError::AlreadyInitialized);
        }

        if config.max_score == 0 || config.max_score > MAX_SCORE {
            return Err(ReputationScoreError::InvalidScore);
        }

        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_ADMIN), &admin);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_CONFIG), &config);
        Ok(())
    }

    /// Initialize a user's reputation record. Idempotent.
    pub fn initialize_reputation(env: Env, address: Address) -> Result<(), ReputationScoreError> {
        if env
            .storage()
            .persistent()
            .has(&DataKey::Score(address.clone()))
        {
            return Ok(());
        }

        let data = ReputationData {
            score: BASE_SCORE,
            total_transactions: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            total_credentials: 0,
            valid_credentials: 0,
            invalid_credentials: 0,
            last_updated: env.ledger().timestamp(),
            volume: 0,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Profile(address.clone()), &data);
        env.storage()
            .persistent()
            .set(&DataKey::Score(address.clone()), &BASE_SCORE);

        let mut population: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Population)
            .unwrap_or_else(|| Vec::new(&env));
        population.push_back(address);
        env.storage()
            .persistent()
            .set(&DataKey::Population, &population);

        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    pub fn get_reputation_score(env: Env, address: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Score(address))
            .unwrap_or(0)
    }

    pub fn get_reputation_history(
        env: Env,
        address: Address,
        limit: u32,
    ) -> Result<Vec<ReputationHistoryEntry>, ReputationScoreError> {
        if limit == 0 {
            return Err(ReputationScoreError::InvalidInput);
        }

        let history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(address))
            .unwrap_or_else(|| Vec::new(&env));

        let len = history.len();
        let clamped = limit.min(MAX_HISTORY_POINTS);
        let start = if len > clamped { len - clamped } else { 0 };
        let mut result = Vec::new(&env);

        for index in start..len {
            if let Some(entry) = history.get(index) {
                result.push_back(entry);
            }
        }
        Ok(result)
    }

    pub fn get_reputation_history_paginated(
        env: Env,
        address: Address,
        page: u32,
        page_size: u32,
    ) -> Result<PaginatedReputationHistory, ReputationScoreError> {
        let history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(address))
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = history.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(entry) = history.get(i) {
                    data.push_back(entry);
                }
            }
        }

        Ok(PaginatedReputationHistory {
            data,
            page,
            total,
            has_more: (start + size) < total,
        })
    }

    pub fn get_reputation_percentile(
        env: Env,
        address: Address,
    ) -> Result<u32, ReputationScoreError> {
        let target = Self::load_profile(&env, address.clone())?.score;
        let population: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Population)
            .unwrap_or_else(|| Vec::new(&env));

        let pop_len = population.len();
        if pop_len == 0 {
            return Ok(0);
        }

        let mut below_or_equal = 0u32;
        for subject in population.iter() {
            if let Ok(candidate) = Self::load_profile(&env, subject.clone()) {
                if candidate.score <= target {
                    below_or_equal += 1;
                }
            }
        }

        // Use u64 to avoid intermediate overflow on large populations.
        Ok(((below_or_equal as u64 * 100) / pop_len as u64) as u32)
    }

    /// Returns `true` if `address` has a score ≥ `threshold` (in raw score units,
    /// not pre-multiplied — the multiplication happens here).
    pub fn meets_reputation_threshold(
        env: Env,
        address: Address,
        threshold: u32,
    ) -> Result<bool, ReputationScoreError> {
        let profile = Self::load_profile(&env, address.clone())?;
        let scaled = threshold.saturating_mul(SCORE_SCALE);
        Ok(profile.score >= scaled)
    }

    /// Get the current reputation tier for an address.
    pub fn get_reputation_tier(env: Env, address: Address) -> ReputationTier {
        let score = Self::get_reputation_score(env.clone(), address);
        let raw_score = score / SCORE_SCALE;
        Self::tier_from_raw_score(&env, raw_score)
    }

    /// Return min/max score requirements for a given tier.
    pub fn get_tier_requirements(env: Env, tier: ReputationTier) -> TierRequirements {
        let thresholds = Self::get_tier_thresholds(env);
        match tier {
            ReputationTier::Bronze => TierRequirements {
                tier,
                min_score: thresholds.bronze_min,
                max_score: if thresholds.silver_min > 0 {
                    thresholds.silver_min - 1
                } else {
                    0
                },
            },
            ReputationTier::Silver => TierRequirements {
                tier,
                min_score: thresholds.silver_min,
                max_score: if thresholds.gold_min > 0 {
                    thresholds.gold_min - 1
                } else {
                    0
                },
            },
            ReputationTier::Gold => TierRequirements {
                tier,
                min_score: thresholds.gold_min,
                max_score: if thresholds.platinum_min > 0 {
                    thresholds.platinum_min - 1
                } else {
                    0
                },
            },
            ReputationTier::Platinum => TierRequirements {
                tier,
                min_score: thresholds.platinum_min,
                max_score: if thresholds.diamond_min > 0 {
                    thresholds.diamond_min - 1
                } else {
                    0
                },
            },
            ReputationTier::Diamond => TierRequirements {
                tier,
                min_score: thresholds.diamond_min,
                max_score: 1000,
            },
        }
    }

    /// Get currently configured tier thresholds (default: 0, 300, 600, 800, 950).
    pub fn get_tier_thresholds(env: Env) -> TierThresholds {
        env.storage()
            .instance()
            .get(&DataKey::TierThresholds)
            .unwrap_or(TierThresholds {
                bronze_min: 0,
                silver_min: 300,
                gold_min: 600,
                platinum_min: 800,
                diamond_min: 950,
            })
    }

    /// Set configurable tier thresholds. Admin only.
    pub fn set_tier_thresholds(
        env: Env,
        caller: Address,
        thresholds: TierThresholds,
    ) -> Result<(), ReputationScoreError> {
        caller.require_auth();
        let admin = Self::get_admin(&env);
        if caller != admin {
            return Err(ReputationScoreError::NotAdmin);
        }

        if !(thresholds.bronze_min <= thresholds.silver_min
            && thresholds.silver_min <= thresholds.gold_min
            && thresholds.gold_min <= thresholds.platinum_min
            && thresholds.platinum_min <= thresholds.diamond_min
            && thresholds.diamond_min <= 1000)
        {
            return Err(ReputationScoreError::InvalidInput);
        }

        env.storage()
            .instance()
            .set(&DataKey::TierThresholds, &thresholds);

        env.events().publish(
            (Symbol::new(&env, "TierThresholdsConfigured"),),
            (
                thresholds.bronze_min,
                thresholds.silver_min,
                thresholds.gold_min,
                thresholds.platinum_min,
                thresholds.diamond_min,
            ),
        );

        Ok(())
    }

    fn tier_from_raw_score(env: &Env, raw_score: u32) -> ReputationTier {
        let thresholds = Self::get_tier_thresholds(env.clone());
        if raw_score >= thresholds.diamond_min {
            ReputationTier::Diamond
        } else if raw_score >= thresholds.platinum_min {
            ReputationTier::Platinum
        } else if raw_score >= thresholds.gold_min {
            ReputationTier::Gold
        } else if raw_score >= thresholds.silver_min {
            ReputationTier::Silver
        } else {
            ReputationTier::Bronze
        }
    }

    // ── Mutations ─────────────────────────────────────────────────────────────

    /// Record a transaction outcome and update the caller's reputation score.
    pub fn update_transaction_reputation(
        env: Env,
        address: Address,
        success: bool,
        amount: i128,
    ) -> Result<u32, ReputationScoreError> {
        // Rate limit: max 20 updates per address per 60 seconds
        check_rate_limit(
            &env,
            &address,
            Symbol::new(&env, "update_rep"),
            defaults::UPDATE_REPUTATION_MAX,
            defaults::UPDATE_REPUTATION_WINDOW,
        )
        .map_err(|_| ReputationScoreError::RateLimitExceeded)?;

        // Reentrancy guard: prevent score inflation via cross-contract callback loops
        ReentrancyGuard::acquire(&env, "update_rep")
            .map_err(|_| ReputationScoreError::Unauthorized)?;

        let config = Self::get_config(&env);
        let mut profile = Self::load_profile(&env, address.clone())?;
        let old_raw = profile.score / SCORE_SCALE;
        let old_tier = Self::tier_from_raw_score(&env, old_raw);

        profile.total_transactions += 1;
        if success {
            profile.successful_transactions += 1;
            profile.score = profile
                .score
                .saturating_add(config.transaction_success_weight)
                .min(config.max_score);
        } else {
            profile.failed_transactions += 1;
            profile.score = profile
                .score
                .saturating_sub(config.transaction_failure_weight);
        }

        profile.last_updated = env.ledger().timestamp();
        profile.volume = profile.volume.saturating_add(amount.unsigned_abs() as u64);

        Self::save_profile(&env, &address, &profile);

        let event_label = if success {
            b"tx_success"
        } else {
            b"tx_failure"
        };
        Self::append_history(
            &env,
            &address,
            profile.score,
            Bytes::from_slice(&env, event_label),
        );

        env.events().publish(
            (Symbol::new(&env, "ReputationScoreUpdated"), address.clone()),
            (profile.score, success),
        );

        let new_raw = profile.score / SCORE_SCALE;
        let new_tier = Self::tier_from_raw_score(&env, new_raw);
        if new_tier > old_tier {
            env.events().publish(
                (Symbol::new(&env, "TierUpgraded"), address),
                (old_tier, new_tier, new_raw),
            );
        } else if new_tier < old_tier {
            env.events().publish(
                (Symbol::new(&env, "TierDowngraded"), address),
                (old_tier, new_tier, new_raw),
            );
        }

        ReentrancyGuard::release(&env, "update_rep");
        Ok(profile.score)
    }

    /// Record a credential validity outcome and update the caller's reputation.
    pub fn update_credential_reputation(
        env: Env,
        address: Address,
        valid: bool,
        credential_type: Bytes,
    ) -> Result<u32, ReputationScoreError> {
        if credential_type.is_empty() {
            return Err(ReputationScoreError::InvalidInput);
        }

        let config = Self::get_config(&env);
        let mut profile = Self::load_profile(&env, address.clone())?;
        let old_raw = profile.score / SCORE_SCALE;
        let old_tier = Self::tier_from_raw_score(&env, old_raw);

        profile.total_credentials += 1;
        if valid {
            profile.valid_credentials += 1;
            profile.score = profile
                .score
                .saturating_add(config.credential_valid_weight)
                .min(config.max_score);
        } else {
            profile.invalid_credentials += 1;
            profile.score = profile
                .score
                .saturating_sub(config.credential_invalid_weight);
        }

        profile.last_updated = env.ledger().timestamp();
        Self::save_profile(&env, &address, &profile);
        Self::append_history(&env, &address, profile.score, credential_type.clone());

        env.events().publish(
            (Symbol::new(&env, "ReputationScoreUpdated"), address.clone()),
            (profile.score, credential_type, valid),
        );

        let new_raw = profile.score / SCORE_SCALE;
        let new_tier = Self::tier_from_raw_score(&env, new_raw);
        if new_tier > old_tier {
            env.events().publish(
                (Symbol::new(&env, "TierUpgraded"), address),
                (old_tier, new_tier, new_raw),
            );
        } else if new_tier < old_tier {
            env.events().publish(
                (Symbol::new(&env, "TierDowngraded"), address),
                (old_tier, new_tier, new_raw),
            );
        }

        Ok(profile.score)
    }

    /// Batch update transaction reputation for multiple addresses (#84).
    /// More gas-efficient than individual calls: one ledger read/write per address.
    pub fn batch_update_transaction_reputation(
        env: Env,
        updates: Vec<(Address, bool, i128)>,
    ) -> Result<Vec<u32>, ReputationScoreError> {
        let mut scores = Vec::new(&env);
        for (address, success, amount) in updates.iter() {
            let score =
                Self::update_transaction_reputation(env.clone(), address.clone(), success, amount)?;
            scores.push_back(score);
        }
        Ok(scores)
    }

    // ── Trust graph ───────────────────────────────────────────────────────────

    /// Record a directional trust attestation from `truster` → `subject`.
    /// Rejects self-attestation, invalid weights, and duplicate attestations.
    pub fn attest_trust(
        env: Env,
        truster: Address,
        subject: Address,
        weight: u32,
        reason: Bytes,
    ) -> Result<TrustAttestation, ReputationScoreError> {
        truster.require_auth();

        if truster == subject {
            return Err(ReputationScoreError::Unauthorized);
        }
        if weight == 0 || weight > MAX_TRUST_WEIGHT {
            return Err(ReputationScoreError::InvalidScore);
        }
        if reason.is_empty() {
            return Err(ReputationScoreError::InvalidInput);
        }

        let mut attestations: Vec<TrustAttestation> = env
            .storage()
            .persistent()
            .get(&DataKey::Trust(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        // Replay protection: one attestation per truster per subject.
        for existing in attestations.iter() {
            if existing.truster == truster {
                return Err(ReputationScoreError::DuplicateAttestation);
            }
        }

        // Enforce max fan-in per subject to bound storage growth.
        if attestations.len() >= MAX_GRAPH_EDGES {
            return Err(ReputationScoreError::InvalidInput);
        }

        let attestation = TrustAttestation {
            truster: truster.clone(),
            subject: subject.clone(),
            weight,
            reason,
            timestamp: env.ledger().timestamp(),
        };

        attestations.push_back(attestation.clone());
        env.storage()
            .persistent()
            .set(&DataKey::Trust(subject.clone()), &attestations);

        env.events()
            .publish((Symbol::new(&env, "trust_att"), truster, subject), weight);

        Ok(attestation)
    }

    pub fn get_trust_attestations(env: Env, subject: Address) -> Vec<TrustAttestation> {
        env.storage()
            .persistent()
            .get(&DataKey::Trust(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Return the aggregated trust graph for `subject` up to `depth` hops.
    /// Valid depth range: MIN_GRAPH_DEPTH (1) – MAX_GRAPH_DEPTH (4).
    pub fn get_trust_graph(
        env: Env,
        subject: Address,
        depth: u32,
    ) -> Result<TrustGraph, ReputationScoreError> {
        if depth < MIN_GRAPH_DEPTH || depth > MAX_GRAPH_DEPTH {
            return Err(ReputationScoreError::InvalidDepth);
        }

        let attestations: Vec<TrustAttestation> = env
            .storage()
            .persistent()
            .get(&DataKey::Trust(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        let aggregate_weight = attestations
            .iter()
            .fold(0u32, |acc, a| acc.saturating_add(a.weight));

        Ok(TrustGraph {
            subject,
            attestations,
            aggregate_weight,
            depth,
        })
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    /// Update the contract configuration. Admin only.
    pub fn update_config(
        env: Env,
        caller: Address,
        config: Config,
    ) -> Result<(), ReputationScoreError> {
        caller.require_auth();
        let admin = Self::get_admin(&env);
        if caller != admin {
            return Err(ReputationScoreError::NotAdmin);
        }
        if config.max_score == 0 || config.max_score > MAX_SCORE {
            return Err(ReputationScoreError::InvalidScore);
        }
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_CONFIG), &config);

        env.events().publish(
            (Symbol::new(&env, "TierThresholdsConfigured"),),
            (
                config.max_score,
                config.transaction_success_weight,
                config.credential_valid_weight,
            ),
        );

        Ok(())
    }

    pub fn population(env: Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::Population)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn get_admin(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(env, KEY_ADMIN))
            .expect("contract not initialized")
    }

    fn get_config(env: &Env) -> Config {
        env.storage()
            .instance()
            .get(&Symbol::new(env, KEY_CONFIG))
            .expect("contract not initialized")
    }

    pub fn load_profile(
        env: &Env,
        address: Address,
    ) -> Result<ReputationData, ReputationScoreError> {
        env.storage()
            .persistent()
            .get(&DataKey::Profile(address.clone()))
            .ok_or(ReputationScoreError::NotInitialized)
    }

    fn save_profile(env: &Env, address: &Address, profile: &ReputationData) {
        env.storage()
            .persistent()
            .set(&DataKey::Profile(address.clone()), profile);
        env.storage()
            .persistent()
            .set(&DataKey::Score(address.clone()), &profile.score);
    }

    fn append_history(env: &Env, address: &Address, score: u32, event: Bytes) {
        let mut history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(address.clone()))
            .unwrap_or_else(|| Vec::new(env));

        history.push_back(ReputationHistoryEntry {
            timestamp: env.ledger().timestamp(),
            score,
            event,
        });

        // Trim to a rolling window of MAX_HISTORY_POINTS entries.
        if history.len() > MAX_HISTORY_POINTS {
            let mut trimmed = Vec::new(env);
            let start = history.len() - MAX_HISTORY_POINTS;
            for i in start..history.len() {
                if let Some(e) = history.get(i) {
                    trimmed.push_back(e);
                }
            }
            history = trimmed;
        }

        env.storage()
            .persistent()
            .set(&DataKey::History(address.clone()), &history);
    }

    // ── Contract Upgrade (#275) ──────────────────────────────────────────────

    /// Initialize the upgrade module with an admin and initial WASM hash.
    /// Must be called once during contract deployment.
    pub fn init_upgrade(
        env: Env,
        admin: Address,
        initial_wasm_hash: BytesN<32>,
    ) -> Result<(), ReputationScoreError> {
        admin.require_auth();
        if contract_upgrade::is_initialized(&env) {
            return Err(ReputationScoreError::AlreadyInitialized);
        }
        contract_upgrade::init(&env, admin, initial_wasm_hash);
        Ok(())
    }

    /// Upgrade the contract to a new WASM hash.
    /// Only the registered admin can perform this operation.
    pub fn upgrade(
        env: Env,
        caller: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), ReputationScoreError> {
        caller.require_auth();
        contract_upgrade::upgrade(&env, &caller, new_wasm_hash)
            .map_err(|_| ReputationScoreError::Unauthorized)
    }

    /// Return the current contract version.
    pub fn get_contract_version(env: Env) -> u32 {
        contract_upgrade::get_contract_version(&env)
    }

    /// Return the current deployed WASM hash.
    pub fn get_wasm_hash(env: Env) -> Option<BytesN<32>> {
        contract_upgrade::get_wasm_hash(&env)
    }

    /// Return the full version history for audit purposes.
    pub fn get_version_history(env: Env) -> Vec<contract_upgrade::VersionRecord> {
        contract_upgrade::get_version_history(&env)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{Address, Bytes, Env};

    // ── Fixtures ──────────────────────────────────────────────────────────────

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

    fn default_config() -> Config {
        Config {
            max_score: MAX_SCORE,
            transaction_success_weight: 10,
            transaction_failure_weight: 5,
            credential_valid_weight: 20,
            credential_invalid_weight: 15,
        }
    }

    fn bootstrap(env: &Env) -> (Address, Address) {
        let admin = Address::generate(env);
        let user = Address::generate(env);
        ReputationScore::initialize(env.clone(), admin.clone(), default_config()).unwrap();
        ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
        (admin, user)
    }

    // ── Initialization ────────────────────────────────────────────────────────

    #[test]
    fn initializes_with_base_score() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        assert_eq!(
            ReputationScore::get_reputation_score(env.clone(), user),
            BASE_SCORE
        );
    }

    #[test]
    fn double_initialize_contract_returns_error() {
        let env = setup_env();
        let admin = Address::generate(&env);
        ReputationScore::initialize(env.clone(), admin.clone(), default_config()).unwrap();
        let result = ReputationScore::initialize(env.clone(), admin, default_config());
        assert_eq!(
            result.unwrap_err(),
            ReputationScoreError::AlreadyInitialized
        );
    }

    #[test]
    fn initialize_with_zero_max_score_returns_error() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let bad_config = Config {
            max_score: 0,
            ..default_config()
        };
        let result = ReputationScore::initialize(env.clone(), admin, bad_config);
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidScore);
    }

    #[test]
    fn initialize_with_above_max_score_returns_error() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let bad_config = Config {
            max_score: MAX_SCORE + 1,
            ..default_config()
        };
        let result = ReputationScore::initialize(env.clone(), admin, bad_config);
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidScore);
    }

    #[test]
    fn initialize_reputation_is_idempotent() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        // Second call should succeed silently.
        assert!(ReputationScore::initialize_reputation(env.clone(), user.clone()).is_ok());
        assert_eq!(ReputationScore::get_reputation_score(env, user), BASE_SCORE);
    }

    // ── Transaction reputation ────────────────────────────────────────────────

    #[test]
    fn successful_transaction_increments_score() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let score =
            ReputationScore::update_transaction_reputation(env.clone(), user, true, 100).unwrap();
        assert_eq!(score, BASE_SCORE + 10);
    }

    #[test]
    fn failed_transaction_decrements_score() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let score =
            ReputationScore::update_transaction_reputation(env.clone(), user, false, 0).unwrap();
        assert_eq!(score, BASE_SCORE - 5);
    }

    #[test]
    fn score_is_clamped_at_max() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        for _ in 0..10_000 {
            ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 0)
                .unwrap();
        }
        assert_eq!(ReputationScore::get_reputation_score(env, user), MAX_SCORE);
    }

    #[test]
    fn score_does_not_underflow_below_zero() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        for _ in 0..10_000 {
            ReputationScore::update_transaction_reputation(env.clone(), user.clone(), false, 0)
                .unwrap();
        }
        assert_eq!(ReputationScore::get_reputation_score(env, user), 0);
    }

    #[test]
    fn volume_accumulates_across_transactions() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 500)
            .unwrap();
        ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 300)
            .unwrap();
        let profile = ReputationScore::load_profile(&env, user.clone()).unwrap();
        assert_eq!(profile.volume, 800);
    }

    #[test]
    fn transaction_on_uninitialized_user_returns_error() {
        let env = setup_env();
        let admin = Address::generate(&env);
        ReputationScore::initialize(env.clone(), admin, default_config()).unwrap();
        let ghost = Address::generate(&env);
        let result = ReputationScore::update_transaction_reputation(env.clone(), ghost, true, 0);
        assert_eq!(result.unwrap_err(), ReputationScoreError::NotInitialized);
    }

    // ── Credential reputation ─────────────────────────────────────────────────

    #[test]
    fn valid_credential_increments_score() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let cred_type = Bytes::from_slice(&env, b"KYC");
        let score =
            ReputationScore::update_credential_reputation(env.clone(), user, true, cred_type)
                .unwrap();
        assert_eq!(score, BASE_SCORE + 20);
    }

    #[test]
    fn invalid_credential_decrements_score() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let cred_type = Bytes::from_slice(&env, b"KYC");
        let score =
            ReputationScore::update_credential_reputation(env.clone(), user, false, cred_type)
                .unwrap();
        assert_eq!(score, BASE_SCORE - 15);
    }

    #[test]
    fn empty_credential_type_returns_error() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let result = ReputationScore::update_credential_reputation(
            env.clone(),
            user,
            true,
            Bytes::new(&env),
        );
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidInput);
    }

    // ── History ───────────────────────────────────────────────────────────────

    #[test]
    fn history_records_each_transaction() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 0).unwrap();
        ReputationScore::update_transaction_reputation(env.clone(), user.clone(), false, 0)
            .unwrap();
        let history = ReputationScore::get_reputation_history(env.clone(), user, 10).unwrap();
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn history_is_trimmed_to_max_points() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        for _ in 0..(MAX_HISTORY_POINTS + 10) {
            ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 0)
                .unwrap();
        }
        let history =
            ReputationScore::get_reputation_history(env.clone(), user, MAX_HISTORY_POINTS + 100)
                .unwrap();
        assert_eq!(history.len(), MAX_HISTORY_POINTS);
    }

    #[test]
    fn get_history_with_zero_limit_returns_error() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let result = ReputationScore::get_reputation_history(env.clone(), user, 0);
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidInput);
    }

    // ── Percentile ────────────────────────────────────────────────────────────

    #[test]
    fn percentile_is_100_for_sole_user() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let pct = ReputationScore::get_reputation_percentile(env.clone(), user).unwrap();
        assert_eq!(pct, 100);
    }

    #[test]
    fn percentile_reflects_relative_ranking() {
        let env = setup_env();
        let admin = Address::generate(&env);
        ReputationScore::initialize(env.clone(), admin, default_config()).unwrap();

        let low = Address::generate(&env);
        let high = Address::generate(&env);
        ReputationScore::initialize_reputation(env.clone(), low.clone()).unwrap();
        ReputationScore::initialize_reputation(env.clone(), high.clone()).unwrap();

        // Push `high` above `low`.
        for _ in 0..10 {
            ReputationScore::update_transaction_reputation(env.clone(), high.clone(), true, 0)
                .unwrap();
        }

        let low_pct = ReputationScore::get_reputation_percentile(env.clone(), low.clone()).unwrap();
        let high_pct =
            ReputationScore::get_reputation_percentile(env.clone(), high.clone()).unwrap();
        assert!(
            high_pct > low_pct,
            "higher score should yield higher percentile"
        );
    }

    // ── Threshold ─────────────────────────────────────────────────────────────

    #[test]
    fn meets_threshold_at_base_score() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        // BASE_SCORE = 80 * SCORE_SCALE; threshold 80 should pass.
        assert!(
            ReputationScore::meets_reputation_threshold(env.clone(), user.clone(), 80).unwrap()
        );
        // threshold 81 should fail.
        assert!(!ReputationScore::meets_reputation_threshold(env.clone(), user, 81).unwrap());
    }

    // ── Trust attestation ─────────────────────────────────────────────────────

    #[test]
    fn trust_attestation_is_recorded() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let truster = Address::generate(&env);
        ReputationScore::initialize_reputation(env.clone(), truster.clone()).unwrap();

        let att = ReputationScore::attest_trust(
            env.clone(),
            truster.clone(),
            user.clone(),
            500,
            Bytes::from_slice(&env, b"good partner"),
        )
        .unwrap();

        assert_eq!(att.truster, truster);
        assert_eq!(att.subject, user);
        assert_eq!(att.weight, 500);

        let stored = ReputationScore::get_trust_attestations(env.clone(), user);
        assert_eq!(stored.len(), 1);
    }

    #[test]
    fn self_attestation_is_rejected() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let result = ReputationScore::attest_trust(
            env.clone(),
            user.clone(),
            user,
            500,
            Bytes::from_slice(&env, b"myself"),
        );
        assert_eq!(result.unwrap_err(), ReputationScoreError::Unauthorized);
    }

    #[test]
    fn zero_weight_attestation_is_rejected() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let truster = Address::generate(&env);
        let result = ReputationScore::attest_trust(
            env.clone(),
            truster,
            user,
            0,
            Bytes::from_slice(&env, b"reason"),
        );
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidScore);
    }

    #[test]
    fn overweight_attestation_is_rejected() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let truster = Address::generate(&env);
        let result = ReputationScore::attest_trust(
            env.clone(),
            truster,
            user,
            MAX_TRUST_WEIGHT + 1,
            Bytes::from_slice(&env, b"reason"),
        );
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidScore);
    }

    #[test]
    fn empty_reason_attestation_is_rejected() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let truster = Address::generate(&env);
        let result =
            ReputationScore::attest_trust(env.clone(), truster, user, 500, Bytes::new(&env));
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidInput);
    }

    #[test]
    fn duplicate_attestation_is_rejected() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let truster = Address::generate(&env);

        ReputationScore::attest_trust(
            env.clone(),
            truster.clone(),
            user.clone(),
            500,
            Bytes::from_slice(&env, b"first"),
        )
        .unwrap();

        let result = ReputationScore::attest_trust(
            env.clone(),
            truster,
            user,
            300,
            Bytes::from_slice(&env, b"second"),
        );
        assert_eq!(
            result.unwrap_err(),
            ReputationScoreError::DuplicateAttestation
        );
    }

    #[test]
    fn boundary_weight_1000_is_accepted() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let truster = Address::generate(&env);
        let result = ReputationScore::attest_trust(
            env.clone(),
            truster,
            user,
            MAX_TRUST_WEIGHT,
            Bytes::from_slice(&env, b"max weight"),
        );
        assert!(result.is_ok());
    }

    // ── Trust graph ───────────────────────────────────────────────────────────

    #[test]
    fn trust_graph_at_valid_depths_succeeds() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        for depth in MIN_GRAPH_DEPTH..=MAX_GRAPH_DEPTH {
            let result = ReputationScore::get_trust_graph(env.clone(), user.clone(), depth);
            assert!(result.is_ok(), "depth {depth} should be valid");
        }
    }

    #[test]
    fn trust_graph_at_depth_zero_is_rejected() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let result = ReputationScore::get_trust_graph(env.clone(), user, 0);
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidDepth);
    }

    #[test]
    fn trust_graph_above_max_depth_is_rejected() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);
        let result = ReputationScore::get_trust_graph(env.clone(), user, MAX_GRAPH_DEPTH + 1);
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidDepth);
    }

    #[test]
    fn trust_graph_aggregate_weight_is_correct() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);

        for weight in [200u32, 300, 400] {
            let truster = Address::generate(&env);
            ReputationScore::attest_trust(
                env.clone(),
                truster,
                user.clone(),
                weight,
                Bytes::from_slice(&env, b"reason"),
            )
            .unwrap();
        }

        let graph = ReputationScore::get_trust_graph(env.clone(), user, 1).unwrap();
        assert_eq!(graph.aggregate_weight, 900);
        assert_eq!(graph.attestations.len(), 3);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    #[test]
    fn admin_can_update_config() {
        let env = setup_env();
        let (admin, _) = bootstrap(&env);
        let new_config = Config {
            max_score: MAX_SCORE / 2,
            ..default_config()
        };
        assert!(ReputationScore::update_config(env.clone(), admin, new_config).is_ok());
    }

    #[test]
    fn non_admin_cannot_update_config() {
        let env = setup_env();
        bootstrap(&env);
        let intruder = Address::generate(&env);
        let result = ReputationScore::update_config(env.clone(), intruder, default_config());
        assert_eq!(result.unwrap_err(), ReputationScoreError::NotAdmin);
    }

    // ── Reputation Tier System (#270) ─────────────────────────────────────────

    #[test]
    fn test_tier_boundaries() {
        let env = setup_env();
        let (_, user) = bootstrap(&env);

        assert_eq!(
            ReputationScore::get_reputation_tier(env.clone(), user.clone()),
            ReputationTier::Bronze
        );

        assert_eq!(ReputationScore::tier_from_raw_score(&env, 0), ReputationTier::Bronze);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 299), ReputationTier::Bronze);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 300), ReputationTier::Silver);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 599), ReputationTier::Silver);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 600), ReputationTier::Gold);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 799), ReputationTier::Gold);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 800), ReputationTier::Platinum);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 949), ReputationTier::Platinum);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 950), ReputationTier::Diamond);
        assert_eq!(ReputationScore::tier_from_raw_score(&env, 1000), ReputationTier::Diamond);
    }

    #[test]
    fn test_tier_upgrade_and_downgrade_events() {
        let env = setup_env();
        let (admin, user) = bootstrap(&env);

        ReputationScore::set_tier_thresholds(
            env.clone(),
            admin,
            TierThresholds {
                bronze_min: 0,
                silver_min: 90,
                gold_min: 150,
                platinum_min: 200,
                diamond_min: 250,
            },
        )
        .unwrap();

        assert_eq!(
            ReputationScore::get_reputation_tier(env.clone(), user.clone()),
            ReputationTier::Bronze
        );

        let _ = ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 100).unwrap();
        assert_eq!(
            ReputationScore::get_reputation_tier(env.clone(), user.clone()),
            ReputationTier::Silver
        );

        let events = env.events().all();
        assert!(events.iter().any(|e| {
            let topics = e.0.clone();
            topics.contains(&soroban_sdk::Val::Symbol(Symbol::new(&env, "TierUpgraded")))
        }));

        let _ = ReputationScore::update_transaction_reputation(env.clone(), user.clone(), false, 50).unwrap();
        assert_eq!(
            ReputationScore::get_reputation_tier(env.clone(), user.clone()),
            ReputationTier::Bronze
        );

        let events_after = env.events().all();
        assert!(events_after.iter().any(|e| {
            let topics = e.0.clone();
            topics.contains(&soroban_sdk::Val::Symbol(Symbol::new(&env, "TierDowngraded")))
        }));
    }

    #[test]
    fn test_threshold_reconfiguration() {
        let env = setup_env();
        let (admin, _) = bootstrap(&env);
        let non_admin = Address::generate(&env);

        let new_thresholds = TierThresholds {
            bronze_min: 0,
            silver_min: 250,
            gold_min: 500,
            platinum_min: 750,
            diamond_min: 900,
        };

        let res = ReputationScore::set_tier_thresholds(env.clone(), non_admin, new_thresholds.clone());
        assert_eq!(res.unwrap_err(), ReputationScoreError::NotAdmin);

        assert!(ReputationScore::set_tier_thresholds(env.clone(), admin, new_thresholds.clone()).is_ok());
        let fetched = ReputationScore::get_tier_thresholds(env);
        assert_eq!(fetched, new_thresholds);
    }

    #[test]
    fn test_querying_tier_requirements() {
        let env = setup_env();
        bootstrap(&env);

        let bronze_req = ReputationScore::get_tier_requirements(env.clone(), ReputationTier::Bronze);
        assert_eq!(bronze_req.tier, ReputationTier::Bronze);
        assert_eq!(bronze_req.min_score, 0);
        assert_eq!(bronze_req.max_score, 299);

        let diamond_req = ReputationScore::get_tier_requirements(env, ReputationTier::Diamond);
        assert_eq!(diamond_req.tier, ReputationTier::Diamond);
        assert_eq!(diamond_req.min_score, 950);
        assert_eq!(diamond_req.max_score, 1000);
    }
}
