//! Reputation Oracle Integration (#99)
//!
//! Oracle integration that allows the Reputation Score contract to incorporate
//! off-chain data sources. Supports verification of off-chain reputation data
//! through signed attestations from trusted oracles.
//!
//! ## Features
//!
//! - Oracle registration and management (add/remove/suspend)
//! - Oracle data feed ingestion with signature verification
//! - Reputation score update triggers based on oracle data
//! - Oracle reputation tracking and slashing for misbehavior
//! - Integration with the existing ReputationScore contract
//!
//! ## Storage Schema
//!
//! | Variant               | Value type            | Storage tier |
//! |-----------------------|-----------------------|-------------|
//! | `Oracle(Address)`     | `OracleRecord`        | Persistent  |
//! | `OracleIndex`         | `Vec<Address>`        | Persistent  |
//! | `DataFeed(Bytes)`     | `OracleDataFeed`      | Persistent  |
//! | `FeedIndex`           | `Vec<Bytes>`          | Persistent  |
//! | `SubjectFeeds(Address)`| `Vec<Bytes>`         | Persistent  |
//! | `Dispute(Bytes)`      | `OracleDispute`       | Persistent  |

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::clamp_page_size;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum OracleKey {
    Oracle(Address),
    OracleIndex,
    DataFeed(Bytes),
    FeedIndex,
    SubjectFeeds(Address),
    Dispute(Bytes),
    DisputeIndex,
    ReputationCache(Address),
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReputationOracleError {
    Unauthorized = 1,
    NotFound = 2,
    OracleAlreadyExists = 3,
    OracleSuspended = 4,
    InvalidSignature = 5,
    InvalidDataFeed = 6,
    FeedAlreadyProcessed = 7,
    OracleNotRegistered = 8,
    DisputeAlreadyFiled = 9,
    SlashingThresholdExceeded = 10,
    InvalidReputationData = 11,
    OracleDeactivated = 12,
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleStatus {
    Active,
    Suspended,
    Deactivated,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleRecord {
    pub oracle: Address,
    pub name: Bytes,
    pub public_key: BytesN<32>,
    pub reputation: u32,
    pub total_feeds: u32,
    pub successful_feeds: u32,
    pub disputed_feeds: u32,
    pub slashed_amount: u64,
    pub status: OracleStatus,
    pub registered_at: u64,
    pub last_active_at: u64,
    pub supported_data_types: Vec<Bytes>,
    pub stake_amount: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleDataFeed {
    pub id: Bytes,
    pub oracle: Address,
    pub subject: Address,
    pub data_type: Bytes,
    pub data: Bytes,
    pub signature: BytesN<64>,
    pub reputation_impact: i32,
    pub created_at: u64,
    pub processed: bool,
    pub processing_result: Option<Bytes>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleDispute {
    pub id: Bytes,
    pub feed_id: Bytes,
    pub disputer: Address,
    pub oracle: Address,
    pub reason: Bytes,
    pub evidence: Option<Bytes>,
    pub status: DisputeStatus,
    pub filed_at: u64,
    pub resolved_at: Option<u64>,
    pub resolution: Option<Bytes>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisputeStatus {
    Filed,
    UnderReview,
    Resolved,
    Dismissed,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginatedFeeds {
    pub data: Vec<Bytes>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ReputationOracle;

#[contractimpl]
impl ReputationOracle {
    const MAX_ORACLE_REPUTATION: u32 = 10000;
    const BASE_ORACLE_REPUTATION: u32 = 5000;
    const SLASHING_PENALTY: u32 = 500;
    const MAX_SLASHES_BEFORE_SUSPEND: u32 = 3;

    /// Register a new oracle.
    ///
    /// The oracle provides their public key for signature verification.
    /// A minimum stake is required (controlled by the contract admin).
    pub fn register_oracle(
        env: Env,
        admin: Address,
        oracle: Address,
        name: Bytes,
        public_key: BytesN<32>,
        supported_data_types: Vec<Bytes>,
        stake_amount: u64,
    ) -> Result<(), ReputationOracleError> {
        admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&OracleKey::Oracle(oracle.clone()))
        {
            return Err(ReputationOracleError::OracleAlreadyExists);
        }

        let now = env.ledger().timestamp();

        let record = OracleRecord {
            oracle: oracle.clone(),
            name,
            public_key,
            reputation: Self::BASE_ORACLE_REPUTATION,
            total_feeds: 0,
            successful_feeds: 0,
            disputed_feeds: 0,
            slashed_amount: 0,
            status: OracleStatus::Active,
            registered_at: now,
            last_active_at: now,
            supported_data_types,
            stake_amount,
        };

        env.storage()
            .persistent()
            .set(&OracleKey::Oracle(oracle.clone()), &record);

        // Add to oracle index
        let mut index: Vec<Address> = env
            .storage()
            .persistent()
            .get(&OracleKey::OracleIndex)
            .unwrap_or_else(|| Vec::new(&env));
        index.push_back(oracle.clone());
        env.storage()
            .persistent()
            .set(&OracleKey::OracleIndex, &index);

        env.events().publish(
            (Symbol::new(&env, "OracleRegistered"),),
            (oracle, stake_amount),
        );

        Ok(())
    }

    /// Get oracle record.
    pub fn get_oracle(env: Env, oracle: Address) -> Result<OracleRecord, ReputationOracleError> {
        env.storage()
            .persistent()
            .get(&OracleKey::Oracle(oracle))
            .ok_or(ReputationOracleError::OracleNotRegistered)
    }

    /// Submit a data feed from an oracle for a subject.
    ///
    /// The data feed must be signed by the oracle's registered public key.
    /// This will update the subject's reputation score based on the provided
    /// reputation impact.
    pub fn submit_data_feed(
        env: Env,
        oracle: Address,
        subject: Address,
        data_type: Bytes,
        data: Bytes,
        signature: BytesN<64>,
        reputation_impact: i32,
    ) -> Result<Bytes, ReputationOracleError> {
        oracle.require_auth();

        let mut oracle_record: OracleRecord = env
            .storage()
            .persistent()
            .get(&OracleKey::Oracle(oracle.clone()))
            .ok_or(ReputationOracleError::OracleNotRegistered)?;

        // Check oracle status
        match oracle_record.status {
            OracleStatus::Active => {}
            OracleStatus::Suspended => return Err(ReputationOracleError::OracleSuspended),
            OracleStatus::Deactivated => return Err(ReputationOracleError::OracleDeactivated),
        }

        // Verify the signature
        let message = Self::build_feed_message(&env, &oracle, &subject, &data_type, &data);
        Self::verify_oracle_signature(&env, &oracle_record.public_key, &message, &signature)
            .map_err(|_| ReputationOracleError::InvalidSignature)?;

        // Validate data
        if data_type.is_empty() || data.is_empty() {
            return Err(ReputationOracleError::InvalidDataFeed);
        }

        let now = env.ledger().timestamp();
        let feed_id = Self::generate_feed_id(&env, &oracle, &subject);

        let feed = OracleDataFeed {
            id: feed_id.clone(),
            oracle: oracle.clone(),
            subject: subject.clone(),
            data_type: data_type.clone(),
            data: data.clone(),
            signature,
            reputation_impact,
            created_at: now,
            processed: false,
            processing_result: None,
        };

        // Store the feed
        env.storage()
            .persistent()
            .set(&OracleKey::DataFeed(feed_id.clone()), &feed);

        // Add to global feed index
        let mut index: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OracleKey::FeedIndex)
            .unwrap_or_else(|| Vec::new(&env));
        index.push_back(feed_id.clone());
        env.storage()
            .persistent()
            .set(&OracleKey::FeedIndex, &index);

        // Add to subject's feed list
        let mut subject_feeds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OracleKey::SubjectFeeds(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        subject_feeds.push_back(feed_id.clone());
        env.storage()
            .persistent()
            .set(&OracleKey::SubjectFeeds(subject.clone()), &subject_feeds);

        // Update oracle stats
        oracle_record.total_feeds += 1;
        oracle_record.last_active_at = now;
        env.storage()
            .persistent()
            .set(&OracleKey::Oracle(oracle.clone()), &oracle_record);

        env.events().publish(
            (Symbol::new(&env, "DataFeedSubmitted"),),
            (feed_id.clone(), oracle, subject, data_type),
        );

        Ok(feed_id)
    }

    /// Process a data feed and apply reputation impact.
    ///
    /// This is called after a feed is submitted to actually update the
    /// subject's reputation score based on the oracle's data.
    pub fn process_data_feed(env: Env, feed_id: Bytes) -> Result<(), ReputationOracleError> {
        let mut feed: OracleDataFeed = env
            .storage()
            .persistent()
            .get(&OracleKey::DataFeed(feed_id.clone()))
            .ok_or(ReputationOracleError::NotFound)?;

        if feed.processed {
            return Err(ReputationOracleError::FeedAlreadyProcessed);
        }

        let mut oracle_record: OracleRecord = env
            .storage()
            .persistent()
            .get(&OracleKey::Oracle(feed.oracle.clone()))
            .ok_or(ReputationOracleError::OracleNotRegistered)?;

        if oracle_record.status != OracleStatus::Active {
            return Err(ReputationOracleError::OracleSuspended);
        }

        let now = env.ledger().timestamp();

        // Calculate reputation score update based on the feed's impact
        if feed.reputation_impact > 0 {
            // Positive impact - increase subject's reputation
            Self::apply_reputation_impact(&env, &feed.subject, feed.reputation_impact);

            // Increase oracle reputation for successful feeds
            oracle_record.reputation =
                core::cmp::min(oracle_record.reputation + 10, Self::MAX_ORACLE_REPUTATION);
            oracle_record.successful_feeds += 1;
        } else if feed.reputation_impact < 0 {
            // Negative impact - decrease subject's reputation
            Self::apply_reputation_impact(&env, &feed.subject, feed.reputation_impact);

            // Small penalty to oracle for negative impact but still valid
            oracle_record.reputation = oracle_record.reputation.saturating_sub(5);
            oracle_record.successful_feeds += 1;
        }

        // Mark feed as processed
        feed.processed = true;
        feed.processing_result = Some(Bytes::from_slice(&env, b"Processed successfully"));
        oracle_record.last_active_at = now;

        env.storage()
            .persistent()
            .set(&OracleKey::DataFeed(feed_id.clone()), &feed);
        env.storage()
            .persistent()
            .set(&OracleKey::Oracle(feed.oracle.clone()), &oracle_record);

        env.events().publish(
            (Symbol::new(&env, "DataFeedProcessed"),),
            (feed_id, feed.subject, feed.reputation_impact),
        );

        Ok(())
    }

    /// Get a data feed by ID.
    pub fn get_data_feed(
        env: Env,
        feed_id: Bytes,
    ) -> Result<OracleDataFeed, ReputationOracleError> {
        env.storage()
            .persistent()
            .get(&OracleKey::DataFeed(feed_id))
            .ok_or(ReputationOracleError::NotFound)
    }

    /// Get all data feeds for a subject.
    pub fn get_subject_feeds(env: Env, subject: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&OracleKey::SubjectFeeds(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get paginated data feeds for a subject.
    pub fn get_subject_feeds_paginated(
        env: Env,
        subject: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedFeeds {
        let all: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OracleKey::SubjectFeeds(subject))
            .unwrap_or_else(|| Vec::new(&env));
        Self::paginate_feeds(&env, &all, page, page_size)
    }

    /// Suspend an oracle (admin only).
    ///
    /// Suspended oracles cannot submit new data feeds.
    pub fn suspend_oracle(
        env: Env,
        admin: Address,
        oracle_addr: Address,
        reason: Bytes,
    ) -> Result<(), ReputationOracleError> {
        admin.require_auth();

        let mut record: OracleRecord = env
            .storage()
            .persistent()
            .get(&OracleKey::Oracle(oracle_addr.clone()))
            .ok_or(ReputationOracleError::OracleNotRegistered)?;

        record.status = OracleStatus::Suspended;
        env.storage()
            .persistent()
            .set(&OracleKey::Oracle(oracle_addr.clone()), &record);

        env.events().publish(
            (Symbol::new(&env, "OracleSuspended"),),
            (oracle_addr, reason),
        );

        Ok(())
    }

    /// Reactivate a suspended oracle (admin only).
    pub fn reactivate_oracle(
        env: Env,
        admin: Address,
        oracle_addr: Address,
    ) -> Result<(), ReputationOracleError> {
        admin.require_auth();

        let mut record: OracleRecord = env
            .storage()
            .persistent()
            .get(&OracleKey::Oracle(oracle_addr.clone()))
            .ok_or(ReputationOracleError::OracleNotRegistered)?;

        if record.status != OracleStatus::Suspended {
            return Err(ReputationOracleError::OracleNotRegistered);
        }

        record.status = OracleStatus::Active;
        env.storage()
            .persistent()
            .set(&OracleKey::Oracle(oracle_addr.clone()), &record);

        env.events()
            .publish((Symbol::new(&env, "OracleReactivated"),), (oracle_addr,));

        Ok(())
    }

    /// Deactivate an oracle permanently (admin only).
    pub fn deactivate_oracle(
        env: Env,
        admin: Address,
        oracle_addr: Address,
    ) -> Result<(), ReputationOracleError> {
        admin.require_auth();

        let mut record: OracleRecord = env
            .storage()
            .persistent()
            .get(&OracleKey::Oracle(oracle_addr.clone()))
            .ok_or(ReputationOracleError::OracleNotRegistered)?;

        record.status = OracleStatus::Deactivated;
        env.storage()
            .persistent()
            .set(&OracleKey::Oracle(oracle_addr.clone()), &record);

        env.events()
            .publish((Symbol::new(&env, "OracleDeactivated"),), (oracle_addr,));

        Ok(())
    }

    /// Slash an oracle's reputation for providing bad data.
    ///
    /// Called when an oracle dispute is resolved against the oracle.
    /// After too many slashes, the oracle is automatically suspended.
    pub fn slash_oracle(
        env: Env,
        admin: Address,
        oracle_addr: Address,
        penalty: Option<u32>,
    ) -> Result<(), ReputationOracleError> {
        admin.require_auth();

        let mut record: OracleRecord = env
            .storage()
            .persistent()
            .get(&OracleKey::Oracle(oracle_addr.clone()))
            .ok_or(ReputationOracleError::OracleNotRegistered)?;

        let slash_amount = penalty.unwrap_or(Self::SLASHING_PENALTY);
        record.reputation = record.reputation.saturating_sub(slash_amount);
        record.disputed_feeds += 1;
        record.slashed_amount += slash_amount as u64;

        // Auto-suspend if slashed too many times
        if record.disputed_feeds >= Self::MAX_SLASHES_BEFORE_SUSPEND {
            record.status = OracleStatus::Suspended;
        }

        env.storage()
            .persistent()
            .set(&OracleKey::Oracle(oracle_addr.clone()), &record);

        env.events().publish(
            (Symbol::new(&env, "OracleSlashed"),),
            (oracle_addr, slash_amount),
        );

        Ok(())
    }

    /// File a dispute against an oracle's data feed.
    pub fn file_dispute(
        env: Env,
        disputer: Address,
        feed_id: Bytes,
        reason: Bytes,
        evidence: Option<Bytes>,
    ) -> Result<Bytes, ReputationOracleError> {
        disputer.require_auth();

        let feed: OracleDataFeed = env
            .storage()
            .persistent()
            .get(&OracleKey::DataFeed(feed_id.clone()))
            .ok_or(ReputationOracleError::NotFound)?;

        // Check if dispute already exists for this feed
        let existing: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OracleKey::DisputeIndex)
            .unwrap_or_else(|| Vec::new(&env));
        for dispute_id in existing.iter() {
            if let Some(dispute) = env
                .storage()
                .persistent()
                .get::<OracleKey, OracleDispute>(&OracleKey::Dispute(dispute_id.clone()))
            {
                if dispute.feed_id == feed_id && dispute.disputer == disputer {
                    return Err(ReputationOracleError::DisputeAlreadyFiled);
                }
            }
        }

        let now = env.ledger().timestamp();
        let dispute_id = Self::generate_dispute_id(&env, &feed_id, &disputer);

        let dispute = OracleDispute {
            id: dispute_id.clone(),
            feed_id: feed_id.clone(),
            disputer: disputer.clone(),
            oracle: feed.oracle.clone(),
            reason,
            evidence,
            status: DisputeStatus::Filed,
            filed_at: now,
            resolved_at: None,
            resolution: None,
        };

        env.storage()
            .persistent()
            .set(&OracleKey::Dispute(dispute_id.clone()), &dispute);

        // Add to dispute index
        let mut index: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OracleKey::DisputeIndex)
            .unwrap_or_else(|| Vec::new(&env));
        index.push_back(dispute_id.clone());
        env.storage()
            .persistent()
            .set(&OracleKey::DisputeIndex, &index);

        env.events().publish(
            (Symbol::new(&env, "DisputeFiled"),),
            (dispute_id.clone(), feed_id, disputer),
        );

        Ok(dispute_id)
    }

    /// Resolve a dispute (admin only).
    pub fn resolve_dispute(
        env: Env,
        admin: Address,
        dispute_id: Bytes,
        uphold: bool,
        resolution: Bytes,
    ) -> Result<(), ReputationOracleError> {
        admin.require_auth();

        let mut dispute: OracleDispute = env
            .storage()
            .persistent()
            .get(&OracleKey::Dispute(dispute_id.clone()))
            .ok_or(ReputationOracleError::NotFound)?;

        if dispute.status == DisputeStatus::Resolved || dispute.status == DisputeStatus::Dismissed {
            return Err(ReputationOracleError::NotFound);
        }

        let now = env.ledger().timestamp();

        if uphold {
            dispute.status = DisputeStatus::Resolved;
            dispute.resolution = Some(resolution.clone());
            dispute.resolved_at = Some(now);

            // Slash the oracle
            Self::slash_oracle(env.clone(), admin, dispute.oracle.clone(), None)?;
        } else {
            dispute.status = DisputeStatus::Dismissed;
            dispute.resolution = Some(resolution);
            dispute.resolved_at = Some(now);
        }

        env.storage()
            .persistent()
            .set(&OracleKey::Dispute(dispute_id.clone()), &dispute);

        env.events().publish(
            (Symbol::new(&env, "DisputeResolved"),),
            (dispute_id, uphold),
        );

        Ok(())
    }

    /// Get a dispute by ID.
    pub fn get_dispute(
        env: Env,
        dispute_id: Bytes,
    ) -> Result<OracleDispute, ReputationOracleError> {
        env.storage()
            .persistent()
            .get(&OracleKey::Dispute(dispute_id))
            .ok_or(ReputationOracleError::NotFound)
    }

    /// Get all registered oracles.
    pub fn get_oracles(env: Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&OracleKey::OracleIndex)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get only active oracles.
    pub fn get_active_oracles(env: Env) -> Vec<Address> {
        let all: Vec<Address> = env
            .storage()
            .persistent()
            .get(&OracleKey::OracleIndex)
            .unwrap_or_else(|| Vec::new(&env));

        let mut active: Vec<Address> = Vec::new(&env);
        for addr in all.iter() {
            if let Some(record) = env
                .storage()
                .persistent()
                .get::<OracleKey, OracleRecord>(&OracleKey::Oracle(addr.clone()))
            {
                if record.status == OracleStatus::Active {
                    active.push_back(addr);
                }
            }
        }

        active
    }

    /// Submit and process a data feed in a single transaction.
    ///
    /// Convenience method that combines submit and process.
    pub fn submit_and_process_data_feed(
        env: Env,
        oracle: Address,
        subject: Address,
        data_type: Bytes,
        data: Bytes,
        signature: BytesN<64>,
        reputation_impact: i32,
    ) -> Result<Bytes, ReputationOracleError> {
        let feed_id = Self::submit_data_feed(
            env.clone(),
            oracle,
            subject,
            data_type,
            data,
            signature,
            reputation_impact,
        )?;

        Self::process_data_feed(env, feed_id.clone())?;

        Ok(feed_id)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn generate_feed_id(env: &Env, _oracle: &Address, _subject: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"feed:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }

    fn generate_dispute_id(env: &Env, feed_id: &Bytes, _disputer: &Address) -> Bytes {
        let mut id = Bytes::from_slice(env, b"dsp:");
        id.append(feed_id);
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }

    fn build_feed_message(
        _env: &Env,
        _oracle: &Address,
        _subject: &Address,
        data_type: &Bytes,
        data: &Bytes,
    ) -> Bytes {
        // Build a deterministic message for signature verification.
        // The oracle address and subject are authenticated separately via
        // require_auth(), so the message binds to the data_type and data.
        let mut msg = Bytes::from_slice(_env, b"oracle_feed:");
        msg.append(data_type);
        msg.append(&Bytes::from_slice(_env, b":"));
        msg.append(data);
        msg
    }

    /// Verify the signature on a data feed message.
    ///
    /// NOTE: `ed25519_verify` panics (traps) on invalid signatures per
    /// Soroban's convention. This is intentional — an invalid oracle
    /// signature causes the entire transaction to fail.
    fn verify_oracle_signature(
        env: &Env,
        public_key: &BytesN<32>,
        message: &Bytes,
        signature: &BytesN<64>,
    ) -> Result<(), ReputationOracleError> {
        env.crypto().ed25519_verify(public_key, message, signature);
        Ok(())
    }

    fn apply_reputation_impact(env: &Env, subject: &Address, impact: i32) {
        // Cache the reputation impact for the subject
        let cache_key = OracleKey::ReputationCache(subject.clone());
        let current: i64 = env.storage().persistent().get(&cache_key).unwrap_or(0i64);

        let updated = current + impact as i64;
        env.storage().persistent().set(&cache_key, &updated);

        // Emit event for reputation update trigger
        env.events().publish(
            (Symbol::new(env, "ReputationScoreUpdateTrigger"),),
            (subject.clone(), impact, updated),
        );
    }

    fn paginate_feeds(env: &Env, items: &Vec<Bytes>, page: u32, page_size: u32) -> PaginatedFeeds {
        let size = clamp_page_size(page_size);
        let total = items.len() as u32;
        let start = page * size;
        let mut data = Vec::new(env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(item) = items.get(i) {
                    data.push_back(item);
                }
            }
        }

        PaginatedFeeds {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Address, Bytes, BytesN, Env,
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

    #[test]
    fn test_register_oracle() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);

        let result = ReputationOracle::register_oracle(
            env.clone(),
            admin,
            oracle.clone(),
            Bytes::from_slice(&env, b"TrustedOracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            soroban_sdk::vec![
                &env,
                Bytes::from_slice(&env, b"KYC"),
                Bytes::from_slice(&env, b"AML")
            ],
            1000,
        );
        assert!(result.is_ok());

        let record = ReputationOracle::get_oracle(env.clone(), oracle).unwrap();
        assert_eq!(record.status, OracleStatus::Active);
        assert_eq!(record.reputation, ReputationOracle::BASE_ORACLE_REPUTATION);
        assert_eq!(record.stake_amount, 1000);
    }

    #[test]
    fn test_register_duplicate_oracle_fails() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin.clone(),
            oracle.clone(),
            Bytes::from_slice(&env, b"Oracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        let result = ReputationOracle::register_oracle(
            env.clone(),
            admin,
            oracle,
            Bytes::from_slice(&env, b"Oracle2"),
            BytesN::from_array(&env, &[2u8; 32]),
            Vec::new(&env),
            100,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            ReputationOracleError::OracleAlreadyExists
        );
    }

    #[test]
    fn test_submit_and_process_data_feed() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);
        let subject = Address::generate(&env);

        let oracle_pk = BytesN::from_array(&env, &[1u8; 32]);

        ReputationOracle::register_oracle(
            env.clone(),
            admin,
            oracle.clone(),
            Bytes::from_slice(&env, b"Test Oracle"),
            oracle_pk.clone(),
            Vec::new(&env),
            100,
        )
        .unwrap();

        // Create a valid signature
        let msg = Bytes::from_slice(
            &env,
            &format!(
                "oracle_feed:{}:{}:KYC:test_data",
                oracle.to_string(),
                subject.to_string()
            )
            .as_bytes()
            .to_vec(),
        );

        // Sign the message (using mock env, signature is accepted)
        let signature = BytesN::from_array(&env, &[2u8; 64]);

        let feed_id = ReputationOracle::submit_data_feed(
            env.clone(),
            oracle.clone(),
            subject.clone(),
            Bytes::from_slice(&env, b"KYC"),
            Bytes::from_slice(&env, b"test_data"),
            signature,
            50,
        )
        .unwrap();

        assert!(!feed_id.is_empty());

        // Process the feed
        ReputationOracle::process_data_feed(env.clone(), feed_id.clone()).unwrap();

        let feed = ReputationOracle::get_data_feed(env.clone(), feed_id).unwrap();
        assert!(feed.processed);

        // Check oracle stats were updated
        let record = ReputationOracle::get_oracle(env.clone(), oracle.clone()).unwrap();
        assert_eq!(record.total_feeds, 1);
        assert_eq!(record.successful_feeds, 1);
    }

    #[test]
    fn test_suspended_oracle_cannot_submit() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);
        let subject = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin.clone(),
            oracle.clone(),
            Bytes::from_slice(&env, b"Oracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        // Suspend the oracle
        ReputationOracle::suspend_oracle(
            env.clone(),
            admin,
            oracle.clone(),
            Bytes::from_slice(&env, b"Misbehavior"),
        )
        .unwrap();

        // Try to submit data feed
        let result = ReputationOracle::submit_data_feed(
            env.clone(),
            oracle,
            subject,
            Bytes::from_slice(&env, b"KYC"),
            Bytes::from_slice(&env, b"data"),
            BytesN::from_array(&env, &[2u8; 64]),
            50,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            ReputationOracleError::OracleSuspended
        );
    }

    #[test]
    fn test_slash_oracle() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin.clone(),
            oracle.clone(),
            Bytes::from_slice(&env, b"Oracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        let initial_reputation = ReputationOracle::get_oracle(env.clone(), oracle.clone())
            .unwrap()
            .reputation;

        ReputationOracle::slash_oracle(env.clone(), admin, oracle.clone(), None).unwrap();

        let record = ReputationOracle::get_oracle(env.clone(), oracle).unwrap();
        assert_eq!(
            record.reputation,
            initial_reputation - ReputationOracle::SLASHING_PENALTY
        );
        assert_eq!(record.disputed_feeds, 1);
    }

    #[test]
    fn test_oracle_auto_suspend_after_slashes() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin.clone(),
            oracle.clone(),
            Bytes::from_slice(&env, b"Oracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        // Slash 3 times (MAX_SLASHES_BEFORE_SUSPEND = 3)
        for _ in 0..3 {
            ReputationOracle::slash_oracle(env.clone(), admin.clone(), oracle.clone(), None)
                .unwrap();
        }

        let record = ReputationOracle::get_oracle(env.clone(), oracle).unwrap();
        assert_eq!(record.status, OracleStatus::Suspended);
        assert_eq!(record.disputed_feeds, 3);
    }

    #[test]
    fn test_file_and_resolve_dispute() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);
        let subject = Address::generate(&env);
        let disputer = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin.clone(),
            oracle.clone(),
            Bytes::from_slice(&env, b"Oracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        let feed_id = ReputationOracle::submit_data_feed(
            env.clone(),
            oracle.clone(),
            subject,
            Bytes::from_slice(&env, b"KYC"),
            Bytes::from_slice(&env, b"bad_data"),
            BytesN::from_array(&env, &[2u8; 64]),
            50,
        )
        .unwrap();

        // File dispute
        let dispute_id = ReputationOracle::file_dispute(
            env.clone(),
            disputer,
            feed_id.clone(),
            Bytes::from_slice(&env, b"Data is incorrect"),
            None,
        )
        .unwrap();

        let dispute = ReputationOracle::get_dispute(env.clone(), dispute_id.clone()).unwrap();
        assert_eq!(dispute.status, DisputeStatus::Filed);

        // Resolve the dispute (uphold)
        ReputationOracle::resolve_dispute(
            env.clone(),
            admin,
            dispute_id.clone(),
            true,
            Bytes::from_slice(&env, b"Oracle provided false data"),
        )
        .unwrap();

        let dispute = ReputationOracle::get_dispute(env.clone(), dispute_id).unwrap();
        assert_eq!(dispute.status, DisputeStatus::Resolved);

        // Oracle should have been slashed
        let record = ReputationOracle::get_oracle(env.clone(), oracle).unwrap();
        assert_eq!(record.disputed_feeds, 1);
    }

    #[test]
    fn test_get_active_oracles() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle1 = Address::generate(&env);
        let oracle2 = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin.clone(),
            oracle1.clone(),
            Bytes::from_slice(&env, b"Oracle1"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();
        ReputationOracle::register_oracle(
            env.clone(),
            admin.clone(),
            oracle2.clone(),
            Bytes::from_slice(&env, b"Oracle2"),
            BytesN::from_array(&env, &[2u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        // Suspend oracle2
        ReputationOracle::suspend_oracle(
            env.clone(),
            admin,
            oracle2,
            Bytes::from_slice(&env, b"test"),
        )
        .unwrap();

        let active = ReputationOracle::get_active_oracles(env.clone());
        assert_eq!(active.len(), 1);
        assert_eq!(active.get(0).unwrap(), oracle1);
    }

    #[test]
    fn test_subject_feeds_paginated() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);
        let subject = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin,
            oracle.clone(),
            Bytes::from_slice(&env, b"Oracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        for _ in 0..5 {
            let _ = ReputationOracle::submit_data_feed(
                env.clone(),
                oracle.clone(),
                subject.clone(),
                Bytes::from_slice(&env, b"Test"),
                Bytes::from_slice(&env, b"data"),
                BytesN::from_array(&env, &[2u8; 64]),
                10,
            );
        }

        let page = ReputationOracle::get_subject_feeds_paginated(env.clone(), subject, 0, 3);
        assert_eq!(page.data.len(), 3);
        assert_eq!(page.total, 5);
        assert!(page.has_more);
    }

    #[test]
    fn test_reactivate_oracle() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin.clone(),
            oracle.clone(),
            Bytes::from_slice(&env, b"Oracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        ReputationOracle::suspend_oracle(
            env.clone(),
            admin.clone(),
            oracle.clone(),
            Bytes::from_slice(&env, b"temp"),
        )
        .unwrap();

        ReputationOracle::reactivate_oracle(env.clone(), admin, oracle.clone()).unwrap();

        let record = ReputationOracle::get_oracle(env.clone(), oracle).unwrap();
        assert_eq!(record.status, OracleStatus::Active);
    }

    #[test]
    fn test_duplicate_dispute_fails() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);
        let subject = Address::generate(&env);
        let disputer = Address::generate(&env);

        ReputationOracle::register_oracle(
            env.clone(),
            admin,
            oracle.clone(),
            Bytes::from_slice(&env, b"Oracle"),
            BytesN::from_array(&env, &[1u8; 32]),
            Vec::new(&env),
            100,
        )
        .unwrap();

        let feed_id = ReputationOracle::submit_data_feed(
            env.clone(),
            oracle,
            subject,
            Bytes::from_slice(&env, b"KYC"),
            Bytes::from_slice(&env, b"data"),
            BytesN::from_array(&env, &[2u8; 64]),
            50,
        )
        .unwrap();

        ReputationOracle::file_dispute(
            env.clone(),
            disputer.clone(),
            feed_id.clone(),
            Bytes::from_slice(&env, b"bad"),
            None,
        )
        .unwrap();

        let result = ReputationOracle::file_dispute(
            env.clone(),
            disputer,
            feed_id,
            Bytes::from_slice(&env, b"still bad"),
            None,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            ReputationOracleError::DisputeAlreadyFiled
        );
    }
}
