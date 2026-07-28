use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::{clamp_page_size, PaginatedAddresses};

// ── Constants ─────────────────────────────────────────────────────────────────

const COMPLIANCE_TTL_LEDGERS: u32 = 6_307_200;
const MAX_RISK_SCORE: u32 = 100;
const HIGH_RISK_THRESHOLD: u32 = 70;
const ORACLE_STALENESS_SECS: u64 = 60 * 60 * 24; // 24 hours
const MAX_BATCH_SIZE: u32 = 50;

// ── Storage keys ──────────────────────────────────────────────────────────────

const KEY_ADMIN: &str = "admin";
const KEY_ORACLES: &str = "oracles";

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ComplianceFilterError {
    /// Address is on an active sanctions list.
    AddressBlocked = 1,
    /// Risk score exceeds the high-risk threshold.
    HighRisk = 2,
    /// Caller is not authorized for this operation.
    Unauthorized = 3,
    /// Requested resource was not found.
    NotFound = 4,
    /// Risk score is outside the allowed range 0–100.
    InvalidRiskScore = 5,
    /// Oracle data is too old to be trusted.
    OracleStale = 6,
    /// List hash does not match the loaded entries.
    InvalidHash = 7,
    /// Contract has not been initialized.
    NotInitialized = 8,
    /// Contract is already initialized.
    AlreadyInitialized = 9,
    /// Input argument is empty or structurally invalid.
    InvalidInput = 10,
    /// Batch size exceeds the maximum allowed.
    BatchTooLarge = 11,
    /// List or entry already exists.
    AlreadyExists = 12,
    /// Oracle is not registered.
    OracleNotRegistered = 13,
}

// ── Storage key enum ──────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum CfKey {
    List(Bytes),
    Entries(Bytes),
    Screening(Address),
    Rule(Bytes),
    Audit(Address, u64),
    AuditIndex(Address),
    ListIndex,
    RiskWeights,
}

// ── Data structures ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanctionsList {
    pub source: Bytes,
    pub last_updated: u64,
    pub hash: BytesN<32>,
    pub active: bool,
    pub entry_count: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScreeningResult {
    pub address: Address,
    pub status: Bytes,
    pub risk_score: u32,
    pub matches: Vec<Bytes>,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplianceRule {
    pub jurisdiction: Bytes,
    pub requirement: Bytes,
    pub enforcement: Bytes,
    pub active: bool,
    pub created: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegulatoryReport {
    pub subject: Address,
    pub activity_summary: Bytes,
    pub risk_flags: Bytes,
    pub timestamp: u64,
    pub ledger_sequence: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchScreenResult {
    pub address: Address,
    pub blocked: bool,
    pub risk_score: u32,
    pub status: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskWeights {
    pub sanctions_weight: u32,
    pub oracle_weight: u32,
    pub high_risk_threshold: u32,
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskFactor {
    pub name: Bytes,
    pub score: u32,
    pub weight: u32,
    pub description: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskAssessment {
    pub score: u32,
    pub factors: Vec<RiskFactor>,
    pub overall: RiskLevel,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ComplianceFilter;

#[contractimpl]
impl ComplianceFilter {
    // ── Initialization ────────────────────────────────────────────────────────

    /// Initialize the contract with a designated admin.
    /// Fails if already initialized.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ComplianceFilterError> {
        if env.storage().instance().has(&Symbol::new(&env, KEY_ADMIN)) {
            return Err(ComplianceFilterError::AlreadyInitialized);
        }
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_ADMIN), &admin);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_ORACLES), &Vec::<Address>::new(&env));
        Ok(())
    }

    // ── Admin & oracle management ─────────────────────────────────────────────

    /// Transfer admin rights to a new address.
    pub fn transfer_admin(
        env: Env,
        caller: Address,
        new_admin: Address,
    ) -> Result<(), ComplianceFilterError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(ComplianceFilterError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_ADMIN), &new_admin);
        env.events()
            .publish((Symbol::new(&env, "admin_xfer"), admin), new_admin);
        Ok(())
    }

    /// Register a trusted oracle that may update risk scores.
    pub fn register_oracle(
        env: Env,
        caller: Address,
        oracle: Address,
    ) -> Result<(), ComplianceFilterError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(ComplianceFilterError::Unauthorized);
        }
        let mut oracles = Self::get_oracles(&env);
        for existing in oracles.iter() {
            if existing == oracle {
                return Err(ComplianceFilterError::AlreadyExists);
            }
        }
        oracles.push_back(oracle.clone());
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_ORACLES), &oracles);
        env.events()
            .publish((Symbol::new(&env, "oracle_reg"),), oracle);
        Ok(())
    }

    /// Remove a previously registered oracle.
    pub fn deregister_oracle(
        env: Env,
        caller: Address,
        oracle: Address,
    ) -> Result<(), ComplianceFilterError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(ComplianceFilterError::Unauthorized);
        }
        let oracles = Self::get_oracles(&env);
        let mut updated = Vec::new(&env);
        let mut found = false;
        for existing in oracles.iter() {
            if existing == oracle {
                found = true;
            } else {
                updated.push_back(existing);
            }
        }
        if !found {
            return Err(ComplianceFilterError::OracleNotRegistered);
        }
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_ORACLES), &updated);
        Ok(())
    }

    // ── Sanctions list management ─────────────────────────────────────────────

    /// Create or update a sanctions list header. Admin only.
    pub fn update_sanctions_list(
        env: Env,
        admin: Address,
        source: Bytes,
        hash: BytesN<32>,
        entry_count: u32,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if source.is_empty() {
            return Err(ComplianceFilterError::InvalidInput);
        }

        let list = SanctionsList {
            source: source.clone(),
            last_updated: env.ledger().timestamp(),
            hash,
            active: true,
            entry_count,
        };

        let lk = CfKey::List(source.clone());
        Self::persist(&env, &lk, &list);

        // Add to the global list index if not already present.
        let mut index: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CfKey::ListIndex)
            .unwrap_or_else(|| Vec::new(&env));
        if !index.iter().any(|s| s == source) {
            index.push_back(source.clone());
            Self::persist(&env, &CfKey::ListIndex, &index);
        }

        env.events()
            .publish((Symbol::new(&env, "list_update"), source), entry_count);
        Ok(())
    }

    /// Bulk-load address entries for a list. Validates the provided hash against
    /// the declared list hash. Admin only.
    pub fn load_list_entries(
        env: Env,
        admin: Address,
        source: Bytes,
        entries: Vec<Address>,
        expected_hash: BytesN<32>,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        let lk = CfKey::List(source.clone());
        let list: SanctionsList = env
            .storage()
            .persistent()
            .get(&lk)
            .ok_or(ComplianceFilterError::NotFound)?;

        // Verify the caller supplied the same hash that was declared on upload.
        if list.hash != expected_hash {
            return Err(ComplianceFilterError::InvalidHash);
        }

        let ek = CfKey::Entries(source);
        Self::persist(&env, &ek, &entries);
        Ok(())
    }

    /// Add a single address to an existing sanctions list. Admin only.
    pub fn add_to_sanctions_list(
        env: Env,
        admin: Address,
        source: Bytes,
        address: Address,
        reason: Bytes,
        jurisdiction: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if reason.is_empty() || jurisdiction.is_empty() {
            return Err(ComplianceFilterError::InvalidInput);
        }

        let lk = CfKey::List(source.clone());
        let mut list: SanctionsList = env
            .storage()
            .persistent()
            .get(&lk)
            .ok_or(ComplianceFilterError::NotFound)?;

        if !list.active {
            return Err(ComplianceFilterError::NotFound);
        }

        let ek = CfKey::Entries(source.clone());
        let mut entries: Vec<Address> = env
            .storage()
            .persistent()
            .get(&ek)
            .unwrap_or_else(|| Vec::new(&env));

        // Idempotent: skip if already present.
        if entries.iter().any(|e| e == address) {
            return Err(ComplianceFilterError::AlreadyExists);
        }

        entries.push_back(address.clone());
        list.entry_count = entries.len() as u32;
        list.last_updated = env.ledger().timestamp();

        Self::persist(&env, &ek, &entries);
        Self::persist(&env, &lk, &list);

        let mut detail = Bytes::from_slice(&env, b"reason:");
        detail.append(&reason);
        detail.append(&Bytes::from_slice(&env, b",jurisdiction:"));
        detail.append(&jurisdiction);
        Self::append_audit(&env, &address, b"sanctioned", &detail);

        env.events()
            .publish((Symbol::new(&env, "sanctioned"), address), source);
        Ok(())
    }

    /// Remove a single address from a sanctions list. Admin only.
    pub fn remove_from_sanctions_list(
        env: Env,
        admin: Address,
        source: Bytes,
        address: Address,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        let lk = CfKey::List(source.clone());
        let mut list: SanctionsList = env
            .storage()
            .persistent()
            .get(&lk)
            .ok_or(ComplianceFilterError::NotFound)?;

        let ek = CfKey::Entries(source.clone());
        let entries: Vec<Address> = env
            .storage()
            .persistent()
            .get(&ek)
            .unwrap_or_else(|| Vec::new(&env));

        let mut updated = Vec::new(&env);
        let mut found = false;
        for entry in entries.iter() {
            if entry == address {
                found = true;
            } else {
                updated.push_back(entry);
            }
        }
        if !found {
            return Err(ComplianceFilterError::NotFound);
        }

        list.entry_count = updated.len() as u32;
        list.last_updated = env.ledger().timestamp();

        Self::persist(&env, &ek, &updated);
        Self::persist(&env, &lk, &list);

        Self::append_audit(
            &env,
            &address,
            b"desanctioned",
            &Bytes::from_slice(&env, b"removed"),
        );
        env.events()
            .publish((Symbol::new(&env, "desanctioned"), address), source);
        Ok(())
    }

    /// Batch-add multiple addresses to a sanctions list. Admin only.
    /// Silently skips addresses already on the list.
    pub fn batch_add_to_sanctions_list(
        env: Env,
        admin: Address,
        source: Bytes,
        addresses: Vec<Address>,
        reason: Bytes,
        jurisdiction: Bytes,
    ) -> Result<u32, ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if addresses.len() > MAX_BATCH_SIZE {
            return Err(ComplianceFilterError::BatchTooLarge);
        }
        if reason.is_empty() || jurisdiction.is_empty() {
            return Err(ComplianceFilterError::InvalidInput);
        }

        let lk = CfKey::List(source.clone());
        let mut list: SanctionsList = env
            .storage()
            .persistent()
            .get(&lk)
            .ok_or(ComplianceFilterError::NotFound)?;

        let ek = CfKey::Entries(source.clone());
        let mut entries: Vec<Address> = env
            .storage()
            .persistent()
            .get(&ek)
            .unwrap_or_else(|| Vec::new(&env));

        let mut added = 0u32;
        for address in addresses.iter() {
            if !entries.iter().any(|e| e == address) {
                entries.push_back(address.clone());
                Self::append_audit(&env, &address, b"batch_sanctioned", &reason);
                added += 1;
            }
        }

        if added > 0 {
            list.entry_count = entries.len() as u32;
            list.last_updated = env.ledger().timestamp();
            Self::persist(&env, &ek, &entries);
            Self::persist(&env, &lk, &list);
        }

        Ok(added)
    }

    /// Deactivate a sanctions list without deleting it.
    pub fn deactivate_sanctions_list(
        env: Env,
        admin: Address,
        source: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        let k = CfKey::List(source);
        let mut list: SanctionsList = env
            .storage()
            .persistent()
            .get(&k)
            .ok_or(ComplianceFilterError::NotFound)?;
        list.active = false;
        list.last_updated = env.ledger().timestamp();
        env.storage().persistent().set(&k, &list);
        Ok(())
    }

    pub fn get_sanctions_list(env: Env, source: Bytes) -> Option<SanctionsList> {
        env.storage().persistent().get(&CfKey::List(source))
    }

    /// Return `true` if the address appears on any active sanctions list.
    pub fn is_sanctioned(env: Env, address: Address) -> bool {
        let (_, blocked) = Self::run_screening(&env, &address);
        blocked
    }

    // ── Paginated queries ─────────────────────────────────────────────────────

    pub fn get_sanctioned_addresses(env: Env, page: u32, page_size: u32) -> PaginatedAddresses {
        let sources: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CfKey::ListIndex)
            .unwrap_or_else(|| Vec::new(&env));

        let mut all: Vec<Address> = Vec::new(&env);
        for source in sources.iter() {
            let list: Option<SanctionsList> =
                env.storage().persistent().get(&CfKey::List(source.clone()));
            if let Some(l) = list {
                if !l.active {
                    continue;
                }
                let entries: Vec<Address> = env
                    .storage()
                    .persistent()
                    .get(&CfKey::Entries(source))
                    .unwrap_or_else(|| Vec::new(&env));
                for entry in entries.iter() {
                    // Deduplicate across lists.
                    if !all.iter().any(|a| a == entry) {
                        all.push_back(entry);
                    }
                }
            }
        }

        Self::paginate_addresses(&env, &all, page, page_size)
    }

    // ── Screening ─────────────────────────────────────────────────────────────

    /// Screen a single address and persist the result. Returns
    /// `AddressBlocked` or `HighRisk` when applicable.
    pub fn screen_address(
        env: Env,
        address: Address,
    ) -> Result<ScreeningResult, ComplianceFilterError> {
        let (mut result, blocked) = Self::run_screening(&env, &address);

        // Merge in any previously stored oracle risk score.
        if let Some(stored) = env
            .storage()
            .persistent()
            .get::<CfKey, ScreeningResult>(&CfKey::Screening(address.clone()))
        {
            // Only use stored score if it is not stale.
            let age = env.ledger().timestamp().saturating_sub(stored.timestamp);
            if age <= ORACLE_STALENESS_SECS && stored.risk_score > result.risk_score {
                result.risk_score = stored.risk_score;
                if result.risk_score >= MAX_RISK_SCORE {
                    result.status = Bytes::from_slice(&env, b"blocked");
                } else if result.risk_score > HIGH_RISK_THRESHOLD {
                    result.status = Bytes::from_slice(&env, b"suspicious");
                }
            }
        }

        let sk = CfKey::Screening(address.clone());
        Self::persist(&env, &sk, &result);

        Self::append_audit(&env, &address, b"screen", &result.risk_flags_bytes(&env));

        env.events().publish(
            (Symbol::new(&env, "screened"), address.clone()),
            result.risk_score,
        );

        if blocked || result.risk_score >= MAX_RISK_SCORE {
            return Err(ComplianceFilterError::AddressBlocked);
        }
        if result.risk_score > HIGH_RISK_THRESHOLD {
            return Err(ComplianceFilterError::HighRisk);
        }

        Ok(result)
    }

    /// Batch screening. Returns results for all addresses without error-aborting
    /// on hits — the caller inspects `blocked` on each `BatchScreenResult`.
    pub fn batch_screen_addresses(
        env: Env,
        addresses: Vec<Address>,
    ) -> Result<Vec<BatchScreenResult>, ComplianceFilterError> {
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(ComplianceFilterError::BatchTooLarge);
        }

        let mut results = Vec::new(&env);
        for addr in addresses.iter() {
            let (result, blocked) = Self::run_screening(&env, &addr);
            results.push_back(BatchScreenResult {
                address: addr,
                blocked,
                risk_score: result.risk_score,
                status: result.status,
            });
        }
        Ok(results)
    }

    /// Update the oracle-supplied risk score for an address.
    /// Only registered oracles may call this. Rejects scores > 100.
    pub fn update_risk_score(
        env: Env,
        oracle: Address,
        address: Address,
        new_score: u32,
        reason: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        oracle.require_auth();
        Self::assert_oracle(&env, &oracle)?;

        if reason.is_empty() {
            return Err(ComplianceFilterError::InvalidInput);
        }
        if new_score > MAX_RISK_SCORE {
            return Err(ComplianceFilterError::InvalidRiskScore);
        }

        let sk = CfKey::Screening(address.clone());
        let mut result: ScreeningResult =
            env.storage()
                .persistent()
                .get(&sk)
                .unwrap_or_else(|| ScreeningResult {
                    address: address.clone(),
                    status: Bytes::from_slice(&env, b"clear"),
                    risk_score: 0,
                    matches: Vec::new(&env),
                    timestamp: 0,
                });

        result.risk_score = new_score;
        result.status = Self::status_from_score(&env, new_score, !result.matches.is_empty());
        result.timestamp = env.ledger().timestamp();

        Self::persist(&env, &sk, &result);
        Self::append_audit(&env, &address, b"risk_score_update", &reason);

        env.events().publish(
            (Symbol::new(&env, "risk_updated"), address, oracle),
            new_score,
        );
        Ok(())
    }

    pub fn get_screening_result(env: Env, address: Address) -> Option<ScreeningResult> {
        env.storage().persistent().get(&CfKey::Screening(address))
    }

    // ── Compliance rules ──────────────────────────────────────────────────────

    /// Register or overwrite a compliance rule for a jurisdiction. Admin only.
    pub fn register_compliance_rule(
        env: Env,
        admin: Address,
        jurisdiction: Bytes,
        requirement: Bytes,
        enforcement: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if jurisdiction.is_empty() || requirement.is_empty() || enforcement.is_empty() {
            return Err(ComplianceFilterError::InvalidInput);
        }

        let rule = ComplianceRule {
            jurisdiction: jurisdiction.clone(),
            requirement,
            enforcement,
            active: true,
            created: env.ledger().timestamp(),
        };
        let k = CfKey::Rule(jurisdiction.clone());
        Self::persist(&env, &k, &rule);

        env.events()
            .publish((Symbol::new(&env, "rule_reg"),), jurisdiction);
        Ok(())
    }

    /// Deactivate a compliance rule without deleting it.
    pub fn deactivate_compliance_rule(
        env: Env,
        admin: Address,
        jurisdiction: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        let k = CfKey::Rule(jurisdiction.clone());
        let mut rule: ComplianceRule = env
            .storage()
            .persistent()
            .get(&k)
            .ok_or(ComplianceFilterError::NotFound)?;
        rule.active = false;
        env.storage().persistent().set(&k, &rule);
        Ok(())
    }

    pub fn get_compliance_rule(env: Env, jurisdiction: Bytes) -> Option<ComplianceRule> {
        env.storage().persistent().get(&CfKey::Rule(jurisdiction))
    }

    // ── Risk weight configuration ─────────────────────────────────────────

    /// Configure risk assessment weights. Emits RiskWeightsConfigured event.
    /// Only admin may call this.
    pub fn configure_risk_weights(
        env: Env,
        admin: Address,
        sanctions_weight: u32,
        oracle_weight: u32,
        high_risk_threshold: u32,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if high_risk_threshold == 0 || high_risk_threshold > MAX_RISK_SCORE {
            return Err(ComplianceFilterError::InvalidRiskScore);
        }

        let weights = RiskWeights {
            sanctions_weight,
            oracle_weight,
            high_risk_threshold,
            last_updated: env.ledger().timestamp(),
        };

        Self::persist(&env, &CfKey::RiskWeights, &weights);

        env.events().publish(
            (Symbol::new(&env, "RiskWeightsConfigured"),),
            (sanctions_weight, oracle_weight, high_risk_threshold),
        );

        Ok(())
    }

    pub fn get_risk_weights(env: Env) -> Option<RiskWeights> {
        env.storage().persistent().get(&CfKey::RiskWeights)
    }

    /// Set risk assessment weights using a structured `RiskWeights` value.
    /// Admin-only. Emits `RiskWeightsSet` event.
    pub fn set_risk_weights(
        env: Env,
        admin: Address,
        weights: RiskWeights,
    ) -> Result<(), ComplianceFilterError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if weights.high_risk_threshold == 0
            || weights.high_risk_threshold > MAX_RISK_SCORE
        {
            return Err(ComplianceFilterError::InvalidRiskScore);
        }

        let mut stored = weights;
        stored.last_updated = env.ledger().timestamp();

        Self::persist(&env, &CfKey::RiskWeights, &stored);

        env.events().publish(
            (Symbol::new(&env, "RiskWeightsSet"),),
            (
                stored.sanctions_weight,
                stored.oracle_weight,
                stored.high_risk_threshold,
            ),
        );

        Ok(())
    }

    /// Assess risk for an address by combining sanctions screening and oracle
    /// risk scores using the configured weights.
    ///
    /// Returns a `RiskAssessment` with the aggregated score, contributing
    /// factors, and an overall `RiskLevel`.
    pub fn assess_risk(
        env: Env,
        address: Address,
    ) -> RiskAssessment {
        // 1. Sanctions screening
        let (screening, blocked) = Self::run_screening(&env, &address);
        let sanction_score: u32 = if blocked { MAX_RISK_SCORE } else { 0 };

        // 2. Oracle score
        let oracle_score: u32 = env
            .storage()
            .persistent()
            .get::<CfKey, ScreeningResult>(&CfKey::Screening(address.clone()))
            .map(|stored| {
                let age = env.ledger().timestamp().saturating_sub(stored.timestamp);
                if age <= ORACLE_STALENESS_SECS {
                    stored.risk_score
                } else {
                    0
                }
            })
            .unwrap_or(0);

        // 3. Load weights (default to 50/50 if not configured)
        let weights: RiskWeights = env
            .storage()
            .persistent()
            .get(&CfKey::RiskWeights)
            .unwrap_or(RiskWeights {
                sanctions_weight: 50,
                oracle_weight: 50,
                high_risk_threshold: HIGH_RISK_THRESHOLD,
                last_updated: 0,
            });

        let total_weight = weights.sanctions_weight.saturating_add(weights.oracle_weight);
        let aggregated_score: u32 = if total_weight == 0 {
            0
        } else {
            (sanction_score
                .saturating_mul(weights.sanctions_weight)
                .saturating_add(oracle_score.saturating_mul(weights.oracle_weight)))
                / total_weight
        };

        // 4. Build risk factors
        let mut factors = Vec::new(&env);

        factors.push_back(RiskFactor {
            name: Bytes::from_slice(&env, b"sanctions"),
            score: sanction_score,
            weight: weights.sanctions_weight,
            description: if blocked {
                Bytes::from_slice(&env, b"Address found on active sanctions list(s)")
            } else {
                Bytes::from_slice(&env, b"No sanctions matches")
            },
        });

        factors.push_back(RiskFactor {
            name: Bytes::from_slice(&env, b"oracle"),
            score: oracle_score,
            weight: weights.oracle_weight,
            description: if oracle_score > 0 {
                Bytes::from_slice(&env, b"Oracle-assigned risk score")
            } else {
                Bytes::from_slice(&env, b"No oracle risk data")
            },
        });

        // 5. Determine overall risk level
        let overall = if aggregated_score >= MAX_RISK_SCORE {
            RiskLevel::Critical
        } else if aggregated_score > weights.high_risk_threshold {
            RiskLevel::High
        } else if aggregated_score > weights.high_risk_threshold / 2 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        RiskAssessment {
            score: aggregated_score,
            factors,
            overall,
        }
    }

    // ── Regulatory reports & audit trail ──────────────────────────────────────

    /// File a regulatory report for a subject address.
    /// De-duplicated by timestamp — at most one report per second per subject.
    pub fn file_regulatory_report(
        env: Env,
        reporter: Address,
        subject: Address,
        activity_summary: Bytes,
        risk_flags: Bytes,
    ) -> Result<(), ComplianceFilterError> {
        reporter.require_auth();

        if activity_summary.is_empty() {
            return Err(ComplianceFilterError::InvalidInput);
        }

        let ts = env.ledger().timestamp();
        let k = CfKey::Audit(subject.clone(), ts);
        if env.storage().persistent().has(&k) {
            // Already filed this second — silently succeed.
            return Ok(());
        }

        let report = RegulatoryReport {
            subject: subject.clone(),
            activity_summary,
            risk_flags,
            timestamp: ts,
            ledger_sequence: env.ledger().sequence(),
        };

        Self::persist(&env, &k, &report);
        Self::append_audit_ts(&env, &subject, ts);

        env.events()
            .publish((Symbol::new(&env, "report_filed"), subject, reporter), ts);
        Ok(())
    }

    pub fn get_audit_trail(env: Env, subject: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&CfKey::AuditIndex(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_audit_trail_paginated(
        env: Env,
        subject: Address,
        page: u32,
        page_size: u32,
    ) -> (Vec<u64>, bool) {
        let timestamps: Vec<u64> = env
            .storage()
            .persistent()
            .get(&CfKey::AuditIndex(subject))
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = timestamps.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(ts) = timestamps.get(i) {
                    data.push_back(ts);
                }
            }
        }

        let has_more = (start + size) < total;
        (data, has_more)
    }

    pub fn get_regulatory_report(
        env: Env,
        subject: Address,
        timestamp: u64,
    ) -> Option<RegulatoryReport> {
        env.storage()
            .persistent()
            .get(&CfKey::Audit(subject, timestamp))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<Address, ComplianceFilterError> {
        env.storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(env, KEY_ADMIN))
            .ok_or(ComplianceFilterError::NotInitialized)
    }

    fn assert_admin(env: &Env, caller: &Address) -> Result<(), ComplianceFilterError> {
        let admin = Self::require_admin(env)?;
        if *caller != admin {
            return Err(ComplianceFilterError::Unauthorized);
        }
        Ok(())
    }

    fn get_oracles(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get::<Symbol, Vec<Address>>(&Symbol::new(env, KEY_ORACLES))
            .unwrap_or_else(|| Vec::new(env))
    }

    fn assert_oracle(env: &Env, oracle: &Address) -> Result<(), ComplianceFilterError> {
        let oracles = Self::get_oracles(env);
        if !oracles.iter().any(|o| &o == oracle) {
            return Err(ComplianceFilterError::OracleNotRegistered);
        }
        Ok(())
    }

    fn run_screening(env: &Env, address: &Address) -> (ScreeningResult, bool) {
        let sources: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CfKey::ListIndex)
            .unwrap_or_else(|| Vec::new(env));

        let mut matches: Vec<Bytes> = Vec::new(env);
        let mut blocked = false;

        for source in sources.iter() {
            let list: Option<SanctionsList> =
                env.storage().persistent().get(&CfKey::List(source.clone()));
            if let Some(l) = list {
                if !l.active {
                    continue;
                }
                let entries: Vec<Address> = env
                    .storage()
                    .persistent()
                    .get(&CfKey::Entries(source.clone()))
                    .unwrap_or_else(|| Vec::new(env));
                if entries.iter().any(|e| e == *address) {
                    matches.push_back(source.clone());
                    blocked = true;
                }
            }
        }

        let risk_score: u32 = if blocked { MAX_RISK_SCORE } else { 0 };
        let status = Self::status_from_score(env, risk_score, blocked);

        (
            ScreeningResult {
                address: address.clone(),
                status,
                risk_score,
                matches,
                timestamp: env.ledger().timestamp(),
            },
            blocked,
        )
    }

    fn status_from_score(env: &Env, score: u32, blocked: bool) -> Bytes {
        if blocked || score >= MAX_RISK_SCORE {
            Bytes::from_slice(env, b"blocked")
        } else if score > HIGH_RISK_THRESHOLD {
            Bytes::from_slice(env, b"suspicious")
        } else {
            Bytes::from_slice(env, b"clear")
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
            .extend_ttl(key, COMPLIANCE_TTL_LEDGERS, COMPLIANCE_TTL_LEDGERS);
    }

    fn append_audit(env: &Env, address: &Address, action: &[u8], detail: &Bytes) {
        let ts = env.ledger().timestamp();
        let mut summary = Bytes::from_slice(env, action);
        summary.append(&Bytes::from_slice(env, b":"));
        summary.append(detail);

        let k = CfKey::Audit(address.clone(), ts);
        if !env.storage().persistent().has(&k) {
            let report = RegulatoryReport {
                subject: address.clone(),
                activity_summary: summary,
                risk_flags: detail.clone(),
                timestamp: ts,
                ledger_sequence: env.ledger().sequence(),
            };
            Self::persist(env, &k, &report);
            Self::append_audit_ts(env, address, ts);
        }
    }

    fn append_audit_ts(env: &Env, address: &Address, ts: u64) {
        let idx = CfKey::AuditIndex(address.clone());
        let mut timestamps: Vec<u64> = env
            .storage()
            .persistent()
            .get(&idx)
            .unwrap_or_else(|| Vec::new(env));
        timestamps.push_back(ts);
        Self::persist(env, &idx, &timestamps);
    }

    fn paginate_addresses(
        env: &Env,
        items: &Vec<Address>,
        page: u32,
        page_size: u32,
    ) -> PaginatedAddresses {
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

        PaginatedAddresses {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }
}

impl ScreeningResult {
    fn risk_flags_bytes(&self, env: &Env) -> Bytes {
        if self.matches.is_empty() {
            Bytes::from_slice(env, b"none")
        } else {
            let mut out = Bytes::from_slice(env, b"matched:");
            for m in self.matches.iter() {
                out.append(&m);
                out.append(&Bytes::from_slice(env, b","));
            }
            out
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{Address, Bytes, BytesN, Env};

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

    fn bootstrap(env: &Env) -> Address {
        let admin = Address::generate(env);
        ComplianceFilter::initialize(env.clone(), admin.clone()).unwrap();
        admin
    }

    fn default_hash(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[0u8; 32])
    }

    fn create_list(env: &Env, admin: &Address, source: &[u8]) -> Bytes {
        let source_bytes = Bytes::from_slice(env, source);
        ComplianceFilter::update_sanctions_list(
            env.clone(),
            admin.clone(),
            source_bytes.clone(),
            default_hash(env),
            0,
        )
        .unwrap();
        source_bytes
    }

    // ── Initialization ────────────────────────────────────────────────────────

    #[test]
    fn initializes_successfully() {
        let env = setup_env();
        let admin = Address::generate(&env);
        assert!(ComplianceFilter::initialize(env.clone(), admin).is_ok());
    }

    #[test]
    fn double_initialize_returns_error() {
        let env = setup_env();
        bootstrap(&env);
        let result = ComplianceFilter::initialize(env.clone(), Address::generate(&env));
        assert_eq!(
            result.unwrap_err(),
            ComplianceFilterError::AlreadyInitialized
        );
    }

    // ── Admin management ──────────────────────────────────────────────────────

    #[test]
    fn non_admin_cannot_update_list() {
        let env = setup_env();
        bootstrap(&env);
        let intruder = Address::generate(&env);
        let result = ComplianceFilter::update_sanctions_list(
            env.clone(),
            intruder,
            Bytes::from_slice(&env, b"source"),
            default_hash(&env),
            0,
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::Unauthorized);
    }

    #[test]
    fn admin_can_be_transferred() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let new_admin = Address::generate(&env);
        ComplianceFilter::transfer_admin(env.clone(), admin.clone(), new_admin.clone()).unwrap();
        // Old admin should no longer be able to create a list.
        let result = ComplianceFilter::update_sanctions_list(
            env.clone(),
            admin,
            Bytes::from_slice(&env, b"src"),
            default_hash(&env),
            0,
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::Unauthorized);
        // New admin can.
        assert!(ComplianceFilter::update_sanctions_list(
            env.clone(),
            new_admin,
            Bytes::from_slice(&env, b"src"),
            default_hash(&env),
            0,
        )
        .is_ok());
    }

    // ── Oracle management ─────────────────────────────────────────────────────

    #[test]
    fn registered_oracle_can_update_risk_score() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let oracle = Address::generate(&env);
        let user = Address::generate(&env);

        ComplianceFilter::register_oracle(env.clone(), admin, oracle.clone()).unwrap();

        assert!(ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user,
            50,
            Bytes::from_slice(&env, b"routine check"),
        )
        .is_ok());
    }

    #[test]
    fn unregistered_oracle_is_rejected() {
        let env = setup_env();
        bootstrap(&env);
        let impostor = Address::generate(&env);
        let user = Address::generate(&env);

        let result = ComplianceFilter::update_risk_score(
            env.clone(),
            impostor,
            user,
            50,
            Bytes::from_slice(&env, b"reason"),
        );
        assert_eq!(
            result.unwrap_err(),
            ComplianceFilterError::OracleNotRegistered
        );
    }

    #[test]
    fn duplicate_oracle_registration_returns_error() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let oracle = Address::generate(&env);

        ComplianceFilter::register_oracle(env.clone(), admin.clone(), oracle.clone()).unwrap();
        let result = ComplianceFilter::register_oracle(env.clone(), admin, oracle);
        assert_eq!(result.unwrap_err(), ComplianceFilterError::AlreadyExists);
    }

    #[test]
    fn deregistered_oracle_cannot_update_score() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let oracle = Address::generate(&env);
        let user = Address::generate(&env);

        ComplianceFilter::register_oracle(env.clone(), admin.clone(), oracle.clone()).unwrap();
        ComplianceFilter::deregister_oracle(env.clone(), admin, oracle.clone()).unwrap();

        let result = ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user,
            30,
            Bytes::from_slice(&env, b"reason"),
        );
        assert_eq!(
            result.unwrap_err(),
            ComplianceFilterError::OracleNotRegistered
        );
    }

    #[test]
    fn risk_score_above_100_returns_error() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let oracle = Address::generate(&env);
        let user = Address::generate(&env);

        ComplianceFilter::register_oracle(env.clone(), admin, oracle.clone()).unwrap();

        let result = ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user,
            101,
            Bytes::from_slice(&env, b"reason"),
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidRiskScore);
    }

    #[test]
    fn risk_score_boundary_100_is_accepted() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let oracle = Address::generate(&env);
        let user = Address::generate(&env);
        ComplianceFilter::register_oracle(env.clone(), admin, oracle.clone()).unwrap();
        assert!(ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user,
            100,
            Bytes::from_slice(&env, b"reason"),
        )
        .is_ok());
    }

    // ── Sanctions list ────────────────────────────────────────────────────────

    #[test]
    fn sanctions_list_is_created_and_retrieved() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let list = ComplianceFilter::get_sanctions_list(env.clone(), source).unwrap();
        assert!(list.active);
        assert_eq!(list.entry_count, 0);
    }

    #[test]
    fn empty_source_is_rejected() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let result = ComplianceFilter::update_sanctions_list(
            env.clone(),
            admin,
            Bytes::new(&env),
            default_hash(&env),
            0,
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidInput);
    }

    #[test]
    fn load_list_entries_rejects_wrong_hash() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");

        let wrong_hash = BytesN::from_array(&env, &[1u8; 32]);
        let result = ComplianceFilter::load_list_entries(
            env.clone(),
            admin,
            source,
            Vec::new(&env),
            wrong_hash,
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidHash);
    }

    #[test]
    fn load_list_entries_accepts_correct_hash() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");

        assert!(ComplianceFilter::load_list_entries(
            env.clone(),
            admin,
            source,
            Vec::new(&env),
            default_hash(&env),
        )
        .is_ok());
    }

    #[test]
    fn add_address_to_list_increases_entry_count() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let target = Address::generate(&env);

        ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin.clone(),
            source.clone(),
            target,
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        let list = ComplianceFilter::get_sanctions_list(env.clone(), source).unwrap();
        assert_eq!(list.entry_count, 1);
    }

    #[test]
    fn adding_duplicate_address_returns_error() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let target = Address::generate(&env);

        ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin.clone(),
            source.clone(),
            target.clone(),
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        let result = ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin,
            source,
            target,
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::AlreadyExists);
    }

    #[test]
    fn remove_address_decreases_entry_count() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let target = Address::generate(&env);

        ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin.clone(),
            source.clone(),
            target.clone(),
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        ComplianceFilter::remove_from_sanctions_list(
            env.clone(),
            admin.clone(),
            source.clone(),
            target,
        )
        .unwrap();

        let list = ComplianceFilter::get_sanctions_list(env.clone(), source).unwrap();
        assert_eq!(list.entry_count, 0);
    }

    #[test]
    fn remove_absent_address_returns_not_found() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");

        let result = ComplianceFilter::remove_from_sanctions_list(
            env.clone(),
            admin,
            source,
            Address::generate(&env),
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::NotFound);
    }

    #[test]
    fn deactivated_list_does_not_block_screening() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let target = Address::generate(&env);

        ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin.clone(),
            source.clone(),
            target.clone(),
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        ComplianceFilter::deactivate_sanctions_list(env.clone(), admin.clone(), source.clone())
            .unwrap();

        assert!(!ComplianceFilter::is_sanctioned(env.clone(), target));
    }

    // ── Batch operations ──────────────────────────────────────────────────────

    #[test]
    fn batch_add_inserts_multiple_addresses() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"BATCH");

        let mut addresses = Vec::new(&env);
        for _ in 0..5 {
            addresses.push_back(Address::generate(&env));
        }

        let added = ComplianceFilter::batch_add_to_sanctions_list(
            env.clone(),
            admin.clone(),
            source.clone(),
            addresses,
            Bytes::from_slice(&env, b"bulk"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        assert_eq!(added, 5);
        let list = ComplianceFilter::get_sanctions_list(env, source).unwrap();
        assert_eq!(list.entry_count, 5);
    }

    #[test]
    fn batch_add_exceeding_limit_returns_error() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"BATCH");

        let mut addresses = Vec::new(&env);
        for _ in 0..(MAX_BATCH_SIZE + 1) {
            addresses.push_back(Address::generate(&env));
        }

        let result = ComplianceFilter::batch_add_to_sanctions_list(
            env.clone(),
            admin,
            source,
            addresses,
            Bytes::from_slice(&env, b"bulk"),
            Bytes::from_slice(&env, b"US"),
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::BatchTooLarge);
    }

    #[test]
    fn batch_screen_returns_result_per_address() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let blocked = Address::generate(&env);
        let clean = Address::generate(&env);

        ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin,
            source,
            blocked.clone(),
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        let mut to_screen = Vec::new(&env);
        to_screen.push_back(blocked.clone());
        to_screen.push_back(clean.clone());

        let results = ComplianceFilter::batch_screen_addresses(env.clone(), to_screen).unwrap();
        assert_eq!(results.len(), 2);

        let r0 = results.get(0).unwrap();
        let r1 = results.get(1).unwrap();

        assert!(r0.blocked);
        assert_eq!(r0.risk_score, MAX_RISK_SCORE);
        assert!(!r1.blocked);
        assert_eq!(r1.risk_score, 0);
    }

    // ── Screening ─────────────────────────────────────────────────────────────

    #[test]
    fn sanctioned_address_returns_blocked_error() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let target = Address::generate(&env);

        ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin,
            source,
            target.clone(),
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        let result = ComplianceFilter::screen_address(env.clone(), target.clone());
        assert_eq!(result.unwrap_err(), ComplianceFilterError::AddressBlocked);
        assert!(ComplianceFilter::is_sanctioned(env, target));
    }

    #[test]
    fn clean_address_returns_ok() {
        let env = setup_env();
        bootstrap(&env);
        let clean = Address::generate(&env);
        let result = ComplianceFilter::screen_address(env.clone(), clean.clone());
        assert!(result.is_ok());
        assert!(!ComplianceFilter::is_sanctioned(env, clean));
    }

    #[test]
    fn high_risk_score_returns_high_risk_error() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let oracle = Address::generate(&env);
        let user = Address::generate(&env);

        ComplianceFilter::register_oracle(env.clone(), admin, oracle.clone()).unwrap();
        ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user.clone(),
            80,
            Bytes::from_slice(&env, b"suspicious activity"),
        )
        .unwrap();

        // Trigger screening which merges stored risk score.
        let result = ComplianceFilter::screen_address(env.clone(), user);
        assert_eq!(result.unwrap_err(), ComplianceFilterError::HighRisk);
    }

    #[test]
    fn screening_result_is_persisted() {
        let env = setup_env();
        bootstrap(&env);
        let user = Address::generate(&env);
        ComplianceFilter::screen_address(env.clone(), user.clone()).ok();
        let stored = ComplianceFilter::get_screening_result(env.clone(), user);
        assert!(stored.is_some());
    }

    // ── Compliance rules ──────────────────────────────────────────────────────

    #[test]
    fn compliance_rule_is_registered_and_retrieved() {
        let env = setup_env();
        let admin = bootstrap(&env);

        ComplianceFilter::register_compliance_rule(
            env.clone(),
            admin,
            Bytes::from_slice(&env, b"EU"),
            Bytes::from_slice(&env, b"GDPR"),
            Bytes::from_slice(&env, b"strict"),
        )
        .unwrap();

        let rule =
            ComplianceFilter::get_compliance_rule(env.clone(), Bytes::from_slice(&env, b"EU"))
                .unwrap();
        assert!(rule.active);
    }

    #[test]
    fn deactivated_rule_is_inactive() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let jurisdiction = Bytes::from_slice(&env, b"EU");

        ComplianceFilter::register_compliance_rule(
            env.clone(),
            admin.clone(),
            jurisdiction.clone(),
            Bytes::from_slice(&env, b"GDPR"),
            Bytes::from_slice(&env, b"strict"),
        )
        .unwrap();

        ComplianceFilter::deactivate_compliance_rule(env.clone(), admin, jurisdiction.clone())
            .unwrap();

        let rule = ComplianceFilter::get_compliance_rule(env.clone(), jurisdiction).unwrap();
        assert!(!rule.active);
    }

    #[test]
    fn empty_fields_rejected_on_rule_registration() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let result = ComplianceFilter::register_compliance_rule(
            env.clone(),
            admin,
            Bytes::new(&env),
            Bytes::from_slice(&env, b"GDPR"),
            Bytes::from_slice(&env, b"strict"),
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidInput);
    }

    // ── Regulatory reports & audit trail ──────────────────────────────────────

    #[test]
    fn regulatory_report_is_filed_and_retrieved() {
        let env = setup_env();
        bootstrap(&env);
        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);

        let ts = env.ledger().timestamp();
        ComplianceFilter::file_regulatory_report(
            env.clone(),
            reporter,
            subject.clone(),
            Bytes::from_slice(&env, b"summary"),
            Bytes::from_slice(&env, b"flags"),
        )
        .unwrap();

        let report = ComplianceFilter::get_regulatory_report(env.clone(), subject.clone(), ts);
        assert!(report.is_some());

        let trail = ComplianceFilter::get_audit_trail(env.clone(), subject);
        assert!(!trail.is_empty());
    }

    #[test]
    fn empty_activity_summary_is_rejected() {
        let env = setup_env();
        bootstrap(&env);
        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);

        let result = ComplianceFilter::file_regulatory_report(
            env.clone(),
            reporter,
            subject,
            Bytes::new(&env),
            Bytes::from_slice(&env, b"flags"),
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidInput);
    }

    #[test]
    fn paginated_audit_trail_respects_page_boundaries() {
        let env = setup_env();
        bootstrap(&env);
        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);

        // File one report (timestamp deduplication means we can only file once per second).
        ComplianceFilter::file_regulatory_report(
            env.clone(),
            reporter,
            subject.clone(),
            Bytes::from_slice(&env, b"summary"),
            Bytes::from_slice(&env, b"flags"),
        )
        .unwrap();

        let (page0, has_more) =
            ComplianceFilter::get_audit_trail_paginated(env.clone(), subject, 0, 10);
        assert_eq!(page0.len(), 1);
        assert!(!has_more);
    }

    // ── Paginated sanctioned addresses ────────────────────────────────────────

    #[test]
    fn paginated_sanctioned_addresses_deduplicates_across_lists() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let shared = Address::generate(&env);

        let src1 = create_list(&env, &admin, b"LIST1");
        let src2 = create_list(&env, &admin, b"LIST2");

        for source in [src1, src2] {
            ComplianceFilter::add_to_sanctions_list(
                env.clone(),
                admin.clone(),
                source,
                shared.clone(),
                Bytes::from_slice(&env, b"reason"),
                Bytes::from_slice(&env, b"US"),
            )
            .unwrap();
        }

        let page = ComplianceFilter::get_sanctioned_addresses(env.clone(), 0, 10);
        // `shared` appears in both lists but should only show up once.
        assert_eq!(page.total, 1);
    }

    // ── Risk assessment ───────────────────────────────────────────────────────

    #[test]
    fn assess_risk_clean_address_returns_low() {
        let env = setup_env();
        bootstrap(&env);
        let clean = Address::generate(&env);

        let assessment = ComplianceFilter::assess_risk(env.clone(), clean);
        assert_eq!(assessment.overall, RiskLevel::Low);
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.factors.len(), 2);
        assert_eq!(assessment.factors.get(0).unwrap().name, Bytes::from_slice(&env, b"sanctions"));
        assert_eq!(assessment.factors.get(1).unwrap().name, Bytes::from_slice(&env, b"oracle"));
    }

    #[test]
    fn assess_risk_sanctioned_address_returns_critical() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let target = Address::generate(&env);

        ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin,
            source,
            target.clone(),
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        let assessment = ComplianceFilter::assess_risk(env.clone(), target);
        assert_eq!(assessment.overall, RiskLevel::Critical);
        assert_eq!(assessment.score, MAX_RISK_SCORE);
    }

    #[test]
    fn assess_risk_with_oracle_score_returns_medium() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let oracle = Address::generate(&env);
        let user = Address::generate(&env);

        ComplianceFilter::register_oracle(env.clone(), admin, oracle.clone()).unwrap();
        ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user.clone(),
            50,
            Bytes::from_slice(&env, b"suspicious activity"),
        )
        .unwrap();

        let assessment = ComplianceFilter::assess_risk(env.clone(), user);
        // Default weights: sanctions=50, oracle=50 => (0*50 + 50*50)/100 = 25
        assert_eq!(assessment.score, 25);
        assert_eq!(assessment.overall, RiskLevel::Medium);
    }

    #[test]
    fn assess_risk_combined_sanctions_and_oracle() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let oracle = Address::generate(&env);
        let source = create_list(&env, &admin, b"OFAC");
        let target = Address::generate(&env);

        // Sanction the address
        ComplianceFilter::add_to_sanctions_list(
            env.clone(),
            admin.clone(),
            source,
            target.clone(),
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"US"),
        )
        .unwrap();

        // Also assign a high oracle score
        ComplianceFilter::register_oracle(env.clone(), admin, oracle.clone()).unwrap();
        ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            target.clone(),
            90,
            Bytes::from_slice(&env, b"suspicious"),
        )
        .unwrap();

        let assessment = ComplianceFilter::assess_risk(env.clone(), target);
        // sanctions=100*50 + oracle=90*50 = 9500 / 100 = 95
        assert_eq!(assessment.score, 95);
        assert_eq!(assessment.overall, RiskLevel::High);
    }

    // ── set_risk_weights ──────────────────────────────────────────────────────

    #[test]
    fn set_risk_weights_stores_and_retrieves() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let weights = RiskWeights {
            sanctions_weight: 70,
            oracle_weight: 30,
            high_risk_threshold: 75,
            last_updated: 0,
        };

        ComplianceFilter::set_risk_weights(env.clone(), admin, weights).unwrap();

        let stored = ComplianceFilter::get_risk_weights(env.clone()).unwrap();
        assert_eq!(stored.sanctions_weight, 70);
        assert_eq!(stored.oracle_weight, 30);
        assert_eq!(stored.high_risk_threshold, 75);
    }

    #[test]
    fn set_risk_weights_rejects_zero_threshold() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let weights = RiskWeights {
            sanctions_weight: 50,
            oracle_weight: 50,
            high_risk_threshold: 0,
            last_updated: 0,
        };

        let result = ComplianceFilter::set_risk_weights(env.clone(), admin, weights);
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidRiskScore);
    }

    #[test]
    fn set_risk_weights_rejects_threshold_above_max() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let weights = RiskWeights {
            sanctions_weight: 50,
            oracle_weight: 50,
            high_risk_threshold: MAX_RISK_SCORE + 1,
            last_updated: 0,
        };

        let result = ComplianceFilter::set_risk_weights(env.clone(), admin, weights);
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidRiskScore);
    }

    #[test]
    fn set_risk_weights_non_admin_rejected() {
        let env = setup_env();
        bootstrap(&env);
        let intruder = Address::generate(&env);

        let weights = RiskWeights {
            sanctions_weight: 70,
            oracle_weight: 30,
            high_risk_threshold: 70,
            last_updated: 0,
        };

        let result = ComplianceFilter::set_risk_weights(env.clone(), intruder, weights);
        assert_eq!(result.unwrap_err(), ComplianceFilterError::Unauthorized);
    }
}
