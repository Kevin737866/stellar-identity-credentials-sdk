use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, Env, Map,
    Symbol, Vec,
};

const SCORE_SCALE: u32 = 10;
const MAX_SCORE: u32 = 1000 * SCORE_SCALE;
const BASE_SCORE: u32 = 80 * SCORE_SCALE;
const CHECKPOINT_INTERVAL: u64 = 60 * 60 * 24;
const MAX_HISTORY_POINTS: u32 = 120;
const MAX_GRAPH_EDGES: u32 = 64;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReputationScoreError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidScore = 4,
    InvalidDepth = 5,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationFactors {
    pub transaction_volume: u32,
    pub transaction_consistency: u32,
    pub credential_count: u32,
    pub credential_diversity: u32,
    pub account_age: u32,
    pub dispute_history: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationHistoryEntry {
    pub timestamp: u64,
    pub score: u32,
    pub event_type: Symbol,
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
pub struct ReputationData {
    pub did: Address,
    pub score: u32,
    pub transaction_count: u32,
    pub successful_transactions: u32,
    pub credential_count: u32,
    pub valid_credentials: u32,
    pub last_updated: u64,
    pub created_at: u64,
    pub reputation_factors: ReputationFactors,
    pub transaction_volume_sum: u64,
    pub counterparty_diversity: u32,
    pub fee_consistency: u32,
    pub contract_interactions: u32,
    pub verified_kyc: u32,
    pub employment_credentials: u32,
    pub academic_credentials: u32,
    pub self_claimed_credentials: u32,
    pub sanctions_matches: u32,
    pub credential_revocations: u32,
    pub disputes: u32,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Profile(Address),
    Working(Address),
    History(Address),
    Trust(Address),
    Population,
}

#[contract]
pub struct ReputationScore;

#[contractimpl]
impl ReputationScore {
    pub fn initialize_reputation(env: Env, did: Address) -> Result<ReputationData, ReputationScoreError> {
        did.require_auth();
        if env.storage().persistent().has(&DataKey::Profile(did.clone())) {
            return Err(ReputationScoreError::AlreadyExists);
        }

        let data = Self::new_profile(&env, did.clone());
        Self::store_profile(&env, &did, &data);
        Self::append_history(&env, &did, ReputationHistoryEntry {
            timestamp: env.ledger().timestamp(),
            score: data.score,
            event_type: symbol_short!("init"),
        });
        Self::track_population(&env, &did);
        Ok(data)
    }

    pub fn calculate_reputation(env: Env, did: Address) -> Result<u32, ReputationScoreError> {
        let mut data = Self::load_profile(&env, &did)?;
        let score = Self::recompute_score(&env, &did, &mut data);
        Self::stage_profile(&env, &did, &data);
        Ok(score)
    }

    pub fn update_reputation(
        env: Env,
        did: Address,
        event_type: Symbol,
        metadata: Map<Symbol, i128>,
    ) -> Result<ReputationData, ReputationScoreError> {
        did.require_auth();
        let mut data = Self::load_profile(&env, &did)?;
        let now = env.ledger().timestamp();

        if event_type == symbol_short!("tx_ok") {
            data.transaction_count += 1;
            data.successful_transactions += 1;
            data.transaction_volume_sum += Self::map_u64(&metadata, &env, symbol_short!("amount"));
            data.counterparty_diversity += Self::map_u32(&metadata, &env, symbol_short!("cp"));
            data.fee_consistency = Self::bounded_add(data.fee_consistency, Self::map_u32(&metadata, &env, symbol_short!("fee")), 1000);
        } else if event_type == symbol_short!("tx_bad") {
            data.transaction_count += 1;
            data.transaction_volume_sum += Self::map_u64(&metadata, &env, symbol_short!("amount"));
            data.disputes += Self::max_u32(1, Self::map_u32(&metadata, &env, symbol_short!("disp")));
        } else if event_type == symbol_short!("cred") {
            data.credential_count += 1;
            if Self::map_u32(&metadata, &env, symbol_short!("valid")) > 0 {
                data.valid_credentials += 1;
            }
            let kind = Self::map_u32(&metadata, &env, symbol_short!("kind"));
            match kind {
                1 => data.verified_kyc += 1,
                2 => data.employment_credentials += 1,
                3 => data.academic_credentials += 1,
                _ => data.self_claimed_credentials += 1,
            }
        } else if event_type == symbol_short!("contract") {
            data.contract_interactions += Self::max_u32(1, Self::map_u32(&metadata, &env, symbol_short!("count")));
        } else if event_type == symbol_short!("dispute") {
            data.disputes += Self::max_u32(1, Self::map_u32(&metadata, &env, symbol_short!("count")));
        } else if event_type == symbol_short!("revoke") {
            data.credential_revocations += Self::max_u32(1, Self::map_u32(&metadata, &env, symbol_short!("count")));
        } else if event_type == symbol_short!("sanctn") {
            data.sanctions_matches += Self::max_u32(1, Self::map_u32(&metadata, &env, symbol_short!("count")));
        }

        data.last_updated = now;
        Self::recompute_score(&env, &did, &mut data);
        Self::stage_profile(&env, &did, &data);
        Self::append_history(&env, &did, ReputationHistoryEntry {
            timestamp: now,
            score: data.score,
            event_type,
        });
        Self::maybe_checkpoint(&env, &did, &data);
        Ok(data)
    }

    pub fn update_transaction_reputation(
        env: Env,
        did: Address,
        successful: bool,
        amount: u64,
    ) -> Result<u32, ReputationScoreError> {
        let mut metadata = Map::new(&env);
        metadata.set(symbol_short!("amount"), amount as i128);
        metadata.set(symbol_short!("cp"), 1i128);
        metadata.set(symbol_short!("fee"), 10i128);
        let event = if successful { symbol_short!("tx_ok") } else { symbol_short!("tx_bad") };
        Ok(Self::update_reputation(env, did, event, metadata)?.score)
    }

    pub fn update_credential_reputation(
        env: Env,
        did: Address,
        credential_valid: bool,
        credential_type: Bytes,
    ) -> Result<u32, ReputationScoreError> {
        let mut metadata = Map::new(&env);
        metadata.set(symbol_short!("valid"), if credential_valid { 1 } else { 0 });
        metadata.set(symbol_short!("kind"), Self::credential_kind(&env, &credential_type) as i128);
        Ok(Self::update_reputation(env, did, symbol_short!("cred"), metadata)?.score)
    }

    pub fn get_reputation_score(env: Env, did: Address) -> Result<u32, ReputationScoreError> {
        Ok(Self::load_profile(&env, &did)?.score)
    }

    pub fn get_reputation_data(env: Env, did: Address) -> Result<ReputationData, ReputationScoreError> {
        Self::load_profile(&env, &did)
    }

    pub fn get_reputation_factors(env: Env, did: Address) -> Result<ReputationFactors, ReputationScoreError> {
        Ok(Self::load_profile(&env, &did)?.reputation_factors)
    }

    pub fn get_reputation_history(
        env: Env,
        did: Address,
        limit: u32,
    ) -> Result<Vec<ReputationHistoryEntry>, ReputationScoreError> {
        let history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(did.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        let len = history.len();
        let start = if len > limit { len - limit } else { 0 };
        let mut result = Vec::new(&env);
        for index in start..len {
            if let Some(entry) = history.get(index) {
                result.push_back(entry);
            }
        }
        Ok(result)
    }

    pub fn get_reputation_percentile(env: Env, did: Address) -> Result<u32, ReputationScoreError> {
        let target = Self::load_profile(&env, &did)?.score;
        let population = Self::population(&env);
        if population.is_empty() {
            return Ok(0);
        }

        let mut below_or_equal = 0u32;
        for subject in population.iter() {
            if let Ok(candidate) = Self::load_profile(&env, &subject) {
                if candidate.score <= target {
                    below_or_equal += 1;
                }
            }
        }

        Ok((below_or_equal * 100) / population.len())
    }

    pub fn meets_reputation_threshold(
        env: Env,
        did: Address,
        threshold: u32,
    ) -> Result<bool, ReputationScoreError> {
        Ok(Self::load_profile(&env, &did)?.score >= threshold * SCORE_SCALE)
    }

    pub fn attest_trust(
        env: Env,
        truster: Address,
        subject: Address,
        weight: u32,
        reason: Bytes,
    ) -> Result<TrustAttestation, ReputationScoreError> {
        truster.require_auth();
        if weight > 1000 {
            return Err(ReputationScoreError::InvalidScore);
        }

        let timestamp = env.ledger().timestamp();
        let edge = TrustAttestation {
            truster: truster.clone(),
            subject: subject.clone(),
            weight,
            reason,
            timestamp,
        };

        let key = DataKey::Trust(truster.clone());
        let mut edges: Vec<TrustAttestation> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));

        let mut replaced = false;
        let mut next_edges = Vec::new(&env);
        for existing in edges.iter() {
            if existing.subject == subject {
                next_edges.push_back(edge.clone());
                replaced = true;
            } else {
                next_edges.push_back(existing);
            }
        }
        if !replaced {
            next_edges.push_back(edge.clone());
        }

        env.storage().persistent().set(&key, &next_edges);
        Self::track_population(&env, &truster);
        Self::track_population(&env, &subject);

        if let Ok(mut trusted) = Self::load_profile(&env, &subject) {
            Self::recompute_score(&env, &subject, &mut trusted);
            Self::stage_profile(&env, &subject, &trusted);
            Self::append_history(&env, &subject, ReputationHistoryEntry {
                timestamp,
                score: trusted.score,
                event_type: symbol_short!("trust"),
            });
            Self::maybe_checkpoint(&env, &subject, &trusted);
        }

        Ok(edge)
    }

    pub fn get_trust_graph(
        env: Env,
        did: Address,
        depth: u32,
    ) -> Result<Vec<TrustAttestation>, ReputationScoreError> {
        if depth == 0 || depth > 4 {
            return Err(ReputationScoreError::InvalidDepth);
        }

        let mut visited = Vec::new(&env);
        let mut frontier = Vec::new(&env);
        let mut graph = Vec::new(&env);
        frontier.push_back(did.clone());
        visited.push_back(did);

        for _ in 0..depth {
            let mut next = Vec::new(&env);
            for current in frontier.iter() {
                let edges: Vec<TrustAttestation> = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Trust(current.clone()))
                    .unwrap_or_else(|| Vec::new(&env));
                for edge in edges.iter() {
                    if graph.len() < MAX_GRAPH_EDGES {
                        graph.push_back(edge.clone());
                    }
                    if !Self::contains_address(&visited, &edge.subject) {
                        visited.push_back(edge.subject.clone());
                        next.push_back(edge.subject);
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }

        Ok(graph)
    }

    pub fn reset_reputation(env: Env, did: Address) -> Result<ReputationData, ReputationScoreError> {
        did.require_auth();
        let data = Self::new_profile(&env, did.clone());
        Self::store_profile(&env, &did, &data);
        Self::append_history(&env, &did, ReputationHistoryEntry {
            timestamp: env.ledger().timestamp(),
            score: data.score,
            event_type: symbol_short!("reset"),
        });
        Ok(data)
    }

    fn new_profile(env: &Env, did: Address) -> ReputationData {
        let now = env.ledger().timestamp();
        ReputationData {
            did,
            score: BASE_SCORE,
            transaction_count: 0,
            successful_transactions: 0,
            credential_count: 0,
            valid_credentials: 0,
            last_updated: now,
            created_at: now,
            reputation_factors: ReputationFactors {
                transaction_volume: 0,
                transaction_consistency: 0,
                credential_count: 0,
                credential_diversity: 0,
                account_age: 0,
                dispute_history: 0,
            },
            transaction_volume_sum: 0,
            counterparty_diversity: 0,
            fee_consistency: 0,
            contract_interactions: 0,
            verified_kyc: 0,
            employment_credentials: 0,
            academic_credentials: 0,
            self_claimed_credentials: 0,
            sanctions_matches: 0,
            credential_revocations: 0,
            disputes: 0,
        }
    }

    fn recompute_score(env: &Env, did: &Address, data: &mut ReputationData) -> u32 {
        let age_days = ((env.ledger().timestamp() - data.created_at) / 86_400) as u32;
        let activity_days = ((env.ledger().timestamp() - data.last_updated) / 86_400) as u32;
        let recency_weight = if activity_days <= 30 {
            100
        } else if activity_days <= 90 {
            80
        } else if activity_days <= 180 {
            60
        } else {
            40
        };

        let tx_volume = Self::min_u32(180, (data.transaction_volume_sum / 250) as u32 + data.contract_interactions * 6);
        let success_rate = if data.transaction_count == 0 {
            0
        } else {
            (data.successful_transactions * 100) / data.transaction_count
        };
        let cadence = Self::min_u32(60, data.transaction_count * 3 + data.counterparty_diversity * 4);
        let tx_consistency = ((success_rate * 2) + cadence + Self::min_u32(40, data.fee_consistency / 10)) * recency_weight / 100;

        let credential_weight = Self::min_u32(
            260,
            data.verified_kyc * 200
                + data.employment_credentials * 100
                + data.academic_credentials * 50
                + data.self_claimed_credentials * 10,
        );
        let credential_diversity = Self::min_u32(
            160,
            (Self::credential_classes(data) * 35) + Self::min_u32(40, data.valid_credentials * 5),
        );
        let account_age = Self::min_u32(140, age_days * 2);
        let dispute_history = Self::min_u32(
            1000,
            data.sanctions_matches * 1000 + data.credential_revocations * 200 + data.disputes * 100,
        );
        let trust_bonus = Self::network_trust_bonus(env, did);

        data.reputation_factors = ReputationFactors {
            transaction_volume: tx_volume,
            transaction_consistency: tx_consistency,
            credential_count: credential_weight,
            credential_diversity,
            account_age,
            dispute_history,
        };

        let positive = BASE_SCORE / SCORE_SCALE
            + tx_volume
            + tx_consistency
            + credential_weight
            + credential_diversity
            + account_age
            + trust_bonus;
        let bounded = if dispute_history >= positive { 0 } else { positive - dispute_history };
        data.score = Self::min_u32(1000, bounded) * SCORE_SCALE;
        data.score
    }

    fn network_trust_bonus(env: &Env, did: &Address) -> u32 {
        let population = Self::population(env);
        let mut weighted_sum = 0u32;
        for account in population.iter() {
            let edges: Vec<TrustAttestation> = env
                .storage()
                .persistent()
                .get(&DataKey::Trust(account.clone()))
                .unwrap_or_else(|| Vec::new(env));
            for edge in edges.iter() {
                if edge.subject == *did {
                    let source_score = Self::load_profile(env, &edge.truster)
                        .map(|profile| profile.score / SCORE_SCALE)
                        .unwrap_or(BASE_SCORE / SCORE_SCALE);
                    weighted_sum += (edge.weight / 20) + (source_score / 25);
                }
            }
        }
        Self::min_u32(180, weighted_sum)
    }

    fn credential_kind(env: &Env, credential_type: &Bytes) -> u32 {
        if *credential_type == Bytes::from_slice(env, b"kyc")
            || *credential_type == Bytes::from_slice(env, b"KYC")
            || *credential_type == Bytes::from_slice(env, b"KYCVerification")
        {
            1
        } else if *credential_type == Bytes::from_slice(env, b"employment")
            || *credential_type == Bytes::from_slice(env, b"Employment")
            || *credential_type == Bytes::from_slice(env, b"IncomeVerification")
        {
            2
        } else if *credential_type == Bytes::from_slice(env, b"academic")
            || *credential_type == Bytes::from_slice(env, b"EducationCredential")
        {
            3
        } else {
            4
        }
    }

    fn credential_classes(data: &ReputationData) -> u32 {
        let mut count = 0;
        if data.verified_kyc > 0 {
            count += 1;
        }
        if data.employment_credentials > 0 {
            count += 1;
        }
        if data.academic_credentials > 0 {
            count += 1;
        }
        if data.self_claimed_credentials > 0 {
            count += 1;
        }
        count
    }

    fn load_profile(env: &Env, did: &Address) -> Result<ReputationData, ReputationScoreError> {
        if let Some(data) = env.storage().temporary().get(&DataKey::Working(did.clone())) {
            return Ok(data);
        }
        env.storage()
            .persistent()
            .get(&DataKey::Profile(did.clone()))
            .ok_or(ReputationScoreError::NotFound)
    }

    fn stage_profile(env: &Env, did: &Address, data: &ReputationData) {
        env.storage().temporary().set(&DataKey::Working(did.clone()), data);
    }

    fn store_profile(env: &Env, did: &Address, data: &ReputationData) {
        env.storage().persistent().set(&DataKey::Profile(did.clone()), data);
        env.storage().temporary().set(&DataKey::Working(did.clone()), data);
    }

    fn maybe_checkpoint(env: &Env, did: &Address, data: &ReputationData) {
        let persisted: ReputationData = env
            .storage()
            .persistent()
            .get(&DataKey::Profile(did.clone()))
            .unwrap_or_else(|| data.clone());
        if data.last_updated.saturating_sub(persisted.last_updated) >= CHECKPOINT_INTERVAL {
            env.storage().persistent().set(&DataKey::Profile(did.clone()), data);
        }
    }

    fn append_history(env: &Env, did: &Address, entry: ReputationHistoryEntry) {
        let key = DataKey::History(did.clone());
        let mut history: Vec<ReputationHistoryEntry> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        history.push_back(entry);
        while history.len() > MAX_HISTORY_POINTS {
            history.remove(0);
        }
        env.storage().persistent().set(&key, &history);
    }

    fn track_population(env: &Env, did: &Address) {
        let key = DataKey::Population;
        let mut population: Vec<Address> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        if !Self::contains_address(&population, did) {
            population.push_back(did.clone());
            env.storage().persistent().set(&key, &population);
        }
    }

    fn population(env: &Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::Population)
            .unwrap_or_else(|| Vec::new(env))
    }

    fn contains_address(values: &Vec<Address>, target: &Address) -> bool {
        for value in values.iter() {
            if value == *target {
                return true;
            }
        }
        false
    }

    fn map_u32(metadata: &Map<Symbol, i128>, env: &Env, key: Symbol) -> u32 {
        metadata
            .get(key)
            .unwrap_or(0)
            .max(0)
            .min(i128::from(u32::MAX)) as u32
    }

    fn map_u64(metadata: &Map<Symbol, i128>, env: &Env, key: Symbol) -> u64 {
        metadata
            .get(key)
            .unwrap_or(0)
            .max(0)
            .min(i128::from(u64::MAX)) as u64
    }

    fn bounded_add(current: u32, delta: u32, max: u32) -> u32 {
        Self::min_u32(max, current.saturating_add(delta))
    }

    fn max_u32(a: u32, b: u32) -> u32 {
        if a > b { a } else { b }
    }

    fn min_u32(a: u32, b: u32) -> u32 {
        if a < b { a } else { b }
    }
}
