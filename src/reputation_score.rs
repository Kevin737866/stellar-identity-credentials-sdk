use soroban_sdk::{
    contract, contracterror, contractimpl, Address, Env, Symbol, Vec, Map, U256,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReputationScoreError {
    NotFound = 1,
    InvalidScore = 2,
    Unauthorized = 3,
    InsufficientData = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationData {
    pub address: Address,
    pub score: u32,
    pub transaction_count: u32,
    pub successful_transactions: u32,
    pub credential_count: u32,
    pub valid_credentials: u32,
    pub last_updated: u64,
    pub reputation_factors: Map<Symbol, u32>,
}

#[contract]
pub struct ReputationScore;

#[contractimpl]
impl ReputationScore {
    /// Initialize reputation tracking for an address
    pub fn initialize_reputation(env: Env, address: Address) -> Result<(), ReputationScoreError> {
        // Check if reputation already exists
        if env.storage().persistent().has(&address) {
            return Err(ReputationScoreError::NotFound); // Already exists
        }

        let reputation_data = ReputationData {
            address: address.clone(),
            score: 50, // Start with neutral score
            transaction_count: 0,
            successful_transactions: 0,
            credential_count: 0,
            valid_credentials: 0,
            last_updated: env.ledger().timestamp(),
            reputation_factors: Map::new(&env),
        };

        env.storage().persistent().set(&address, &reputation_data);
        Ok(())
    }

    /// Update reputation based on transaction
    pub fn update_transaction_reputation(
        env: Env,
        address: Address,
        successful: bool,
        amount: u64,
    ) -> Result<u32, ReputationScoreError> {
        let mut reputation_data: ReputationData = env
            .storage()
            .persistent()
            .get(&address)
            .ok_or(ReputationScoreError::NotFound)?;

        // Update transaction counts
        reputation_data.transaction_count += 1;
        if successful {
            reputation_data.successful_transactions += 1;
        }

        // Calculate score impact based on transaction success and amount
        let score_impact = Self::calculate_transaction_score_impact(
            &env,
            successful,
            amount,
            reputation_data.transaction_count,
        );

        // Update score
        reputation_data.score = Self::apply_score_change(reputation_data.score, score_impact);
        reputation_data.last_updated = env.ledger().timestamp();

        // Store updated reputation
        env.storage().persistent().set(&address, &reputation_data);

        Ok(reputation_data.score)
    }

    /// Update reputation based on credential verification
    pub fn update_credential_reputation(
        env: Env,
        address: Address,
        credential_valid: bool,
        credential_type: Symbol,
    ) -> Result<u32, ReputationScoreError> {
        let mut reputation_data: ReputationData = env
            .storage()
            .persistent()
            .get(&address)
            .ok_or(ReputationScoreError::NotFound)?;

        // Update credential counts
        reputation_data.credential_count += 1;
        if credential_valid {
            reputation_data.valid_credentials += 1;
        }

        // Calculate score impact based on credential validity
        let score_impact = Self::calculate_credential_score_impact(
            &env,
            credential_valid,
            credential_type,
            reputation_data.credential_count,
        );

        // Update score
        reputation_data.score = Self::apply_score_change(reputation_data.score, score_impact);
        reputation_data.last_updated = env.ledger().timestamp();

        // Update reputation factors
        let current_factor = reputation_data.reputation_factors.get(credential_type).unwrap_or(0);
        reputation_data.reputation_factors.set(credential_type, current_factor + 1);

        // Store updated reputation
        env.storage().persistent().set(&address, &reputation_data);

        Ok(reputation_data.score)
    }

    /// Get reputation score for an address
    pub fn get_reputation_score(env: Env, address: Address) -> Result<u32, ReputationScoreError> {
        let reputation_data: ReputationData = env
            .storage()
            .persistent()
            .get(&address)
            .ok_or(ReputationScoreError::NotFound)?;
        Ok(reputation_data.score)
    }

    /// Get full reputation data for an address
    pub fn get_reputation_data(env: Env, address: Address) -> Result<ReputationData, ReputationScoreError> {
        env.storage()
            .persistent()
            .get(&address)
            .ok_or(ReputationScoreError::NotFound)
    }

    /// Batch get reputation scores for multiple addresses
    pub fn batch_get_reputation_scores(
        env: Env,
        addresses: Vec<Address>,
    ) -> Vec<u32> {
        let mut scores = Vec::new(&env);
        for address in addresses.iter() {
            let score = Self::get_reputation_score(env.clone(), address.clone()).unwrap_or(0);
            scores.push_back(score);
        }
        scores
    }

    /// Get reputation history (simplified - stores last N updates)
    pub fn get_reputation_history(env: Env, address: Address, limit: u32) -> Vec<u64> {
        let history_key = Symbol::new(&env, &format!("history:{}", address.to_string()));
        let history: Vec<u64> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or_else(|| Vec::new(&env));

        // Return last 'limit' entries
        let start = if history.len() > limit {
            history.len() - limit
        } else {
            0
        };

        let mut result = Vec::new(&env);
        for i in start..history.len() {
            result.push_back(history.get(i).unwrap());
        }
        result
    }

    /// Calculate reputation percentile rank
    pub fn get_reputation_percentile(env: Env, address: Address) -> Result<u32, ReputationScoreError> {
        let target_score = Self::get_reputation_score(env.clone(), address.clone())?;
        
        // This would require maintaining a global score distribution
        // For now, return a simple calculation
        Ok((target_score * 100) / 100) // Simple percentile
    }

    /// Check if address meets minimum reputation threshold
    pub fn meets_reputation_threshold(
        env: Env,
        address: Address,
        threshold: u32,
    ) -> Result<bool, ReputationScoreError> {
        let score = Self::get_reputation_score(env, address)?;
        Ok(score >= threshold)
    }

    /// Calculate transaction score impact
    fn calculate_transaction_score_impact(
        env: &Env,
        successful: bool,
        amount: u64,
        transaction_count: u32,
    ) -> i32 {
        let base_impact = if successful { 2 } else { -5 };
        
        // Adjust impact based on transaction amount (larger amounts have more impact)
        let amount_factor = if amount > 1000000 { 2 } else { 1 };
        
        // Adjust impact based on transaction history (new accounts get more impact)
        let history_factor = if transaction_count < 10 { 2 } else { 1 };
        
        base_impact * amount_factor * history_factor
    }

    /// Calculate credential score impact
    fn calculate_credential_score_impact(
        env: &Env,
        valid: bool,
        credential_type: Symbol,
        credential_count: u32,
    ) -> i32 {
        let base_impact = if valid { 3 } else { -3 };
        
        // Different credential types have different weights
        let type_weight = match credential_type.to_string().as_str() {
            "KYC" => 3,
            "Identity" => 2,
            "Education" => 2,
            "Professional" => 2,
            _ => 1,
        };
        
        base_impact * type_weight
    }

    /// Apply score change with bounds checking
    fn apply_score_change(current_score: u32, change: i32) -> u32 {
        let new_score = current_score as i32 + change;
        
        // Bound the score between 0 and 100
        if new_score < 0 {
            0
        } else if new_score > 100 {
            100
        } else {
            new_score as u32
        }
    }

    /// Get reputation factors for an address
    pub fn get_reputation_factors(env: Env, address: Address) -> Result<Map<Symbol, u32>, ReputationScoreError> {
        let reputation_data: ReputationData = env
            .storage()
            .persistent()
            .get(&address)
            .ok_or(ReputationScoreError::NotFound)?;
        Ok(reputation_data.reputation_factors)
    }

    /// Reset reputation (admin function)
    pub fn reset_reputation(env: Env, address: Address) -> Result<(), ReputationScoreError> {
        let mut reputation_data: ReputationData = env
            .storage()
            .persistent()
            .get(&address)
            .ok_or(ReputationScoreError::NotFound)?;

        reputation_data.score = 50;
        reputation_data.transaction_count = 0;
        reputation_data.successful_transactions = 0;
        reputation_data.credential_count = 0;
        reputation_data.valid_credentials = 0;
        reputation_data.last_updated = env.ledger().timestamp();
        reputation_data.reputation_factors = Map::new(&env);

        env.storage().persistent().set(&address, &reputation_data);
        Ok(())
    }

    /// Get top reputation addresses (simplified implementation)
    pub fn get_top_reputation_addresses(env: Env, limit: u32) -> Vec<Address> {
        // This would require maintaining a sorted list of addresses by score
        // For now, return empty vector
        Vec::new(&env)
    }
}
