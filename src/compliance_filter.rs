use soroban_sdk::{
    contract, contracterror, contractimpl, Address, Bytes, Env, Symbol, Vec, Map,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ComplianceFilterError {
    AddressBlocked = 1,
    HighRisk = 2,
    Unauthorized = 3,
    NotFound = 4,
    InvalidRiskScore = 5,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplianceRecord {
    pub address: Address,
    pub risk_score: u32, // 0-100, where 100 is highest risk
    pub sanctions_list: Vec<Bytes>,
    pub last_checked: u64,
    pub check_count: u32,
    pub status: Symbol, // "cleared", "flagged", "blocked"
    pub metadata: Map<Symbol, Bytes>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanctionsList {
    pub list_id: Symbol,
    pub name: Bytes,
    pub source: Bytes,
    pub last_updated: u64,
    pub active: bool,
    pub entries: Vec<Address>,
}

#[contract]
pub struct ComplianceFilter;

#[contractimpl]
impl ComplianceFilter {
    /// Initialize compliance checking for an address
    pub fn initialize_compliance(env: Env, address: Address) -> Result<(), ComplianceFilterError> {
        // Check if compliance record already exists
        if env.storage().persistent().has(&address) {
            return Err(ComplianceFilterError::NotFound); // Already exists
        }

        let compliance_record = ComplianceRecord {
            address: address.clone(),
            risk_score: 0, // Start with neutral risk
            sanctions_list: Vec::new(&env),
            last_checked: env.ledger().timestamp(),
            check_count: 0,
            status: Symbol::new(&env, "cleared"),
            metadata: Map::new(&env),
        };

        env.storage().persistent().set(&address, &compliance_record);
        Ok(())
    }

    /// Check address compliance against sanctions lists
    pub fn check_compliance(env: Env, address: Address) -> Result<ComplianceRecord, ComplianceFilterError> {
        let mut compliance_record: ComplianceRecord = env
            .storage()
            .persistent()
            .get(&address)
            .unwrap_or_else(|| ComplianceRecord {
                address: address.clone(),
                risk_score: 0,
                sanctions_list: Vec::new(&env),
                last_checked: 0,
                check_count: 0,
                status: Symbol::new(&env, "cleared"),
                metadata: Map::new(&env),
            });

        // Check against all active sanctions lists
        let mut found_lists = Vec::new(&env);
        let mut is_blocked = false;
        let mut risk_score = compliance_record.risk_score;

        // Get all active sanctions lists
        let active_lists = Self::get_active_sanctions_lists(env.clone());
        
        for list_id in active_lists.iter() {
            if let Some(list) = Self::get_sanctions_list(env.clone(), list_id.clone()) {
                if list.active {
                    // Check if address is in this sanctions list
                    if Self::is_address_in_list(&list, &address) {
                        found_lists.push_back(list_id.clone());
                        is_blocked = true;
                        risk_score = 100; // Maximum risk for sanctioned addresses
                    }
                }
            }
        }

        // Update compliance record
        compliance_record.sanctions_list = found_lists;
        compliance_record.risk_score = risk_score;
        compliance_record.last_checked = env.ledger().timestamp();
        compliance_record.check_count += 1;

        // Set status based on findings
        compliance_record.status = if is_blocked {
            Symbol::new(&env, "blocked")
        } else if risk_score > 70 {
            Symbol::new(&env, "flagged")
        } else {
            Symbol::new(&env, "cleared")
        };

        // Store updated record
        env.storage().persistent().set(&address, &compliance_record);

        if is_blocked {
            return Err(ComplianceFilterError::AddressBlocked);
        } else if risk_score > 70 {
            return Err(ComplianceFilterError::HighRisk);
        }

        Ok(compliance_record)
    }

    /// Create or update a sanctions list
    pub fn update_sanctions_list(
        env: Env,
        list_id: Symbol,
        name: Bytes,
        source: Bytes,
        entries: Vec<Address>,
    ) -> Result<(), ComplianceFilterError> {
        let list = SanctionsList {
            list_id: list_id.clone(),
            name: name.clone(),
            source: source.clone(),
            last_updated: env.ledger().timestamp(),
            active: true,
            entries: entries.to_vec(&env),
        };

        env.storage().persistent().set(&list_id, &list);
        Ok(())
    }

    /// Get compliance record for an address
    pub fn get_compliance_record(env: Env, address: Address) -> Result<ComplianceRecord, ComplianceFilterError> {
        env.storage()
            .persistent()
            .get(&address)
            .ok_or(ComplianceFilterError::NotFound)
    }

    /// Get sanctions list by ID
    pub fn get_sanctions_list(env: Env, list_id: Symbol) -> Option<SanctionsList> {
        env.storage().persistent().get(&list_id)
    }

    /// Deactivate a sanctions list
    pub fn deactivate_sanctions_list(env: Env, list_id: Symbol) -> Result<(), ComplianceFilterError> {
        let mut list: SanctionsList = env
            .storage()
            .persistent()
            .get(&list_id)
            .ok_or(ComplianceFilterError::NotFound)?;

        list.active = false;
        list.last_updated = env.ledger().timestamp();

        env.storage().persistent().set(&list_id, &list);
        Ok(())
    }

    /// Update risk score for an address
    pub fn update_risk_score(
        env: Env,
        address: Address,
        new_score: u32,
        reason: Option<Bytes>,
    ) -> Result<(), ComplianceFilterError> {
        if new_score > 100 {
            return Err(ComplianceFilterError::InvalidRiskScore);
        }

        let mut compliance_record: ComplianceRecord = env
            .storage()
            .persistent()
            .get(&address)
            .ok_or(ComplianceFilterError::NotFound)?;

        compliance_record.risk_score = new_score;
        compliance_record.last_checked = env.ledger().timestamp();

        // Update status based on new risk score
        compliance_record.status = if new_score > 70 {
            Symbol::new(&env, "flagged")
        } else {
            Symbol::new(&env, "cleared")
        };

        // Store reason if provided
        if let Some(reason_bytes) = reason {
            compliance_record.metadata.set(
                Symbol::new(&env, "last_risk_update_reason"),
                reason_bytes,
            );
        }

        env.storage().persistent().set(&address, &compliance_record);
        Ok(())
    }

    /// Batch check compliance for multiple addresses
    pub fn batch_check_compliance(env: Env, addresses: Vec<Address>) -> Vec<Result<ComplianceRecord, ComplianceFilterError>> {
        let mut results = Vec::new(&env);
        for address in addresses.iter() {
            let result = Self::check_compliance(env.clone(), address.clone());
            results.push_back(result);
        }
        results
    }

    /// Get all active sanctions lists
    fn get_active_sanctions_lists(env: Env) -> Vec<Symbol> {
        // This would require maintaining an index of sanctions lists
        // For now, return some common list identifiers
        let mut lists = Vec::new(&env);
        lists.push_back(Symbol::new(&env, "OFAC"));
        lists.push_back(Symbol::new(&env, "UN"));
        lists.push_back(Symbol::new(&env, "EU"));
        lists
    }

    /// Check if address is in a sanctions list
    fn is_address_in_list(list: &SanctionsList, address: &Address) -> bool {
        for entry in list.entries.iter() {
            if entry == address {
                return true;
            }
        }
        false
    }

    /// Get risk score for an address
    pub fn get_risk_score(env: Env, address: Address) -> Result<u32, ComplianceFilterError> {
        let record: ComplianceRecord = env
            .storage()
            .persistent()
            .get(&address)
            .ok_or(ComplianceFilterError::NotFound)?;
        Ok(record.risk_score)
    }

    /// Check if address is blocked
    pub fn is_address_blocked(env: Env, address: Address) -> bool {
        if let Ok(record) = Self::get_compliance_record(env, address) {
            record.status == Symbol::new(&env, "blocked")
        } else {
            false
        }
    }

    /// Get compliance statistics
    pub fn get_compliance_stats(env: Env) -> Map<Symbol, u32> {
        let mut stats = Map::new(&env);
        
        // This would require maintaining global statistics
        // For now, return empty stats
        stats.set(Symbol::new(&env, "total_checks"), 0u32);
        stats.set(Symbol::new(&env, "blocked_addresses"), 0u32);
        stats.set(Symbol::new(&env, "flagged_addresses"), 0u32);
        stats.set(Symbol::new(&env, "cleared_addresses"), 0u32);
        
        stats
    }

    /// Add address to sanctions list
    pub fn add_to_sanctions_list(
        env: Env,
        list_id: Symbol,
        address: Address,
    ) -> Result<(), ComplianceFilterError> {
        let mut list: SanctionsList = env
            .storage()
            .persistent()
            .get(&list_id)
            .ok_or(ComplianceFilterError::NotFound)?;

        // Check if address already exists in list
        for entry in list.entries.iter() {
            if entry == address {
                return Ok(()); // Already in list
            }
        }

        // Add address to list
        list.entries.push_back(address);
        list.last_updated = env.ledger().timestamp();

        env.storage().persistent().set(&list_id, &list);

        // Update compliance record for the address
        Self::check_compliance(env, address)?;

        Ok(())
    }

    /// Remove address from sanctions list
    pub fn remove_from_sanctions_list(
        env: Env,
        list_id: Symbol,
        address: Address,
    ) -> Result<(), ComplianceFilterError> {
        let mut list: SanctionsList = env
            .storage()
            .persistent()
            .get(&list_id)
            .ok_or(ComplianceFilterError::NotFound)?;

        // Find and remove address from list
        let mut found = false;
        let mut new_entries = Vec::new(&env);
        for entry in list.entries.iter() {
            if entry != address {
                new_entries.push_back(entry);
            } else {
                found = true;
            }
        }

        if !found {
            return Ok(()); // Address not in list
        }

        list.entries = new_entries;
        list.last_updated = env.ledger().timestamp();

        env.storage().persistent().set(&list_id, &list);

        // Re-check compliance for the address
        Self::check_compliance(env, address)?;

        Ok(())
    }

    /// Get compliance history for an address
    pub fn get_compliance_history(env: Env, address: Address, limit: u32) -> Vec<u64> {
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
}
