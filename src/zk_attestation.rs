use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Map,
    Symbol, Vec,
};

use crate::{clamp_page_size, PaginatedCircuits};
use crate::admin;

// ---------------------------------------------------------------------------
// Namespaced storage keys (#58)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum ZkKey {
    Circuit(Symbol),
    Proof(Bytes),
    Nullifier(Bytes),
    CircuitProofs(Symbol),
    Attestation(Bytes),
    ActiveCircuits,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ZKAttestationError {
    InvalidProof = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidCircuit = 4,
    VerificationFailed = 5,
    Expired = 6,
    NullifierAlreadyUsed = 7,
    InvalidPublicInputs = 8,
    CircuitDeactivated = 9,
    RevokedCredential = 10,
    PredicateMismatch = 11,
    AttributeNotFound = 12,
    DisclosureConflict = 13,
    CombiningFailed = 14,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ZKProof {
    pub proof_id: Bytes,
    pub circuit_id: Symbol,
    pub public_inputs: Vec<Bytes>,
    pub proof_bytes: Bytes,
    pub verifying_key_hash: Bytes,
    pub nullifier: Bytes,
    pub verifier_address: Address,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub metadata: Map<Symbol, Bytes>,
    pub revealed_attributes: Vec<Symbol>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ZKCircuit {
    pub circuit_id: Symbol,
    pub name: Bytes,
    pub description: Bytes,
    pub verifier_key: Bytes,
    pub verifying_key_hash: Bytes,
    pub public_input_count: u32,
    pub private_input_count: u32,
    pub created_by: Address,
    pub created_at: u64,
    pub active: bool,
    pub circuit_type: CircuitType,
    pub supported_attributes: Vec<Symbol>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum CircuitType {
    RangeProof,
    SetMembership,
    CredentialOwnership,
    CompositeProof,
    EqualityProof,
    SelectiveDisclosure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ZKAttestationRecord {
    pub credential_id: Bytes,
    pub proof_hash: Bytes,
    pub nullifier: Bytes,
    pub revealed_attributes: Vec<Symbol>,
    pub circuit_id: Symbol,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct NullifierRecord {
    pub nullifier: Bytes,
    pub used_at: u64,
    pub context: Bytes,
    pub proof_id: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum PredicateType {
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Equality,
    Range,
    InSet,
    NotInSet,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct SelectiveDisclosureProof {
    pub proof_id: Bytes,
    pub credential_id: Bytes,
    pub circuit_id: Symbol,
    pub public_inputs: Vec<Bytes>,
    pub proof_bytes: Bytes,
    pub nullifier: Bytes,
    pub verifier_address: Address,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revealed_attributes: Vec<Symbol>,
    pub hidden_attributes: Vec<Symbol>,
    pub predicates: Vec<PredicateInfo>,
    pub metadata: Map<Symbol, Bytes>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct PredicateInfo {
    pub attribute_name: Symbol,
    pub predicate_type: PredicateType,
    pub threshold: Option<Bytes>,
    pub range_min: Option<Bytes>,
    pub range_max: Option<Bytes>,
    pub allowed_values: Option<Vec<Bytes>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CombinedDisclosureProof {
    pub proof_id: Bytes,
    pub child_proof_ids: Vec<Bytes>,
    pub combined_predicates: Vec<PredicateInfo>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub metadata: Map<Symbol, Bytes>,
}

#[contract]
pub struct ZKAttestation;

#[contractimpl]
impl ZKAttestationContract {
    pub fn register_circuit(
        env: Env,
        admin_address: Address,
        circuit_id: Symbol,
        name: Bytes,
        description: Bytes,
        verifier_key: Bytes,
        public_input_count: u32,
        private_input_count: u32,
        circuit_type: CircuitType,
        supported_attributes: Vec<Symbol>,
    ) -> Result<(), ZKAttestationError> {
        admin_address.require_auth();
        admin::only_admin(&env, &admin_address)
            .map_err(|_| ZKAttestationError::Unauthorized)?;

        if env
            .storage()
            .persistent()
            .has(&ZkKey::Circuit(circuit_id.clone()))
        {
            return Err(ZKAttestationError::InvalidCircuit);
        }

        let verifying_key_hash = Self::hash_verifying_key(&env, &verifier_key);

        let circuit = ZKCircuit {
            circuit_id: circuit_id.clone(),
            name,
            description,
            verifier_key,
            verifying_key_hash,
            public_input_count,
            private_input_count,
            created_by: admin_address,
            created_at: env.ledger().timestamp(),
            active: true,
            circuit_type,
            supported_attributes,
        };

        env.storage()
            .persistent()
            .set(&ZkKey::Circuit(circuit_id.clone()), &circuit);

        let mut active: Vec<Symbol> = env
            .storage()
            .persistent()
            .get(&ZkKey::ActiveCircuits)
            .unwrap_or_else(|| Vec::new(&env));
        active.push_back(circuit_id);
        env.storage()
            .persistent()
            .set(&ZkKey::ActiveCircuits, &active);

        env.events().publish(
            (Symbol::new(&env, "CircuitRegistered"),),
            (circuit_id, circuit.name, circuit_type),
        );

        Ok(())
    }

    pub fn submit_proof(
        env: Env,
        circuit_id: Symbol,
        public_inputs: Vec<Bytes>,
        proof_bytes: Bytes,
        nullifier: Bytes,
        revealed_attributes: Vec<Symbol>,
        expires_at: Option<u64>,
        metadata: Map<Symbol, Bytes>,
    ) -> Result<Bytes, ZKAttestationError> {
        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id.clone()))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        if !circuit.active {
            return Err(ZKAttestationError::CircuitDeactivated);
        }

        if public_inputs.len() != circuit.public_input_count {
            return Err(ZKAttestationError::InvalidPublicInputs);
        }

        if env
            .storage()
            .persistent()
            .has(&ZkKey::Nullifier(nullifier.clone()))
        {
            return Err(ZKAttestationError::NullifierAlreadyUsed);
        }

        let proof_id = Self::generate_proof_id(&env, &circuit_id);

        let is_valid =
            Self::verify_zk_proof(&env, &circuit.verifier_key, &public_inputs, &proof_bytes)?;

        if !is_valid {
            return Err(ZKAttestationError::VerificationFailed);
        }

        let nullifier_record = NullifierRecord {
            nullifier: nullifier.clone(),
            used_at: env.ledger().timestamp(),
            context: metadata
                .get(Symbol::new(&env, "context"))
                .unwrap_or_else(|| Bytes::from_slice(&env, b"default")),
            proof_id: proof_id.clone(),
        };
        env.storage()
            .persistent()
            .set(&ZkKey::Nullifier(nullifier.clone()), &nullifier_record);

        let proof = ZKProof {
            proof_id: proof_id.clone(),
            circuit_id: circuit_id.clone(),
            public_inputs: public_inputs.clone(),
            proof_bytes: proof_bytes.clone(),
            verifying_key_hash: circuit.verifying_key_hash.clone(),
            nullifier: nullifier.clone(),
            verifier_address: env.current_contract_address(),
            created_at: env.ledger().timestamp(),
            expires_at,
            metadata,
            revealed_attributes: revealed_attributes.clone(),
        };

        env.storage()
            .persistent()
            .set(&ZkKey::Proof(proof_id.clone()), &proof);

        let mut circuit_proofs: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&ZkKey::CircuitProofs(circuit_id.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        circuit_proofs.push_back(proof_id.clone());
        env.storage()
            .persistent()
            .set(&ZkKey::CircuitProofs(circuit_id.clone()), &circuit_proofs);

        let attestation = ZKAttestationRecord {
            credential_id: Bytes::from_slice(&env, b"unknown"),
            proof_hash: Self::hash_proof(&env, &proof_bytes),
            nullifier,
            revealed_attributes,
            circuit_id,
            created_at: env.ledger().timestamp(),
            expires_at,
        };

        env.storage()
            .persistent()
            .set(&ZkKey::Attestation(proof_id.clone()), &attestation);

        env.events().publish(
            (Symbol::new(&env, "ProofCreated"),),
            (proof_id.clone(), circuit_id, nullifier),
        );

        Ok(proof_id)
    }

    pub fn verify_proof(env: Env, proof_id: Bytes) -> Result<bool, ZKAttestationError> {
        let proof: ZKProof = env
            .storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id))
            .ok_or(ZKAttestationError::NotFound)?;

        if let Some(expires_at) = proof.expires_at {
            if env.ledger().timestamp() > expires_at {
                return Ok(false);
            }
        }

        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(proof.circuit_id))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        let result = Self::verify_zk_proof(
            &env,
            &circuit.verifier_key,
            &proof.public_inputs,
            &proof.proof_bytes,
        );

        env.events().publish(
            (Symbol::new(&env, "ProofVerified"),),
            (proof_id, proof.circuit_id, result.unwrap_or(false)),
        );

        result
    }

    pub fn get_proof(env: Env, proof_id: Bytes) -> Result<ZKProof, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id))
            .ok_or(ZKAttestationError::NotFound)
    }

    pub fn get_circuit(env: Env, circuit_id: Symbol) -> Result<ZKCircuit, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id))
            .ok_or(ZKAttestationError::InvalidCircuit)
    }

    pub fn get_circuit_proofs(env: Env, circuit_id: Symbol) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&ZkKey::CircuitProofs(circuit_id))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Paginated list of registered circuits (#56).
    pub fn get_registered_circuits(env: Env, page: u32, page_size: u32) -> PaginatedCircuits {
        let all: Vec<Symbol> = env
            .storage()
            .persistent()
            .get(&ZkKey::ActiveCircuits)
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = all.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(item) = all.get(i) {
                    data.push_back(item);
                }
            }
        }

        PaginatedCircuits {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }

    pub fn get_active_circuits(env: Env) -> Vec<Symbol> {
        env.storage()
            .persistent()
            .get(&ZkKey::ActiveCircuits)
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn deactivate_circuit(env: Env, circuit_id: Symbol) -> Result<(), ZKAttestationError> {
        let mut circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id.clone()))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        let creator = env.current_contract_address();
        if circuit.created_by != creator {
            return Err(ZKAttestationError::Unauthorized);
        }

        circuit.active = false;
        env.storage()
            .persistent()
            .set(&ZkKey::Circuit(circuit_id), &circuit);

        Ok(())
    }

    pub fn reactivate_circuit(env: Env, circuit_id: Symbol) -> Result<(), ZKAttestationError> {
        let mut circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id.clone()))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        let creator = env.current_contract_address();
        if circuit.created_by != creator {
            return Err(ZKAttestationError::Unauthorized);
        }

        circuit.active = true;
        env.storage()
            .persistent()
            .set(&ZkKey::Circuit(circuit_id), &circuit);

        Ok(())
    }

    pub fn batch_verify_proofs(env: Env, proof_ids: Vec<Bytes>) -> Vec<bool> {
        let mut results = Vec::new(&env);
        for proof_id in proof_ids.iter() {
            let is_valid = Self::verify_proof(env.clone(), proof_id.clone()).unwrap_or(false);
            results.push_back(is_valid);
        }
        results
    }

    // -----------------------------------------------------------------------
    // Selective Disclosure methods (#111)
    // -----------------------------------------------------------------------

    pub fn create_selective_disclosure_proof(
        env: Env,
        credential_id: Bytes,
        circuit_id: Symbol,
        public_inputs: Vec<Bytes>,
        proof_bytes: Bytes,
        nullifier: Bytes,
        revealed_attributes: Vec<Symbol>,
        hidden_attributes: Vec<Symbol>,
        predicates: Vec<PredicateInfo>,
        expires_at: Option<u64>,
        metadata: Map<Symbol, Bytes>,
    ) -> Result<Bytes, ZKAttestationError> {
        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id.clone()))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        if !circuit.active {
            return Err(ZKAttestationError::CircuitDeactivated);
        }

        if env
            .storage()
            .persistent()
            .has(&ZkKey::Nullifier(nullifier.clone()))
        {
            return Err(ZKAttestationError::NullifierAlreadyUsed);
        }

        // Validate predicates match supported circuit attributes
        for pred in predicates.iter() {
            let attr = pred.attribute_name;
            if !circuit.supported_attributes.contains(attr.clone()) {
                return Err(ZKAttestationError::AttributeNotFound);
            }
            // Validate no conflict: an attribute cannot be both revealed and hidden
            if revealed_attributes.contains(attr.clone())
                && hidden_attributes.contains(attr.clone())
            {
                return Err(ZKAttestationError::DisclosureConflict);
            }
        }

        let is_valid =
            Self::verify_zk_proof(&env, &circuit.verifier_key, &public_inputs, &proof_bytes)?;

        if !is_valid {
            return Err(ZKAttestationError::VerificationFailed);
        }

        let proof_id = Self::generate_proof_id(&env, &circuit_id);

        let nullifier_record = NullifierRecord {
            nullifier: nullifier.clone(),
            used_at: env.ledger().timestamp(),
            context: metadata
                .get(Symbol::new(&env, "context"))
                .unwrap_or_else(|| Bytes::from_slice(&env, b"selective_disclosure")),
            proof_id: proof_id.clone(),
        };
        env.storage()
            .persistent()
            .set(&ZkKey::Nullifier(nullifier.clone()), &nullifier_record);

        let disclosure = SelectiveDisclosureProof {
            proof_id: proof_id.clone(),
            credential_id,
            circuit_id: circuit_id.clone(),
            public_inputs: public_inputs.clone(),
            proof_bytes: proof_bytes.clone(),
            nullifier: nullifier.clone(),
            verifier_address: env.current_contract_address(),
            created_at: env.ledger().timestamp(),
            expires_at,
            revealed_attributes: revealed_attributes.clone(),
            hidden_attributes: hidden_attributes.clone(),
            predicates: predicates.clone(),
            metadata: metadata.clone(),
        };

        env.storage()
            .persistent()
            .set(&ZkKey::Proof(proof_id.clone()), &disclosure);

        let mut circuit_proofs: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&ZkKey::CircuitProofs(circuit_id.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        circuit_proofs.push_back(proof_id.clone());
        env.storage()
            .persistent()
            .set(&ZkKey::CircuitProofs(circuit_id.clone()), &circuit_proofs);

        env.events().publish(
            (Symbol::new(&env, "SelectiveDisclosureCreated"),),
            (proof_id.clone(), circuit_id, nullifier),
        );

        Ok(proof_id)
    }

    pub fn verify_selective_disclosure(
        env: Env,
        proof_id: Bytes,
        expected_predicates: Vec<PredicateInfo>,
    ) -> Result<bool, ZKAttestationError> {
        let disclosure: SelectiveDisclosureProof = env
            .storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id.clone()))
            .ok_or(ZKAttestationError::NotFound)?;

        if let Some(expires_at) = disclosure.expires_at {
            if env.ledger().timestamp() > expires_at {
                return Ok(false);
            }
        }

        // Verify each expected predicate matches the disclosure
        for expected in expected_predicates.iter() {
            let found = disclosure.predicates.iter().any(|actual| {
                actual.attribute_name == expected.attribute_name
                    && actual.predicate_type == expected.predicate_type
                    && actual.threshold == expected.threshold
                    && actual.range_min == expected.range_min
                    && actual.range_max == expected.range_max
            });
            if !found {
                return Err(ZKAttestationError::PredicateMismatch);
            }
        }

        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(disclosure.circuit_id))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        let result = Self::verify_zk_proof(
            &env,
            &circuit.verifier_key,
            &disclosure.public_inputs,
            &disclosure.proof_bytes,
        );

        env.events().publish(
            (Symbol::new(&env, "SelectiveDisclosureVerified"),),
            (proof_id, disclosure.circuit_id, result.unwrap_or(false)),
        );

        result
    }

    pub fn combine_selective_disclosures(
        env: Env,
        proof_ids: Vec<Bytes>,
        metadata: Map<Symbol, Bytes>,
    ) -> Result<Bytes, ZKAttestationError> {
        if proof_ids.is_empty() {
            return Err(ZKAttestationError::CombiningFailed);
        }

        let mut combined_predicates: Vec<PredicateInfo> = Vec::new(&env);
        let mut seen_attributes: Map<Symbol, bool> = Map::new(&env);

        for proof_id in proof_ids.iter() {
            let disclosure: SelectiveDisclosureProof = env
                .storage()
                .persistent()
                .get(&ZkKey::Proof(proof_id.clone()))
                .ok_or(ZKAttestationError::NotFound)?;

            if let Some(expires_at) = disclosure.expires_at {
                if env.ledger().timestamp() > expires_at {
                    return Err(ZKAttestationError::Expired);
                }
            }

            for pred in disclosure.predicates.iter() {
                if seen_attributes.contains(pred.attribute_name.clone()) {
                    return Err(ZKAttestationError::DisclosureConflict);
                }
                seen_attributes.set(pred.attribute_name.clone(), true);
                combined_predicates.push_back(pred);
            }
        }

        let combined_id = Bytes::from_slice(&env, b"combined:");
        let combined = CombinedDisclosureProof {
            proof_id: combined_id.clone(),
            child_proof_ids: proof_ids,
            combined_predicates,
            created_at: env.ledger().timestamp(),
            expires_at: None,
            metadata,
        };

        env.storage()
            .persistent()
            .set(&ZkKey::Proof(combined_id.clone()), &combined);

        env.events().publish(
            (Symbol::new(&env, "DisclosuresCombined"),),
            (combined_id.clone(),),
        );

        Ok(combined_id)
    }

    pub fn get_selective_disclosure(
        env: Env,
        proof_id: Bytes,
    ) -> Result<SelectiveDisclosureProof, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id))
            .ok_or(ZKAttestationError::NotFound)
    }

    pub fn get_combined_disclosure(
        env: Env,
        proof_id: Bytes,
    ) -> Result<CombinedDisclosureProof, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id))
            .ok_or(ZKAttestationError::NotFound)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn generate_proof_id(env: &Env, _circuit_id: &Symbol) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"zk:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }

    fn verify_zk_proof(
        _env: &Env,
        verifier_key: &Bytes,
        _public_inputs: &Vec<Bytes>,
        proof_bytes: &Bytes,
    ) -> Result<bool, ZKAttestationError> {
        if proof_bytes.is_empty() {
            return Err(ZKAttestationError::InvalidProof);
        }
        if verifier_key.is_empty() {
            return Err(ZKAttestationError::InvalidCircuit);
        }
        Ok(true)
    }

    fn hash_verifying_key(env: &Env, verifier_key: &Bytes) -> Bytes {
        env.crypto().sha256(verifier_key).into()
    }

    fn hash_proof(env: &Env, proof_bytes: &Bytes) -> Bytes {
        env.crypto().sha256(proof_bytes).into()
    }

    fn compute_nullifier(
        env: &Env,
        credential_id: &Bytes,
        _circuit_id: &Symbol,
        context: &Bytes,
    ) -> Bytes {
        let mut data = credential_id.clone();
        data.append(context);
        env.crypto().sha256(&data).into()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{vec, Bytes, Env, Map, Symbol, Vec};

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

    fn register_test_circuit(env: &Env) -> Symbol {
        let circuit_id = Symbol::new(env, "test_circuit");
        let admin = env.current_contract_address();
        ZKAttestation::register_circuit(
            env.clone(),
            admin,
            circuit_id.clone(),
            Bytes::from_slice(env, b"Test Circuit"),
            Bytes::from_slice(env, b"Test Description"),
            Bytes::from_slice(env, b"test_verifier_key_32_bytes_long!"),
            2,
            3,
            CircuitType::RangeProof,
            vec![env, Symbol::new(env, "age_commitment")],
        )
        .unwrap();
        circuit_id
    }

    // ── Issue #41: Event emission tests ─────────────────────────────────

    #[test]
    fn test_circuit_registered_event_emitted() {
        let env = setup_env();
        let circuit_id = Symbol::new(&env, "test_circuit");
        let admin = env.current_contract_address();

        ZKAttestation::register_circuit(
            env.clone(),
            admin,
            circuit_id,
            Bytes::from_slice(&env, b"Test Circuit"),
            Bytes::from_slice(&env, b"Test Description"),
            Bytes::from_slice(&env, b"test_verifier_key_32_bytes_long!"),
            2,
            3,
            CircuitType::RangeProof,
            vec![&env, Symbol::new(&env, "age_commitment")],
        )
        .unwrap();

        let events = env.events().all();
        assert!(events.iter().any(|e| {
            let topics = e.0.clone();
            topics.contains(&soroban_sdk::Val::Symbol(Symbol::new(
                &env,
                "CircuitRegistered",
            )))
        }));
    }

    #[test]
    fn test_proof_created_event_emitted() {
        let env = setup_env();
        let circuit_id = register_test_circuit(&env);

        let public_inputs = vec![
            &env,
            Bytes::from_slice(&env, b"commitment_1"),
            Bytes::from_slice(&env, b"18"),
        ];
        let proof_bytes = Bytes::from_slice(&env, b"valid_zk_proof_data");
        let nullifier = Bytes::from_slice(&env, b"unique_nullifier_1");
        let revealed_attributes = vec![&env, Symbol::new(&env, "age_commitment")];
        let mut metadata = Map::new(&env);
        metadata.set(
            Symbol::new(&env, "context"),
            Bytes::from_slice(&env, b"age_verification"),
        );

        ZKAttestation::submit_proof(
            env.clone(),
            circuit_id,
            public_inputs,
            proof_bytes,
            nullifier,
            revealed_attributes,
            None,
            metadata,
        )
        .unwrap();

        let events = env.events().all();
        assert!(events.iter().any(|e| {
            let topics = e.0.clone();
            topics.contains(&soroban_sdk::Val::Symbol(Symbol::new(
                &env,
                "ProofCreated",
            )))
        }));
    }

    #[test]
    fn test_proof_verified_event_emitted() {
        let env = setup_env();
        let circuit_id = register_test_circuit(&env);

        let public_inputs = vec![
            &env,
            Bytes::from_slice(&env, b"commitment_1"),
            Bytes::from_slice(&env, b"18"),
        ];
        let proof_bytes = Bytes::from_slice(&env, b"valid_zk_proof_data");
        let nullifier = Bytes::from_slice(&env, b"unique_nullifier_2");
        let revealed_attributes = vec![&env, Symbol::new(&env, "age_commitment")];
        let mut metadata = Map::new(&env);
        metadata.set(
            Symbol::new(&env, "context"),
            Bytes::from_slice(&env, b"age_verification"),
        );

        let proof_id = ZKAttestation::submit_proof(
            env.clone(),
            circuit_id,
            public_inputs,
            proof_bytes,
            nullifier,
            revealed_attributes,
            None,
            metadata,
        )
        .unwrap();

        ZKAttestation::verify_proof(env.clone(), proof_id).unwrap();

        let events = env.events().all();
        assert!(events.iter().any(|e| {
            let topics = e.0.clone();
            topics.contains(&soroban_sdk::Val::Symbol(Symbol::new(
                &env,
                "ProofVerified",
            )))
        }));
    }

    // ── Selective Disclosure tests (#111) ──────────────────────────────

    fn register_sd_test_circuit(env: &Env) -> Symbol {
        let circuit_id = Symbol::new(env, "sd_circuit");
        let admin = env.current_contract_address();
        ZKAttestation::register_circuit(
            env.clone(),
            admin,
            circuit_id.clone(),
            Bytes::from_slice(env, b"Selective Disclosure"),
            Bytes::from_slice(env, b"Test selective disclosure circuit"),
            Bytes::from_slice(env, b"sd_verifier_key_32_bytes_long!!"),
            3,
            4,
            CircuitType::SelectiveDisclosure,
            vec![
                env,
                Symbol::new(env, "age"),
                Symbol::new(env, "income"),
                Symbol::new(env, "credit_score"),
            ],
        )
        .unwrap();
        circuit_id
    }

    #[test]
    fn test_create_selective_disclosure_proof() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        let public_inputs = vec![
            &env,
            Bytes::from_slice(&env, b"commitment_1"),
            Bytes::from_slice(&env, b"18"),
            Bytes::from_slice(&env, b"65"),
        ];
        let proof_bytes = Bytes::from_slice(&env, b"valid_zk_proof_data");
        let nullifier = Bytes::from_slice(&env, b"sd_nullifier_1");
        let revealed = vec![&env, Symbol::new(&env, "credit_score")];
        let hidden = vec![&env, Symbol::new(&env, "age")];
        let predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "age"),
                predicate_type: PredicateType::Range,
                threshold: None,
                range_min: Some(Bytes::from_slice(&env, b"18")),
                range_max: Some(Bytes::from_slice(&env, b"65")),
                allowed_values: None,
            },
        ];
        let mut metadata = Map::new(&env);
        metadata.set(
            Symbol::new(&env, "context"),
            Bytes::from_slice(&env, b"age_verification"),
        );

        let result = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id,
            public_inputs,
            proof_bytes,
            nullifier,
            revealed,
            hidden,
            predicates,
            None,
            metadata,
        );

        assert!(result.is_ok());
        let proof_id = result.unwrap();
        assert!(!proof_id.is_empty());
    }

    #[test]
    fn test_selective_disclosure_rejects_conflicting_attributes() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        let predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "age"),
                predicate_type: PredicateType::GreaterThan,
                threshold: Some(Bytes::from_slice(&env, b"18")),
                range_min: None,
                range_max: None,
                allowed_values: None,
            },
        ];

        let result = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id,
            vec![&env, Bytes::from_slice(&env, b"input_1")],
            Bytes::from_slice(&env, b"proof_data"),
            Bytes::from_slice(&env, b"nullifier_2"),
            vec![&env, Symbol::new(&env, "age")],   // revealed
            vec![&env, Symbol::new(&env, "age")],   // hidden (conflict)
            predicates,
            None,
            Map::new(&env),
        );

        assert_eq!(result, Err(ZKAttestationError::DisclosureConflict));
    }

    #[test]
    fn test_verify_selective_disclosure_success() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        let predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "age"),
                predicate_type: PredicateType::Range,
                threshold: None,
                range_min: Some(Bytes::from_slice(&env, b"18")),
                range_max: Some(Bytes::from_slice(&env, b"65")),
                allowed_values: None,
            },
        ];

        let proof_id = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id.clone(),
            vec![
                &env,
                Bytes::from_slice(&env, b"commitment_1"),
                Bytes::from_slice(&env, b"18"),
                Bytes::from_slice(&env, b"65"),
            ],
            Bytes::from_slice(&env, b"valid_proof"),
            Bytes::from_slice(&env, b"nullifier_3"),
            vec![&env, Symbol::new(&env, "credit_score")],
            vec![&env, Symbol::new(&env, "age")],
            predicates.clone(),
            None,
            Map::new(&env),
        )
        .unwrap();

        let result = ZKAttestation::verify_selective_disclosure(
            env.clone(),
            proof_id,
            predicates,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_selective_disclosure_predicate_mismatch() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        let predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "age"),
                predicate_type: PredicateType::Range,
                threshold: None,
                range_min: Some(Bytes::from_slice(&env, b"18")),
                range_max: Some(Bytes::from_slice(&env, b"65")),
                allowed_values: None,
            },
        ];

        let proof_id = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id.clone(),
            vec![
                &env,
                Bytes::from_slice(&env, b"commitment_1"),
                Bytes::from_slice(&env, b"18"),
                Bytes::from_slice(&env, b"65"),
            ],
            Bytes::from_slice(&env, b"valid_proof"),
            Bytes::from_slice(&env, b"nullifier_4"),
            vec![&env, Symbol::new(&env, "credit_score")],
            vec![&env, Symbol::new(&env, "age")],
            predicates,
            None,
            Map::new(&env),
        )
        .unwrap();

        let wrong_predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "income"),
                predicate_type: PredicateType::GreaterThan,
                threshold: Some(Bytes::from_slice(&env, b"100000")),
                range_min: None,
                range_max: None,
                allowed_values: None,
            },
        ];

        let result = ZKAttestation::verify_selective_disclosure(
            env.clone(),
            proof_id,
            wrong_predicates,
        );

        assert_eq!(result, Err(ZKAttestationError::PredicateMismatch));
    }

    #[test]
    fn test_combine_selective_disclosures() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        let age_predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "age"),
                predicate_type: PredicateType::Range,
                threshold: None,
                range_min: Some(Bytes::from_slice(&env, b"18")),
                range_max: Some(Bytes::from_slice(&env, b"65")),
                allowed_values: None,
            },
        ];

        let income_predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "income"),
                predicate_type: PredicateType::GreaterThan,
                threshold: Some(Bytes::from_slice(&env, b"50000")),
                range_min: None,
                range_max: None,
                allowed_values: None,
            },
        ];

        let proof_id_1 = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id.clone(),
            vec![&env, Bytes::from_slice(&env, b"c1")],
            Bytes::from_slice(&env, b"proof_1"),
            Bytes::from_slice(&env, b"nullifier_5"),
            vec![&env],
            vec![&env, Symbol::new(&env, "age")],
            age_predicates,
            None,
            Map::new(&env),
        )
        .unwrap();

        let proof_id_2 = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id.clone(),
            vec![&env, Bytes::from_slice(&env, b"c2")],
            Bytes::from_slice(&env, b"proof_2"),
            Bytes::from_slice(&env, b"nullifier_6"),
            vec![&env],
            vec![&env, Symbol::new(&env, "income")],
            income_predicates,
            None,
            Map::new(&env),
        )
        .unwrap();

        let combined = ZKAttestation::combine_selective_disclosures(
            env.clone(),
            vec![&env, proof_id_1, proof_id_2],
            Map::new(&env),
        );

        assert!(combined.is_ok());
    }

    #[test]
    fn test_combine_selective_disclosures_empty_fails() {
        let env = setup_env();
        let result = ZKAttestation::combine_selective_disclosures(
            env.clone(),
            vec![&env],
            Map::new(&env),
        );
        assert_eq!(result, Err(ZKAttestationError::CombiningFailed));
    }

    #[test]
    fn test_selective_disclosure_getters() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        let predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "age"),
                predicate_type: PredicateType::Range,
                threshold: None,
                range_min: Some(Bytes::from_slice(&env, b"18")),
                range_max: Some(Bytes::from_slice(&env, b"65")),
                allowed_values: None,
            },
        ];

        let proof_id = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id.clone(),
            vec![&env, Bytes::from_slice(&env, b"c1")],
            Bytes::from_slice(&env, b"proof_data"),
            Bytes::from_slice(&env, b"nullifier_7"),
            vec![&env, Symbol::new(&env, "credit_score")],
            vec![&env, Symbol::new(&env, "age")],
            predicates,
            None,
            Map::new(&env),
        )
        .unwrap();

        let fetched = ZKAttestation::get_selective_disclosure(env.clone(), proof_id);
        assert!(fetched.is_ok());
        let disclosure = fetched.unwrap();
        assert_eq!(disclosure.hidden_attributes.len(), 1);
        assert_eq!(disclosure.revealed_attributes.len(), 1);
        assert_eq!(disclosure.predicates.len(), 1);
    }

    #[test]
    fn test_selective_disclosure_rejects_nullifier_reuse() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        let predicates = vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "age"),
                predicate_type: PredicateType::GreaterThan,
                threshold: Some(Bytes::from_slice(&env, b"18")),
                range_min: None,
                range_max: None,
                allowed_values: None,
            },
        ];

        let nullifier = Bytes::from_slice(&env, b"reuse_nullifier");

        // First use succeeds
        let first = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id.clone(),
            vec![&env, Bytes::from_slice(&env, b"c1")],
            Bytes::from_slice(&env, b"proof_data"),
            nullifier.clone(),
            vec![&env],
            vec![&env, Symbol::new(&env, "age")],
            predicates.clone(),
            None,
            Map::new(&env),
        );
        assert!(first.is_ok());

        // Second use with same nullifier fails
        let second = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_456"),
            circuit_id.clone(),
            vec![&env, Bytes::from_slice(&env, b"c2")],
            Bytes::from_slice(&env, b"proof_data_2"),
            nullifier,
            vec![&env],
            vec![&env, Symbol::new(&env, "age")],
            predicates,
            None,
            Map::new(&env),
        );
        assert_eq!(second, Err(ZKAttestationError::NullifierAlreadyUsed));
    }

    #[test]
    fn test_selective_disclosure_event_emitted() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_123"),
            circuit_id,
            vec![&env, Bytes::from_slice(&env, b"c1")],
            Bytes::from_slice(&env, b"proof_data"),
            Bytes::from_slice(&env, b"event_nullifier"),
            vec![&env],
            vec![&env, Symbol::new(&env, "age")],
            vec![
                &env,
                PredicateInfo {
                    attribute_name: Symbol::new(&env, "age"),
                    predicate_type: PredicateType::Range,
                    threshold: None,
                    range_min: Some(Bytes::from_slice(&env, b"18")),
                    range_max: Some(Bytes::from_slice(&env, b"65")),
                    allowed_values: None,
                },
            ],
            None,
            Map::new(&env),
        )
        .unwrap();

        let events = env.events().all();
        assert!(events.iter().any(|e| {
            let topics = e.0.clone();
            topics.contains(&soroban_sdk::Val::Symbol(Symbol::new(
                &env,
                "SelectiveDisclosureCreated",
            )))
        }));
    }
}
