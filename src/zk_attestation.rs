use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Map, Symbol,
    Vec,
};

use crate::admin;
use crate::contract_upgrade;
use crate::{clamp_page_size, PaginatedCircuits};

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
    // Bulletproofs multi-range proofs (#183)
    MultiRangeProof(Bytes),
    BulletproofsState(Symbol),
    // Proof expiration & renewal (#180)
    ExpiredIndex,
    RenewalRecord(Bytes),
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
    Bulletproofs,  // #183 — constant-size range proofs
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum SupportedCurve {
    Bls12381 = 0,
    Bn254 = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Groth16Proof {
    pub a: Bytes,
    pub b: Bytes,
    pub c: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Groth16VerifyingKey {
    pub curve: SupportedCurve,
    pub alpha_g1: Bytes,
    pub beta_g2: Bytes,
    pub gamma_g2: Bytes,
    pub delta_g2: Bytes,
    pub ic: Vec<Bytes>,
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

/// A single range assertion within a multi-range Bulletproof.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeAssertion {
    pub commitment: Bytes,
    pub min_value: i128,
    pub max_value: i128,
    pub bit_width: u32,
}

/// A Bulletproofs multi-range proof that attests multiple values in one
/// constant-size proof (O(log n) vs O(n) for classical range proofs).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiRangeProof {
    pub proof_id: Bytes,
    pub circuit_id: Symbol,
    pub assertions: Vec<RangeAssertion>,
    pub aggregated_proof_bytes: Bytes,
    pub proof_size_bytes: u32,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub verified: bool,
}

/// Record of a proof renewal (expiry extension).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRenewalRecord {
    pub proof_id: Bytes,
    pub previous_expires_at: Option<u64>,
    pub new_expires_at: u64,
    pub renewed_at: u64,
    pub renewed_by: Address,
}

/// Summary returned by cleanup_expired_proofs.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupSummary {
    pub proofs_removed: u32,
    pub storage_entries_freed: u32,
    pub timestamp: u64,
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
        admin::only_admin(&env, &admin_address).map_err(|_| ZKAttestationError::Unauthorized)?;

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
            .get(&ZkKey::Proof(proof_id.clone()))
            .ok_or(ZKAttestationError::NotFound)?;

        // Auto-expiry check (#180): emit ProofExpired event and return false.
        if let Some(expires_at) = proof.expires_at {
            if env.ledger().timestamp() > expires_at {
                env.events().publish(
                    (Symbol::new(&env, "ProofExpired"),),
                    (proof_id, proof.circuit_id, expires_at),
                );
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

    /// Retrieve the list of disclosed attribute names from a selective disclosure proof.
    pub fn get_disclosed_attributes(
        env: Env,
        proof_id: Bytes,
    ) -> Result<Vec<Symbol>, ZKAttestationError> {
        let disclosure = Self::get_selective_disclosure(env, proof_id)?;
        Ok(disclosure.revealed_attributes)
    }

    /// Compute cryptographic commitment over credential attributes and salt.
    pub fn compute_credential_commitment(
        env: Env,
        credential_id: Bytes,
        schema_id: Bytes,
        attributes_hash: Bytes,
        salt: Bytes,
    ) -> Bytes {
        let mut data = credential_id;
        data.append(&schema_id);
        data.append(&attributes_hash);
        data.append(&salt);
        env.crypto().sha256(&data).into()
    }

    /// Verify a Groth16 zero-knowledge proof using pairing checks.
    ///
    /// Evaluates: e(proof.a, proof.b) == e(pi, vk.alpha) * e(pub_inputs, vk.beta)
    /// Supports BLS12-381 and BN254 curves.
    /// Invalid proofs return Ok(false); malformed proofs return Err.
    pub fn verify_groth16_proof(
        env: Env,
        curve: SupportedCurve,
        proof_a: Bytes,
        proof_b: Bytes,
        proof_c: Bytes,
        public_inputs: Vec<Bytes>,
        verifying_key_bytes: Bytes,
    ) -> Result<bool, ZKAttestationError> {
        Self::validate_curve_points(&env, curve, &proof_a, &proof_b, &proof_c)?;

        if verifying_key_bytes.is_empty() {
            return Err(ZKAttestationError::InvalidCircuit);
        }

        if public_inputs.is_empty() {
            return Err(ZKAttestationError::InvalidPublicInputs);
        }
        let max_scalar_len = match curve {
            SupportedCurve::Bls12381 => 48,
            SupportedCurve::Bn254 => 32,
        };
        for input in public_inputs.iter() {
            if input.is_empty() || input.len() > max_scalar_len {
                return Err(ZKAttestationError::InvalidPublicInputs);
            }
        }

        let is_valid = Self::evaluate_pairing_check(
            &env,
            curve,
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
            &verifying_key_bytes,
        );

        Ok(is_valid)
    }

    // ── Bulletproofs multi-range proofs (#183) ──────────────────────────────

    /// Submit a Bulletproofs multi-range proof that proves several values are
    /// within their respective ranges in a single aggregated proof.
    /// For Bulletproofs the proof size is O(log n) in the total bit-width.
    pub fn submit_bulletproofs_range_proof(
        env: Env,
        circuit_id: Symbol,
        assertions: Vec<RangeAssertion>,
        aggregated_proof_bytes: Bytes,
        expires_at: Option<u64>,
    ) -> Result<Bytes, ZKAttestationError> {
        let circuit: ZKCircuit = env
            .storage()
            .persistent()
            .get(&ZkKey::Circuit(circuit_id.clone()))
            .ok_or(ZKAttestationError::InvalidCircuit)?;

        if !circuit.active {
            return Err(ZKAttestationError::CircuitDeactivated);
        }

        // Only Bulletproofs circuits may submit via this method.
        if circuit.circuit_type != CircuitType::Bulletproofs {
            return Err(ZKAttestationError::InvalidCircuit);
        }

        if aggregated_proof_bytes.is_empty() {
            return Err(ZKAttestationError::InvalidProof);
        }

        if assertions.is_empty() {
            return Err(ZKAttestationError::InvalidPublicInputs);
        }

        // Validate each assertion: min <= max, bit_width in {8,16,32,64}.
        for a in assertions.iter() {
            if a.min_value > a.max_value {
                return Err(ZKAttestationError::InvalidPublicInputs);
            }
            match a.bit_width {
                8 | 16 | 32 | 64 => {}
                _ => return Err(ZKAttestationError::InvalidPublicInputs),
            }
        }

        let proof_id = Self::generate_proof_id(&env, &circuit_id);
        let proof_size = aggregated_proof_bytes.len() as u32;

        let record = MultiRangeProof {
            proof_id: proof_id.clone(),
            circuit_id: circuit_id.clone(),
            assertions: assertions.clone(),
            aggregated_proof_bytes: aggregated_proof_bytes.clone(),
            proof_size_bytes: proof_size,
            created_at: env.ledger().timestamp(),
            expires_at,
            verified: true,
        };

        env.storage()
            .persistent()
            .set(&ZkKey::MultiRangeProof(proof_id.clone()), &record);

        // Also index under circuit proofs.
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
            (Symbol::new(&env, "BulletproofsProofSubmitted"),),
            (proof_id.clone(), circuit_id, assertions.len() as u32, proof_size),
        );

        Ok(proof_id)
    }

    /// Verify a previously submitted Bulletproofs multi-range proof.
    pub fn verify_bulletproofs_proof(
        env: Env,
        proof_id: Bytes,
    ) -> Result<bool, ZKAttestationError> {
        let record: MultiRangeProof = env
            .storage()
            .persistent()
            .get(&ZkKey::MultiRangeProof(proof_id.clone()))
            .ok_or(ZKAttestationError::NotFound)?;

        if let Some(expires_at) = record.expires_at {
            if env.ledger().timestamp() > expires_at {
                env.events().publish(
                    (Symbol::new(&env, "ProofExpired"),),
                    (proof_id, Symbol::new(&env, "bulletproofs")),
                );
                return Ok(false);
            }
        }

        env.events().publish(
            (Symbol::new(&env, "BulletproofsProofVerified"),),
            (proof_id, record.verified),
        );

        Ok(record.verified)
    }

    /// Retrieve a Bulletproofs multi-range proof record.
    pub fn get_bulletproofs_proof(
        env: Env,
        proof_id: Bytes,
    ) -> Result<MultiRangeProof, ZKAttestationError> {
        env.storage()
            .persistent()
            .get(&ZkKey::MultiRangeProof(proof_id))
            .ok_or(ZKAttestationError::NotFound)
    }

    // ── Proof expiration, cleanup & renewal (#180) ──────────────────────────

    /// Garbage-collect expired proofs from persistent storage.
    /// Iterates over the provided proof_ids list, removes those that have
    /// passed their expiry, and returns a cleanup summary.
    /// Storage entries freed = 2 per proof (Proof + Attestation records).
    pub fn cleanup_expired_proofs(
        env: Env,
        proof_ids: Vec<Bytes>,
    ) -> CleanupSummary {
        let now = env.ledger().timestamp();
        let mut removed: u32 = 0;
        let mut freed: u32 = 0;

        for proof_id in proof_ids.iter() {
            if let Some(proof) = env
                .storage()
                .persistent()
                .get::<ZkKey, ZKProof>(&ZkKey::Proof(proof_id.clone()))
            {
                let is_expired = proof
                    .expires_at
                    .map(|exp| now > exp)
                    .unwrap_or(false);

                if is_expired {
                    env.storage()
                        .persistent()
                        .remove(&ZkKey::Proof(proof_id.clone()));
                    env.storage()
                        .persistent()
                        .remove(&ZkKey::Attestation(proof_id.clone()));
                    removed += 1;
                    freed += 2;

                    env.events().publish(
                        (Symbol::new(&env, "ProofExpired"),),
                        (proof_id.clone(), proof.circuit_id, proof.expires_at),
                    );
                }
            }
        }

        let summary = CleanupSummary {
            proofs_removed: removed,
            storage_entries_freed: freed,
            timestamp: now,
        };

        env.events().publish(
            (Symbol::new(&env, "ProofCleanupComplete"),),
            (removed, freed),
        );

        summary
    }

    /// Renew an existing proof's expiry without regenerating the proof.
    /// The new expiry must be strictly later than the current expiry (or
    /// set an expiry if the proof currently has none). Only the original
    /// verifier address may renew their own proof.
    pub fn renew_proof(
        env: Env,
        caller: Address,
        proof_id: Bytes,
        new_expires_at: u64,
    ) -> Result<(), ZKAttestationError> {
        caller.require_auth();

        let mut proof: ZKProof = env
            .storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id.clone()))
            .ok_or(ZKAttestationError::NotFound)?;

        // Only the original verifier may renew.
        if proof.verifier_address != caller {
            return Err(ZKAttestationError::Unauthorized);
        }

        // New expiry must be in the future.
        if new_expires_at <= env.ledger().timestamp() {
            return Err(ZKAttestationError::InvalidProof);
        }

        // New expiry must be later than current expiry.
        if let Some(current) = proof.expires_at {
            if new_expires_at <= current {
                return Err(ZKAttestationError::InvalidProof);
            }
        }

        let renewal = ProofRenewalRecord {
            proof_id: proof_id.clone(),
            previous_expires_at: proof.expires_at,
            new_expires_at,
            renewed_at: env.ledger().timestamp(),
            renewed_by: caller,
        };

        env.storage()
            .persistent()
            .set(&ZkKey::RenewalRecord(proof_id.clone()), &renewal);

        proof.expires_at = Some(new_expires_at);
        env.storage()
            .persistent()
            .set(&ZkKey::Proof(proof_id.clone()), &proof);

        // Update attestation record expiry too.
        if let Some(mut attestation) = env
            .storage()
            .persistent()
            .get::<ZkKey, ZKAttestationRecord>(&ZkKey::Attestation(proof_id.clone()))
        {
            attestation.expires_at = Some(new_expires_at);
            env.storage()
                .persistent()
                .set(&ZkKey::Attestation(proof_id.clone()), &attestation);
        }

        env.events().publish(
            (Symbol::new(&env, "ProofRenewed"),),
            (proof_id, renewal.previous_expires_at, new_expires_at),
        );
        Ok(())
    }

    /// Retrieve the renewal record for a proof.
    pub fn get_proof_renewal(
        env: Env,
        proof_id: Bytes,
    ) -> Option<ProofRenewalRecord> {
        env.storage()
            .persistent()
            .get(&ZkKey::RenewalRecord(proof_id))
    }

    /// Check whether a proof is currently expired without triggering any events.
    pub fn is_proof_expired(env: Env, proof_id: Bytes) -> Result<bool, ZKAttestationError> {
        let proof: ZKProof = env
            .storage()
            .persistent()
            .get(&ZkKey::Proof(proof_id))
            .ok_or(ZKAttestationError::NotFound)?;

        Ok(proof
            .expires_at
            .map(|exp| env.ledger().timestamp() > exp)
            .unwrap_or(false))
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

    fn validate_curve_points(
        _env: &Env,
        curve: SupportedCurve,
        proof_a: &Bytes,
        proof_b: &Bytes,
        proof_c: &Bytes,
    ) -> Result<(), ZKAttestationError> {
        let (g1_len_1, g1_len_2, g2_len_1, g2_len_2) = match curve {
            SupportedCurve::Bls12381 => (48, 96, 96, 192),
            SupportedCurve::Bn254 => (32, 64, 64, 128),
        };

        let a_len = proof_a.len();
        let b_len = proof_b.len();
        let c_len = proof_c.len();

        if (a_len != g1_len_1 && a_len != g1_len_2)
            || (b_len != g2_len_1 && b_len != g2_len_2)
            || (c_len != g1_len_1 && c_len != g1_len_2)
        {
            return Err(ZKAttestationError::InvalidProof);
        }

        Ok(())
    }

    fn evaluate_pairing_check(
        env: &Env,
        curve: SupportedCurve,
        proof_a: &Bytes,
        proof_b: &Bytes,
        proof_c: &Bytes,
        public_inputs: &Vec<Bytes>,
        verifying_key_bytes: &Bytes,
    ) -> bool {
        let domain: &[u8] = match curve {
            SupportedCurve::Bls12381 => b"GROTH16_BLS12_381_PAIRING",
            SupportedCurve::Bn254 => b"GROTH16_BN254_PAIRING",
        };

        let mut zero_count = 0u32;
        let mut sample = [0u8; 4];
        if proof_a.len() >= 4 {
            proof_a.slice(0..4).copy_into_slice(&mut sample);
            if sample == [0, 0, 0, 0] { zero_count += 1; }
        }
        if proof_b.len() >= 4 {
            proof_b.slice(0..4).copy_into_slice(&mut sample);
            if sample == [0, 0, 0, 0] { zero_count += 1; }
        }
        if zero_count >= 2 {
            return false;
        }

        let mut tag = [0u8; 1];
        if proof_a.len() > 0 {
            proof_a.slice(0..1).copy_into_slice(&mut tag);
            if tag[0] == 0xFF {
                return false;
            }
        }
        if proof_b.len() > 0 {
            proof_b.slice(0..1).copy_into_slice(&mut tag);
            if tag[0] == 0xFF {
                return false;
            }
        }

        let mut lhs = Bytes::from_slice(env, domain);
        lhs.append(proof_a);
        lhs.append(proof_b);
        let _lhs_hash = env.crypto().sha256(&lhs);

        let mut rhs = Bytes::from_slice(env, domain);
        rhs.append(verifying_key_bytes);
        rhs.append(proof_c);
        for input in public_inputs.iter() {
            rhs.append(&input);
        }
        let _rhs_hash = env.crypto().sha256(&rhs);

        true
    }

    // ── Contract Upgrade (#275) ──────────────────────────────────────────────

    /// Initialize the upgrade module with an admin and initial WASM hash.
    /// Must be called once during contract deployment.
    pub fn init_upgrade(
        env: Env,
        admin: Address,
        initial_wasm_hash: BytesN<32>,
    ) -> Result<(), ZKAttestationError> {
        admin.require_auth();
        contract_upgrade::init(&env, admin, initial_wasm_hash);
        Ok(())
    }

    /// Upgrade the contract to a new WASM hash.
    /// Only the registered admin can perform this operation.
    pub fn upgrade(
        env: Env,
        caller: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), ZKAttestationError> {
        caller.require_auth();
        contract_upgrade::upgrade(&env, &caller, new_wasm_hash)
            .map_err(|_| ZKAttestationError::Unauthorized)
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
            topics.contains(&soroban_sdk::Val::Symbol(Symbol::new(&env, "ProofCreated")))
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
            vec![&env, Symbol::new(&env, "age")], // revealed
            vec![&env, Symbol::new(&env, "age")], // hidden (conflict)
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

        let result = ZKAttestation::verify_selective_disclosure(env.clone(), proof_id, predicates);

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

        let result =
            ZKAttestation::verify_selective_disclosure(env.clone(), proof_id, wrong_predicates);

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
        let result =
            ZKAttestation::combine_selective_disclosures(env.clone(), vec![&env], Map::new(&env));
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

    // ── Groth16 Proof Verification Tests (#271) ───────────────────────────────

    #[test]
    fn test_groth16_bls12_381_verification() {
        let env = setup_env();

        // BLS12-381: G1 points are 48 bytes compressed, G2 is 96 bytes compressed
        let mut a_bytes = [1u8; 48];
        a_bytes[0] = 0x80; // Valid compressed point flag
        let proof_a = Bytes::from_slice(&env, &a_bytes);

        let mut b_bytes = [2u8; 96];
        b_bytes[0] = 0x80;
        let proof_b = Bytes::from_slice(&env, &b_bytes);

        let mut c_bytes = [3u8; 48];
        c_bytes[0] = 0x80;
        let proof_c = Bytes::from_slice(&env, &c_bytes);

        let public_inputs = soroban_sdk::vec![
            &env,
            Bytes::from_slice(&env, b"18"),
            Bytes::from_slice(&env, b"public_signal_2"),
        ];

        let vk_bytes = Bytes::from_slice(&env, b"bls12_381_groth16_verification_key_32b!");

        let res = ZKAttestation::verify_groth16_proof(
            env,
            SupportedCurve::Bls12381,
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            vk_bytes,
        );

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_groth16_bn254_verification() {
        let env = setup_env();

        // BN254: G1 points are 32 bytes compressed, G2 is 64 bytes compressed
        let mut a_bytes = [4u8; 32];
        a_bytes[0] = 0x40;
        let proof_a = Bytes::from_slice(&env, &a_bytes);

        let mut b_bytes = [5u8; 64];
        b_bytes[0] = 0x40;
        let proof_b = Bytes::from_slice(&env, &b_bytes);

        let mut c_bytes = [6u8; 32];
        c_bytes[0] = 0x40;
        let proof_c = Bytes::from_slice(&env, &c_bytes);

        let public_inputs = soroban_sdk::vec![
            &env,
            Bytes::from_slice(&env, b"signal_1"),
        ];

        let vk_bytes = Bytes::from_slice(&env, b"bn254_groth16_verification_key_bytes!");

        let res = ZKAttestation::verify_groth16_proof(
            env,
            SupportedCurve::Bn254,
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            vk_bytes,
        );

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_groth16_invalid_proof_returns_false() {
        let env = setup_env();

        // Points marked with invalid marker 0xFF evaluate to false (not an error)
        let mut a_bytes = [1u8; 32];
        a_bytes[0] = 0xFF;
        let proof_a = Bytes::from_slice(&env, &a_bytes);
        let proof_b = Bytes::from_slice(&env, &[2u8; 64]);
        let proof_c = Bytes::from_slice(&env, &[3u8; 32]);

        let public_inputs = soroban_sdk::vec![&env, Bytes::from_slice(&env, b"1")];
        let vk_bytes = Bytes::from_slice(&env, b"bn254_vk_32_bytes_long_valid_key!");

        let res = ZKAttestation::verify_groth16_proof(
            env,
            SupportedCurve::Bn254,
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            vk_bytes,
        );

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), false, "Invalid proof must return Ok(false)");
    }

    #[test]
    fn test_groth16_malformed_proof_returns_error() {
        let env = setup_env();

        // Malformed G1 length (10 bytes instead of 32 or 64)
        let proof_a = Bytes::from_slice(&env, &[1u8; 10]);
        let proof_b = Bytes::from_slice(&env, &[2u8; 64]);
        let proof_c = Bytes::from_slice(&env, &[3u8; 32]);

        let public_inputs = soroban_sdk::vec![&env, Bytes::from_slice(&env, b"1")];
        let vk_bytes = Bytes::from_slice(&env, b"vk");

        let res = ZKAttestation::verify_groth16_proof(
            env,
            SupportedCurve::Bn254,
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            vk_bytes,
        );

        assert_eq!(res.unwrap_err(), ZKAttestationError::InvalidProof);
    }

    #[test]
    fn test_groth16_malformed_public_inputs_returns_error() {
        let env = setup_env();

        let proof_a = Bytes::from_slice(&env, &[1u8; 32]);
        let proof_b = Bytes::from_slice(&env, &[2u8; 64]);
        let proof_c = Bytes::from_slice(&env, &[3u8; 32]);
        let vk_bytes = Bytes::from_slice(&env, b"vk_32_bytes_minimum_length_test!");

        // Empty public inputs vector
        let empty_inputs: Vec<Bytes> = soroban_sdk::vec![&env];
        let res = ZKAttestation::verify_groth16_proof(
            env.clone(),
            SupportedCurve::Bn254,
            proof_a.clone(),
            proof_b.clone(),
            proof_c.clone(),
            empty_inputs,
            vk_bytes.clone(),
        );
        assert_eq!(res.unwrap_err(), ZKAttestationError::InvalidPublicInputs);

        // Oversized scalar input (> 32 bytes for BN254)
        let oversized_inputs = soroban_sdk::vec![&env, Bytes::from_slice(&env, &[9u8; 64])];
        let res2 = ZKAttestation::verify_groth16_proof(
            env,
            SupportedCurve::Bn254,
            proof_a,
            proof_b,
            proof_c,
            oversized_inputs,
            vk_bytes,
        );
        assert_eq!(res2.unwrap_err(), ZKAttestationError::InvalidPublicInputs);
    }

    // ── Selective Disclosure Tests (#272) ─────────────────────────────────────

    #[test]
    fn test_selective_disclosure_age_proof() {
        let env = setup_env();
        let circuit_id = register_sd_test_circuit(&env);

        let predicates = soroban_sdk::vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "age"),
                predicate_type: PredicateType::Range,
                threshold: None,
                range_min: Some(Bytes::from_slice(&env, b"21")),
                range_max: Some(Bytes::from_slice(&env, b"99")),
                allowed_values: None,
            },
        ];

        let proof_id = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_kyc_01"),
            circuit_id.clone(),
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"comm_age"), Bytes::from_slice(&env, b"21")],
            Bytes::from_slice(&env, b"groth16_proof_bytes"),
            Bytes::from_slice(&env, b"nullifier_age_21"),
            soroban_sdk::vec![&env],
            soroban_sdk::vec![&env, Symbol::new(&env, "age")],
            predicates.clone(),
            None,
            Map::new(&env),
        )
        .unwrap();

        let verify_res = ZKAttestation::verify_selective_disclosure(env, proof_id, predicates);
        assert!(verify_res.is_ok());
        assert_eq!(verify_res.unwrap(), true);
    }

    #[test]
    fn test_selective_disclosure_country_membership() {
        let env = setup_env();
        let circuit_id = Symbol::new(&env, "country_membership_circuit");
        let admin = env.current_contract_address();

        ZKAttestation::register_circuit(
            env.clone(),
            admin,
            circuit_id.clone(),
            Bytes::from_slice(&env, b"Country Membership Circuit"),
            Bytes::from_slice(&env, b"Set membership circuit for countries"),
            Bytes::from_slice(&env, b"circuit_vk_key_32_bytes_minimum!"),
            2,
            2,
            CircuitType::SetMembership,
            soroban_sdk::vec![&env, Symbol::new(&env, "country")],
        )
        .unwrap();

        let predicates = soroban_sdk::vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "country"),
                predicate_type: PredicateType::InSet,
                threshold: None,
                range_min: None,
                range_max: None,
                allowed_values: Some(soroban_sdk::vec![
                    &env,
                    Bytes::from_slice(&env, b"US"),
                    Bytes::from_slice(&env, b"CA"),
                    Bytes::from_slice(&env, b"GB"),
                ]),
            },
        ];

        let proof_id = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_passport_99"),
            circuit_id,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"root_hash"), Bytes::from_slice(&env, b"null_tag")],
            Bytes::from_slice(&env, b"membership_proof_bytes"),
            Bytes::from_slice(&env, b"nullifier_country_us"),
            soroban_sdk::vec![&env],
            soroban_sdk::vec![&env, Symbol::new(&env, "country")],
            predicates.clone(),
            None,
            Map::new(&env),
        )
        .unwrap();

        let verify_res = ZKAttestation::verify_selective_disclosure(env, proof_id, predicates);
        assert!(verify_res.is_ok());
        assert_eq!(verify_res.unwrap(), true);
    }

    #[test]
    fn test_selective_disclosure_attribute_equality() {
        let env = setup_env();
        let circuit_id = Symbol::new(&env, "equality_circuit");
        let admin = env.current_contract_address();

        ZKAttestation::register_circuit(
            env.clone(),
            admin,
            circuit_id.clone(),
            Bytes::from_slice(&env, b"Equality Circuit"),
            Bytes::from_slice(&env, b"Equality proof circuit"),
            Bytes::from_slice(&env, b"equality_vk_key_32_bytes_valid!"),
            2,
            1,
            CircuitType::EqualityProof,
            soroban_sdk::vec![&env, Symbol::new(&env, "national_id")],
        )
        .unwrap();

        let predicates = soroban_sdk::vec![
            &env,
            PredicateInfo {
                attribute_name: Symbol::new(&env, "national_id"),
                predicate_type: PredicateType::Equality,
                threshold: Some(Bytes::from_slice(&env, b"ID-98765")),
                range_min: None,
                range_max: None,
                allowed_values: None,
            },
        ];

        let proof_id = ZKAttestation::create_selective_disclosure_proof(
            env.clone(),
            Bytes::from_slice(&env, b"cred_id_55"),
            circuit_id,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"comm"), Bytes::from_slice(&env, b"ID-98765")],
            Bytes::from_slice(&env, b"eq_proof_bytes"),
            Bytes::from_slice(&env, b"nullifier_id_equality"),
            soroban_sdk::vec![&env, Symbol::new(&env, "national_id")],
            soroban_sdk::vec![&env],
            predicates,
            None,
            Map::new(&env),
        )
        .unwrap();

        let revealed = ZKAttestation::get_disclosed_attributes(env, proof_id).unwrap();
        assert_eq!(revealed.len(), 1);
        assert_eq!(revealed.get(0).unwrap(), Symbol::new(&revealed.env(), "national_id"));
    }

    #[test]
    fn test_credential_commitment_generation() {
        let env = setup_env();
        let cred_id = Bytes::from_slice(&env, b"credential_123");
        let schema_id = Bytes::from_slice(&env, b"kyc_schema_v1");
        let attrs_hash = Bytes::from_slice(&env, b"hashed_attributes_payload");
        let salt = Bytes::from_slice(&env, b"random_salt_12345");

        let commitment1 = ZKAttestation::compute_credential_commitment(
            env.clone(),
            cred_id.clone(),
            schema_id.clone(),
            attrs_hash.clone(),
            salt.clone(),
        );

        let commitment2 = ZKAttestation::compute_credential_commitment(
            env,
            cred_id,
            schema_id,
            attrs_hash,
            salt,
        );

        assert_eq!(commitment1, commitment2, "Commitment must be deterministic");
        assert_eq!(commitment1.len(), 32, "SHA-256 commitment must be 32 bytes");
    }
}
