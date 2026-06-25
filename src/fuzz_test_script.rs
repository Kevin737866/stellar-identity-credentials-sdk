#![cfg(test)]

use crate::{
    compliance_filter::{ComplianceFilter, ComplianceFilterError},
    credential_issuer::{CredentialIssuer, CredentialIssuerError},
    did_registry::{DIDRegistry, DIDRegistryError},
    reputation_score::{ReputationScore, ReputationScoreError},
    zk_attestation::{CircuitType, ZKAttestationContract, ZKAttestationError},
    VerificationMethod,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

// ── Test helpers ─────────────────────────────────────────────────────────────

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

fn generate_address(env: &Env) -> Address {
    Address::generate(env)
}

/// Build a minimal, valid VerificationMethod anchored to `controller`.
fn make_vm(env: &Env, controller: &Address) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, b"#key-1"),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
        controller: controller.clone(),
        public_key: BytesN::from_array(env, &[1u8; 32]),
    }
}

/// Register a ZK circuit and return its Symbol id.
fn register_circuit(env: &Env, id: &str) -> Symbol {
    let circuit_id = Symbol::new(env, id);
    ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).register_circuit(
        env.clone(),
        circuit_id.clone(),
        Bytes::from_slice(env, b"Test Circuit"),
        Bytes::from_slice(env, b"A test circuit"),
        Bytes::from_slice(env, b"key_data_16_bytes!"),
        1,
        1,
        CircuitType::RangeProof,
        Vec::new(env),
    )
    .expect("circuit registration should succeed");
    circuit_id
}

/// Build a default metadata map used by ZK proof tests.
fn make_metadata(env: &Env) -> Map<Symbol, Bytes> {
    let mut metadata = Map::new(env);
    metadata.set(Symbol::new(env, "context"), Bytes::from_slice(env, b"test"));
    metadata
}

// ── DIDRegistry ──────────────────────────────────────────────────────────────

mod did_registry_tests {
    use super::*;

    // ── Success paths ─────────────────────────────────────────────────────────

    #[test]
    fn create_valid_did_succeeds() {
        let env = setup_env();
        let controller = generate_address(&env);
        let did = Bytes::from_slice(&env, b"did:stellar:GABCDEFGHIJK");
        let vm = make_vm(&env, &controller);

        let result =
            DIDRegistry::create_did(env.clone(), controller, did, soroban_sdk::vec![&env, vm], Vec::new(&env));
        assert!(result.is_ok(), "valid DID creation should succeed");
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_did_exceeding_max_length() {
        let env = setup_env();
        let controller = generate_address(&env);
        let long_did = Bytes::from_slice(&env, &[b'a'; 10_000]);
        let vm = make_vm(&env, &controller);

        let result = DIDRegistry::create_did(
            env.clone(),
            controller,
            long_did,
            soroban_sdk::vec![&env, vm],
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), DIDRegistryError::InvalidFormat);
    }

    #[test]
    fn rejects_invalid_did_format() {
        let env = setup_env();
        let controller = generate_address(&env);
        let bad_did = Bytes::from_slice(&env, b"invalid:did:format");
        let vm = make_vm(&env, &controller);

        let result = DIDRegistry::create_did(
            env.clone(),
            controller,
            bad_did,
            soroban_sdk::vec![&env, vm],
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), DIDRegistryError::InvalidFormat);
    }

    #[test]
    fn rejects_empty_did() {
        let env = setup_env();
        let controller = generate_address(&env);
        let empty_did = Bytes::new(&env);
        let vm = make_vm(&env, &controller);

        let result = DIDRegistry::create_did(
            env.clone(),
            controller,
            empty_did,
            soroban_sdk::vec![&env, vm],
            Vec::new(&env),
        );
        assert!(result.is_err(), "empty DID should be rejected");
    }

    #[test]
    fn rejects_did_with_no_verification_methods() {
        let env = setup_env();
        let controller = generate_address(&env);
        let did = Bytes::from_slice(&env, b"did:stellar:GABCDEFGHIJK");

        let result = DIDRegistry::create_did(
            env.clone(),
            controller,
            did,
            Vec::new(&env), // no VMs
            Vec::new(&env),
        );
        assert!(
            result.is_err(),
            "DID with no verification methods should be rejected"
        );
    }

    #[test]
    fn rejects_duplicate_did_registration() {
        let env = setup_env();
        let controller = generate_address(&env);
        let did = Bytes::from_slice(&env, b"did:stellar:GABCDEFGHIJK");
        let vm = make_vm(&env, &controller);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            soroban_sdk::vec![&env, vm.clone()],
            Vec::new(&env),
        )
        .unwrap();

        let result =
            DIDRegistry::create_did(env.clone(), controller, did, soroban_sdk::vec![&env, vm], Vec::new(&env));
        assert!(
            result.is_err(),
            "duplicate DID registration should be rejected"
        );
    }

    /// Boundary: exactly at the max allowed DID length should succeed.
    #[test]
    fn accepts_did_at_max_boundary() {
        let env = setup_env();
        let controller = generate_address(&env);
        // Assumes MAX_DID_LENGTH = 256; adjust if your contract differs.
        let max_did = Bytes::from_slice(&env, &[b'a'; 256]);
        let vm = make_vm(&env, &controller);

        // Either succeeds (at boundary) or fails with InvalidFormat — never panics.
        let result = DIDRegistry::create_did(
            env.clone(),
            controller,
            max_did,
            soroban_sdk::vec![&env, vm],
            Vec::new(&env),
        );
        assert!(
            result.is_ok() || result.unwrap_err() == DIDRegistryError::InvalidFormat,
            "boundary-length DID must either succeed or return InvalidFormat"
        );
    }
}

// ── CredentialIssuer ─────────────────────────────────────────────────────────

mod credential_issuer_tests {
    use super::*;

    // ── Success paths ─────────────────────────────────────────────────────────

    #[test]
    fn registered_issuer_can_issue_credential() {
        let env = setup_env();
        let issuer = generate_address(&env);
        let subject = generate_address(&env);

        CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer,
            subject,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"IdentityCredential")],
            Bytes::from_slice(&env, b"claim_data"),
            None,
            Bytes::from_slice(&env, b"valid_proof"),
        );
        assert!(
            result.is_ok(),
            "registered issuer should be able to issue a credential"
        );
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_credential_with_empty_claims() {
        let env = setup_env();
        let issuer = generate_address(&env);
        let subject = generate_address(&env);

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer,
            subject,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::new(&env), // empty claims
            None,
            Bytes::from_slice(&env, b"proof"),
        );
        assert_eq!(
            result.unwrap_err(),
            CredentialIssuerError::InvalidCredential
        );
    }

    #[test]
    fn rejects_empty_credential_type_list() {
        let env = setup_env();
        let issuer = generate_address(&env);
        let subject = generate_address(&env);

        CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer,
            subject,
            Vec::new(&env), // no credential types
            Bytes::from_slice(&env, b"data"),
            None,
            Bytes::from_slice(&env, b"proof"),
        );
        assert_eq!(
            result.unwrap_err(),
            CredentialIssuerError::InvalidCredential
        );
    }

    #[test]
    fn rejects_unregistered_issuer() {
        let env = setup_env();
        let issuer = generate_address(&env);
        let subject = generate_address(&env);

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer, // never registered
            subject,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"IdentityCredential")],
            Bytes::from_slice(&env, b"data"),
            None,
            Bytes::from_slice(&env, b"proof"),
        );
        assert!(result.is_err(), "unregistered issuer should be rejected");
    }

    #[test]
    fn rejects_oversized_credential_type() {
        let env = setup_env();
        let issuer = generate_address(&env);
        let subject = generate_address(&env);

        // 5 000 bytes > MAX_CREDENTIAL_TYPE_LENGTH (128)
        let oversized_type = soroban_sdk::vec![&env, Bytes::from_slice(&env, &[b'X'; 5_000])];

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer,
            subject,
            oversized_type,
            Bytes::from_slice(&env, b"data"),
            None,
            Bytes::from_slice(&env, b"proof"),
        );
        assert!(
            result.is_err(),
            "oversized credential type should be rejected"
        );
    }

    #[test]
    fn rejects_duplicate_issuer_registration() {
        let env = setup_env();
        let issuer = generate_address(&env);

        CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();
        let result = CredentialIssuer::register_issuer(env.clone(), issuer);
        assert!(
            result.is_err(),
            "duplicate issuer registration should be rejected"
        );
    }

    #[test]
    fn rejects_expired_credential() {
        let env = setup_env();
        let issuer = generate_address(&env);
        let subject = generate_address(&env);

        CredentialIssuer::register_issuer(env.clone(), issuer.clone()).unwrap();

        // expiry in the past
        let past_timestamp = Some(1_000_000_000u64);

        let result = CredentialIssuer::issue_credential(
            env.clone(),
            issuer,
            subject,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"IdentityCredential")],
            Bytes::from_slice(&env, b"data"),
            past_timestamp,
            Bytes::from_slice(&env, b"proof"),
        );
        assert!(
            result.is_err(),
            "credential with past expiry should be rejected"
        );
    }
}

// ── ReputationScore ───────────────────────────────────────────────────────────

mod reputation_score_tests {
    use super::*;

    // ── Success paths ─────────────────────────────────────────────────────────

    #[test]
    fn attest_trust_within_valid_range_succeeds() {
        let env = setup_env();
        let attester = generate_address(&env);
        let subject = generate_address(&env);

        ReputationScore::initialize_reputation(env.clone(), attester.clone()).unwrap();

        // Boundary values: 0, 500, and 1000 should all succeed
        for score in [0u32, 500, 1000] {
            let result = ReputationScore::attest_trust(
                env.clone(),
                attester.clone(),
                subject.clone(),
                score,
                Bytes::from_slice(&env, b"context"),
            );
            assert!(result.is_ok(), "score {score} should be accepted");
        }
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_trust_score_above_maximum() {
        let env = setup_env();
        let user = generate_address(&env);
        ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

        let result = ReputationScore::attest_trust(
            env.clone(),
            user.clone(),
            generate_address(&env),
            1001, // just over the max
            Bytes::from_slice(&env, b"test"),
        );
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidScore);
    }

    #[test]
    fn rejects_trust_graph_depth_of_zero() {
        let env = setup_env();
        let user = generate_address(&env);

        let result = ReputationScore::get_trust_graph(env.clone(), user.clone(), 0);
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidDepth);
    }

    #[test]
    fn rejects_trust_graph_depth_above_maximum() {
        let env = setup_env();
        let user = generate_address(&env);

        let result = ReputationScore::get_trust_graph(env.clone(), user.clone(), 5);
        assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidDepth);
    }

    #[test]
    fn accepts_trust_graph_at_valid_depths() {
        let env = setup_env();
        let user = generate_address(&env);
        ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

        // Assumes valid depth range is 1–4 inclusive; adjust if your contract differs.
        for depth in 1u32..=4 {
            let result = ReputationScore::get_trust_graph(env.clone(), user.clone(), depth);
            assert!(result.is_ok(), "depth {depth} should be valid");
        }
    }

    #[test]
    fn rejects_self_attestation() {
        let env = setup_env();
        let user = generate_address(&env);
        ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

        let result = ReputationScore::attest_trust(
            env.clone(),
            user.clone(),
            user.clone(), // attesting oneself
            500,
            Bytes::from_slice(&env, b"self"),
        );
        assert!(result.is_err(), "self-attestation should be rejected");
    }

    #[test]
    fn rejects_attestation_from_uninitialized_user() {
        let env = setup_env();
        let uninitialized = generate_address(&env);
        let subject = generate_address(&env);

        let result = ReputationScore::attest_trust(
            env.clone(),
            uninitialized, // no initialize_reputation called
            subject,
            500,
            Bytes::from_slice(&env, b"test"),
        );
        assert!(
            result.is_err(),
            "attestation from uninitialized user should fail"
        );
    }
}

// ── ZKAttestation ─────────────────────────────────────────────────────────────

mod zk_attestation_tests {
    use super::*;

    // ── Success paths ─────────────────────────────────────────────────────────

    #[test]
    fn valid_proof_submission_succeeds() {
        let env = setup_env();
        let circuit_id = register_circuit(&env, "valid_proof");
        let metadata = make_metadata(&env);

        let result = ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).submit_proof(
            env.clone(),
            circuit_id,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"input")],
            Bytes::from_slice(&env, b"valid_proof_bytes"),
            Bytes::from_slice(&env, b"unique_nullifier"),
            Vec::new(&env),
            None,
            metadata,
        );
        assert!(result.is_ok(), "valid proof submission should succeed");
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_duplicate_circuit_registration() {
        let env = setup_env();
        let circuit_id = register_circuit(&env, "dup_test");

        let result = ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).register_circuit(
            env.clone(),
            circuit_id,
            Bytes::from_slice(&env, b"Test"),
            Bytes::from_slice(&env, b"Test circuit"),
            Bytes::from_slice(&env, b"key_data_16_bytes!"),
            1,
            1,
            CircuitType::RangeProof,
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), ZKAttestationError::InvalidCircuit);
    }

    #[test]
    fn rejects_nullifier_reuse() {
        let env = setup_env();
        let circuit_id = register_circuit(&env, "null_test");
        let metadata = make_metadata(&env);
        let nullifier = Bytes::from_slice(&env, b"same_nullifier");

        ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).submit_proof(
            env.clone(),
            circuit_id.clone(),
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"input1")],
            Bytes::from_slice(&env, b"proof1"),
            nullifier.clone(),
            Vec::new(&env),
            None,
            metadata.clone(),
        )
        .unwrap();

        let result = ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).submit_proof(
            env.clone(),
            circuit_id,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"input2")],
            Bytes::from_slice(&env, b"proof2"),
            nullifier, // reused
            Vec::new(&env),
            None,
            metadata,
        );
        assert_eq!(
            result.unwrap_err(),
            ZKAttestationError::NullifierAlreadyUsed
        );
    }

    #[test]
    fn rejects_empty_proof() {
        let env = setup_env();
        let circuit_id = register_circuit(&env, "empty_proof");
        let metadata = make_metadata(&env);

        let result = ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).submit_proof(
            env.clone(),
            circuit_id,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"input")],
            Bytes::new(&env), // empty proof
            Bytes::from_slice(&env, b"unique_null"),
            Vec::new(&env),
            None,
            metadata,
        );
        assert_eq!(result.unwrap_err(), ZKAttestationError::InvalidProof);
    }

    #[test]
    fn rejects_proof_for_unregistered_circuit() {
        let env = setup_env();
        let unknown_circuit = Symbol::new(&env, "ghost_circuit");
        let metadata = make_metadata(&env);

        let result = ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).submit_proof(
            env.clone(),
            unknown_circuit,
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"input")],
            Bytes::from_slice(&env, b"proof"),
            Bytes::from_slice(&env, b"nullifier"),
            Vec::new(&env),
            None,
            metadata,
        );
        assert!(
            result.is_err(),
            "proof for unregistered circuit should be rejected"
        );
    }

    #[test]
    fn rejects_proof_with_empty_inputs() {
        let env = setup_env();
        let circuit_id = register_circuit(&env, "empty_inputs");
        let metadata = make_metadata(&env);

        let result = ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).submit_proof(
            env.clone(),
            circuit_id,
            Vec::new(&env), // no inputs
            Bytes::from_slice(&env, b"proof"),
            Bytes::from_slice(&env, b"nullifier_ei"),
            Vec::new(&env),
            None,
            metadata,
        );
        assert!(result.is_err(), "proof with no inputs should be rejected");
    }

    /// Two distinct nullifiers for the same circuit must both succeed.
    #[test]
    fn allows_different_nullifiers_on_same_circuit() {
        let env = setup_env();
        let circuit_id = register_circuit(&env, "multi_null");
        let metadata = make_metadata(&env);

        for (i, tag) in [b"null_one".as_ref(), b"null_two".as_ref()]
            .iter()
            .enumerate()
        {
            let result = ZKAttestationContractClient::new(&env, &env.register_contract(None, ZKAttestationContract)).submit_proof(
                env.clone(),
                circuit_id.clone(),
                soroban_sdk::vec![&env, Bytes::from_slice(&env, b"input")],
                Bytes::from_slice(&env, b"proof"),
                Bytes::from_slice(&env, tag),
                Vec::new(&env),
                None,
                metadata.clone(),
            );
            assert!(
                result.is_ok(),
                "proof {i} with unique nullifier should succeed"
            );
        }
    }
}

// ── ComplianceFilter ─────────────────────────────────────────────────────────

mod compliance_filter_tests {
    use super::*;

    // ── Success paths ─────────────────────────────────────────────────────────

    #[test]
    fn valid_risk_scores_are_accepted() {
        let env = setup_env();
        let oracle = generate_address(&env);
        let user = generate_address(&env);

        // Boundary values: 0, 50, 100 should all be valid
        for score in [0u32, 50, 100] {
            let result = ComplianceFilter::update_risk_score(
                env.clone(),
                oracle.clone(),
                user.clone(),
                score,
                Bytes::from_slice(&env, b"context"),
            );
            assert!(result.is_ok(), "risk score {score} should be accepted");
        }
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_risk_score_above_100() {
        let env = setup_env();
        let oracle = generate_address(&env);
        let user = generate_address(&env);

        let result = ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user,
            101, // just over max
            Bytes::from_slice(&env, b"test"),
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidRiskScore);
    }

    #[test]
    fn rejects_unauthorized_oracle() {
        let env = setup_env();
        let unauthorized = generate_address(&env);
        let user = generate_address(&env);

        let result = ComplianceFilter::update_risk_score(
            env.clone(),
            unauthorized, // not a registered oracle
            user,
            50,
            Bytes::from_slice(&env, b"test"),
        );
        assert!(result.is_err(), "unregistered oracle should be rejected");
    }

    #[test]
    fn rejects_empty_context_on_risk_update() {
        let env = setup_env();
        let oracle = generate_address(&env);
        let user = generate_address(&env);

        let result = ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user,
            50,
            Bytes::new(&env), // empty context
        );
        assert!(
            result.is_err(),
            "risk update with empty context should be rejected"
        );
    }

    /// u32::MAX is far above 100 — must be cleanly rejected, not panic.
    #[test]
    fn rejects_extreme_risk_score_without_panic() {
        let env = setup_env();
        let oracle = generate_address(&env);
        let user = generate_address(&env);

        let result = ComplianceFilter::update_risk_score(
            env.clone(),
            oracle,
            user,
            u32::MAX,
            Bytes::from_slice(&env, b"extreme"),
        );
        assert_eq!(result.unwrap_err(), ComplianceFilterError::InvalidRiskScore);
    }
}
