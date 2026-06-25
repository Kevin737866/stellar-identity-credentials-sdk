#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{
    compliance_filter::ComplianceFilter,
    credential_issuer::CredentialIssuer,
    credential_schema::{CredentialSchema, FieldValidation},
    did_registry::DIDRegistry,
    reputation_score::{Config, ReputationScore},
    schema_registry::{CredentialSchemaRegistry, SchemaRegistryError},
    zk_attestation::{CircuitType, ZKAttestationContract, ZKAttestationError},
    Service, VerificationMethod,
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

fn default_config() -> Config {
    Config {
        max_score: 10000,
        transaction_success_weight: 10,
        transaction_failure_weight: 5,
        credential_valid_weight: 20,
        credential_invalid_weight: 15,
    }
}

fn make_vm(env: &Env, id: &str, key: &[u8; 32]) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, id.as_bytes()),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
        controller: Address::generate(env),
        public_key: BytesN::from_array(env, key),
    }
}

fn make_services(env: &Env) -> Vec<Service> {
    vec![
        env,
        Service {
            id: Bytes::from_slice(env, b"#hub"),
            type_: Bytes::from_slice(env, b"IdentityHub"),
            endpoint: Bytes::from_slice(env, b"https://hub.example.com"),
        },
    ]
}

use core::sync::atomic::{AtomicU32, Ordering};
static DID_COUNTER: AtomicU32 = AtomicU32::new(0);

fn make_did_bytes(env: &Env) -> Bytes {
    let n = DID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut did = Bytes::from_slice(env, b"did:stellar:GABC");
    did.append(&Bytes::from_slice(env, n.to_string().as_bytes()));
    did
}

// =========================================================================
// Test 1: Full KYC flow
// =========================================================================

#[test]
fn test_full_kyc_flow() {
    let env = setup_env();

    let controller = Address::generate(&env);
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);

    assert!(DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        did.clone(),
        vec![&env, vm],
        make_services(&env),
    )
    .is_ok());

    let resolved = DIDRegistry::resolve_did(env.clone(), did.clone());
    assert!(resolved.is_ok());
    assert!(!resolved.unwrap().deactivated);

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        subject.clone(),
        vec![&env, Bytes::from_slice(&env, b"KYCCredential")],
        Bytes::from_slice(&env, b"{\"name\":\"Alice\",\"dob\":\"1990-01-01\"}"),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert!(cred_id.is_ok());
    let cred_id = cred_id.unwrap();

    let valid = CredentialIssuer::verify_credential(env.clone(), cred_id.clone());
    assert!(valid.is_ok());
    assert!(valid.unwrap());

    let revoked = CredentialIssuer::revoke_credential(
        env.clone(),
        issuer.clone(),
        cred_id.clone(),
        Some(Bytes::from_slice(&env, b"KYC expired")),
    );
    assert!(revoked.is_ok());

    let valid_after = CredentialIssuer::verify_credential(env.clone(), cred_id.clone());
    assert!(valid_after.is_ok());
    assert!(!valid_after.unwrap());
}

// =========================================================================
// Test 2: Reputation evolution
// =========================================================================

#[test]
fn test_reputation_evolution() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    ReputationScore::initialize(env.clone(), admin, default_config()).unwrap();
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

    let initial_score = ReputationScore::get_reputation_score(env.clone(), user.clone());

    for _ in 0..5 {
        ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 1000)
            .unwrap();
    }

    let score_after = ReputationScore::get_reputation_score(env.clone(), user.clone());
    assert!(score_after > initial_score);

    ReputationScore::update_credential_reputation(
        env.clone(),
        user.clone(),
        true,
        Bytes::from_slice(&env, b"KYC"),
    )
    .unwrap();

    let history = ReputationScore::get_reputation_history(env.clone(), user.clone(), 10);
    assert!(history.is_ok());
    assert!(history.unwrap().len() >= 5);
}

// =========================================================================
// Test 3: Compliance enforcement
// =========================================================================

#[test]
fn test_compliance_enforcement() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let sanctioned = Address::generate(&env);

    let source = Bytes::from_slice(&env, b"OFAC_SDN");
    let hash = BytesN::from_array(&env, &[2u8; 32]);

    ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash,
        1,
    )
    .unwrap();

    let entries = vec![&env, sanctioned.clone()];
    ComplianceFilter::load_list_entries(env.clone(), admin.clone(), source.clone(), entries)
        .unwrap();

    let screening = ComplianceFilter::screen_address(env.clone(), sanctioned.clone());
    assert!(screening.is_err());

    let clean_user = Address::generate(&env);
    let clean_result = ComplianceFilter::screen_address(env.clone(), clean_user.clone());
    assert!(clean_result.is_ok());
    assert_eq!(
        clean_result.unwrap().status,
        Bytes::from_slice(&env, b"clear")
    );
}

#[test]
fn test_sanctions_list_admin_management() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let offender = Address::generate(&env);
    let source = Bytes::from_slice(&env, b"UN_LIST");
    let hash = BytesN::from_array(&env, &[3u8; 32]);

    ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash,
        0,
    )
    .unwrap();

    assert!(!ComplianceFilter::is_sanctioned(env.clone(), offender.clone()));

    ComplianceFilter::add_to_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        offender.clone(),
        Bytes::from_slice(&env, b"terror financing"),
        Bytes::from_slice(&env, b"US"),
    )
    .unwrap();

    assert!(ComplianceFilter::is_sanctioned(env.clone(), offender.clone()));

    ComplianceFilter::remove_from_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        offender.clone(),
    )
    .unwrap();

    assert!(!ComplianceFilter::is_sanctioned(env.clone(), offender.clone()));
}

// =========================================================================
// Test 4: ZK proof lifecycle
// =========================================================================

#[test]
fn test_zk_proof_lifecycle() {
    let env = setup_env();

    let circuit_id = Symbol::new(&env, "age_test");
    ZKAttestationContract::register_circuit(
        env.clone(),
        circuit_id.clone(),
        Bytes::from_slice(&env, b"Age Range Proof"),
        Bytes::from_slice(&env, b"Prove age >= minimum"),
        Bytes::from_slice(&env, b"test_verifier_key_32_bytes_long!"),
        2,
        3,
        CircuitType::RangeProof,
        vec![&env, Symbol::new(&env, "age_commitment")],
    )
    .unwrap();

    let public_inputs = vec![
        &env,
        Bytes::from_slice(&env, b"commitment_value_1"),
        Bytes::from_slice(&env, b"18"),
    ];
    let proof_bytes = Bytes::from_slice(&env, b"valid_zk_proof_data");
    let nullifier = Bytes::from_slice(&env, b"unique_nullifier_123");
    let revealed_attributes = vec![&env, Symbol::new(&env, "age_commitment")];
    let mut metadata = Map::new(&env);
    metadata.set(
        Symbol::new(&env, "context"),
        Bytes::from_slice(&env, b"age_verification"),
    );

    let proof_id = ZKAttestationContract::submit_proof(
        env.clone(),
        circuit_id.clone(),
        public_inputs,
        proof_bytes,
        nullifier,
        revealed_attributes,
        None,
        metadata,
    );
    assert!(proof_id.is_ok());
    let proof_id = proof_id.unwrap();

    let verify_result = ZKAttestationContract::verify_proof(env.clone(), proof_id.clone());
    assert!(verify_result.is_ok());
    assert!(verify_result.unwrap());

    let retrieved = ZKAttestationContract::get_proof(env.clone(), proof_id.clone());
    assert!(retrieved.is_ok());

    let circuits = ZKAttestationContract::get_active_circuits(env.clone());
    assert!(circuits.len() >= 1);
}

// =========================================================================
// Test 5: Admin operations
// =========================================================================

#[test]
fn test_admin_operations() {
    let env = setup_env();
    let admin = Address::generate(&env);

    let source = Bytes::from_slice(&env, b"UN_LIST");
    let hash = BytesN::from_array(&env, &[3u8; 32]);

    let result = ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash.clone(),
        5,
    );
    assert!(result.is_ok());

    let list = ComplianceFilter::get_sanctions_list(env.clone(), source.clone());
    assert!(list.is_some());
    assert!(list.unwrap().active);

    let deactivate =
        ComplianceFilter::deactivate_sanctions_list(env.clone(), admin.clone(), source.clone());
    assert!(deactivate.is_ok());

    let list_after = ComplianceFilter::get_sanctions_list(env.clone(), source.clone());
    assert!(list_after.is_some());
    assert!(!list_after.unwrap().active);
}

// =========================================================================
// Test 6: Multi-user scenario
// =========================================================================

#[test]
fn test_multi_user_scenario() {
    let env = setup_env();

    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    let user3 = Address::generate(&env);
    let admin = Address::generate(&env);

    let did1 = make_did_bytes(&env);
    let did2 = make_did_bytes(&env);
    let did3 = make_did_bytes(&env);

    assert!(DIDRegistry::create_did(
        env.clone(),
        user1.clone(),
        did1.clone(),
        vec![&env, make_vm(&env, "#key-1", &[1u8; 32])],
        make_services(&env),
    )
    .is_ok());

    assert!(DIDRegistry::create_did(
        env.clone(),
        user2.clone(),
        did2.clone(),
        vec![&env, make_vm(&env, "#key-1", &[2u8; 32])],
        make_services(&env),
    )
    .is_ok());

    assert!(DIDRegistry::create_did(
        env.clone(),
        user3.clone(),
        did3.clone(),
        vec![&env, make_vm(&env, "#key-1", &[3u8; 32])],
        make_services(&env),
    )
    .is_ok());

    ReputationScore::initialize(env.clone(), admin, default_config()).unwrap();
    for user in [&user1, &user2, &user3] {
        ReputationScore::initialize_reputation(env.clone(), (*user).clone()).unwrap();
        ReputationScore::update_transaction_reputation(env.clone(), (*user).clone(), true, 500)
            .unwrap();
    }

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        user1.clone(),
        user2.clone(),
        vec![&env, Bytes::from_slice(&env, b"KYCCredential")],
        Bytes::from_slice(&env, b"{\"name\":\"Bob\"}"),
        None,
        Bytes::from_slice(&env, b"proof"),
    )
    .unwrap();

    let user2_creds = CredentialIssuer::get_subject_credentials(env.clone(), user2.clone());
    assert_eq!(user2_creds.len(), 1);
    assert_eq!(user2_creds.get(0).unwrap(), cred_id);

    let user1_creds = CredentialIssuer::get_issuer_credentials(env.clone(), user1.clone());
    assert_eq!(user1_creds.len(), 1);

    let valid = CredentialIssuer::verify_credential(env.clone(), cred_id);
    assert!(valid.is_ok());
    assert!(valid.unwrap());
}

// =========================================================================
// Test 7: Deterministic parallel-safe test
// =========================================================================

#[test]
fn test_deterministic_parallel_safe() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    ReputationScore::initialize(env.clone(), admin, default_config()).unwrap();
    ReputationScore::initialize_reputation(env.clone(), alice.clone()).unwrap();
    ReputationScore::initialize_reputation(env.clone(), bob.clone()).unwrap();

    let alice_score = ReputationScore::get_reputation_score(env.clone(), alice.clone());
    let bob_score = ReputationScore::get_reputation_score(env.clone(), bob.clone());
    assert_eq!(alice_score, bob_score);

    for _ in 0..3 {
        ReputationScore::update_transaction_reputation(env.clone(), alice.clone(), true, 100)
            .unwrap();
    }

    let alice_after = ReputationScore::get_reputation_score(env.clone(), alice.clone());
    let bob_after = ReputationScore::get_reputation_score(env.clone(), bob.clone());

    assert!(alice_after > bob_after);
    assert_eq!(bob_after, bob_score);
}

// =========================================================================
// Test 8: Schema Registry lifecycle
// =========================================================================

#[test]
fn test_schema_registry_lifecycle() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let other_issuer = Address::generate(&env);

    let schema_id = Bytes::from_slice(&env, b"schema-kyc-v1");
    let definition_v1 = Bytes::from_slice(&env, b"{\"type\":\"KYC\",\"fields\":[\"name\",\"dob\"]}");
    let definition_v2 = Bytes::from_slice(
        &env,
        b"{\"type\":\"KYC\",\"fields\":[\"name\",\"dob\",\"address\"]}",
    );

    assert!(CredentialSchemaRegistry::register_schema(
        env.clone(),
        issuer.clone(),
        schema_id.clone(),
        definition_v1.clone(),
    )
    .is_ok());

    let schema = CredentialSchemaRegistry::get_schema(env.clone(), schema_id.clone(), None);
    assert!(schema.is_ok());
    let schema = schema.unwrap();
    assert_eq!(schema.version, 1);
    assert_eq!(schema.definition, definition_v1);

    let duplicate = CredentialSchemaRegistry::register_schema(
        env.clone(),
        issuer.clone(),
        schema_id.clone(),
        definition_v1.clone(),
    );
    assert_eq!(duplicate.unwrap_err(), SchemaRegistryError::AlreadyExists);

    assert!(CredentialSchemaRegistry::update_schema(
        env.clone(),
        issuer.clone(),
        schema_id.clone(),
        definition_v2.clone(),
    )
    .is_ok());

    let schema_updated =
        CredentialSchemaRegistry::get_schema(env.clone(), schema_id.clone(), None).unwrap();
    assert_eq!(schema_updated.version, 2);

    let schema_v1 =
        CredentialSchemaRegistry::get_schema(env.clone(), schema_id.clone(), Some(1)).unwrap();
    assert_eq!(schema_v1.version, 1);

    let unauthorized = CredentialSchemaRegistry::update_schema(
        env.clone(),
        other_issuer.clone(),
        schema_id.clone(),
        definition_v2.clone(),
    );
    assert_eq!(
        unauthorized.unwrap_err(),
        SchemaRegistryError::Unauthorized
    );

    assert!(
        CredentialSchemaRegistry::validate_schema_exists(env.clone(), schema_id.clone()).unwrap()
    );
}
