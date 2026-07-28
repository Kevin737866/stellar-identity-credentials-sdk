#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{
    compliance_filter::ComplianceFilter,
    credential_issuer::CredentialIssuer,
    credential_schema::{CredentialSchema, FieldValidation},
    did_registry::{DIDRegistry, DIDRegistryError},
    reputation_score::{ReputationData, ReputationScore, ReputationScoreError, TrustAttestation},
    schema_registry::{CredentialSchemaRegistry, SchemaRegistryError},
    zk_attestation::{CircuitType, ZKAttestation, ZKAttestationError},
    DIDDocument, Service, VerifiableCredential, VerificationMethod,
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

fn make_vm(env: &Env, id: &str, key: &[u8; 32]) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, id.as_bytes()),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
        controller: Address::generate(env),
        public_key: BytesN::from_array(env, key),
    }
}

use core::sync::atomic::{AtomicU32, Ordering};
static DID_COUNTER: AtomicU32 = AtomicU32::new(0);

fn make_did_bytes(env: &Env, _addr: &Address) -> Bytes {
    let n = DID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut did = Bytes::from_slice(env, b"did:stellar:GABC");
    did.append(&Bytes::from_slice(env, n.to_string().as_bytes()));
    did
}

fn make_claims(env: &Env) -> Map<Bytes, Bytes> {
    let mut claims = Map::new(env);
    claims.set(
        Bytes::from_slice(env, b"name"),
        Bytes::from_slice(env, b"Alice"),
    );
    claims.set(
        Bytes::from_slice(env, b"dob"),
        Bytes::from_slice(env, b"1990-01-01"),
    );
    claims
}

fn new_address(env: &Env) -> Address {
    Address::generate(env)
}

fn make_vm_vec(_env: &Env, vms: Vec<VerificationMethod>) -> Vec<VerificationMethod> {
    vms
}

fn make_services(env: &Env) -> Vec<Service> {
    soroban_sdk::vec![
        env,
        Service {
            id: Bytes::from_slice(env, b"#hub"),
            type_: Bytes::from_slice(env, b"IdentityHub"),
            endpoint: Bytes::from_slice(env, b"https://hub.example.com"),
        },
    ]
}

// =========================================================================
// Test 1: Full KYC flow
// =========================================================================

#[test]
fn test_full_kyc_flow() {
    let env = setup_env();
    env.mock_all_auths();

    let key = &[1u8; 32];
    let controller = new_address(&env);
    let issuer = new_address(&env);
    let subject = new_address(&env);

    let did = make_did_bytes(&env, &controller);
    let vm = make_vm(&env, "#key-1", key);
    let services = make_services(&env);

    assert!(DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        did.clone(),
        make_vm_vec(&env, soroban_sdk::vec![&env, vm]),
        services,
    )
    .is_ok());

    let resolved = DIDRegistry::resolve_did(env.clone(), did.clone());
    assert!(resolved.is_ok());
    assert!(!resolved.unwrap().deactivated);

    // Register issuer first

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        subject.clone(),
        soroban_sdk::vec![&env, Bytes::from_slice(&env, b"KYCCredential")],
        make_claims(&env),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert!(cred_id.is_ok());
    let cred_id = cred_id.unwrap();

    let verification = CredentialIssuer::verify_credential(env.clone(), cred_id.clone());
    assert!(verification.is_ok());
    assert!(verification.unwrap());

    let revoked = CredentialIssuer::revoke_credential(
        env.clone(),
        issuer.clone(),
        cred_id.clone(),
        Some(Bytes::from_slice(&env, b"KYC expired")),
    );
    assert!(revoked.is_ok());

    let verification_after = CredentialIssuer::verify_credential(env.clone(), cred_id.clone());
    assert!(verification_after.is_ok());
    assert!(!verification_after.unwrap());

    let status = CredentialIssuer::get_credential_status(env.clone(), cred_id.clone());
    assert_eq!(status, Bytes::from_slice(&env, b"revoked"));

    let reason = CredentialIssuer::get_revocation_reason(env.clone(), cred_id.clone());
    assert!(reason.is_some());
}

// =========================================================================
// Test 2: Reputation evolution
// =========================================================================

#[test]
fn test_reputation_evolution() {
    let env = setup_env();
    let user = new_address(&env);

    let init = ReputationScore::initialize_reputation(env.clone(), user.clone());
    assert!(init.is_ok());
    let initial_score = init.unwrap().score;

    for _ in 0..5 {
        let _ =
            ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 1000);
    }

    let score_after_txns = ReputationScore::get_reputation_score(env.clone(), user.clone());
    assert!(score_after_txns > initial_score);

    let _ = ReputationScore::update_credential_reputation(
        env.clone(),
        user.clone(),
        true,
        Bytes::from_slice(&env, b"KYC"),
    );

    let data = ReputationScore::get_reputation_score(env.clone(), user.clone());
    assert!(data > 0);

    let history = ReputationScore::get_reputation_history(env.clone(), user.clone(), 10);
    assert!(history.is_ok());
    assert!(history.unwrap().len() >= 6);
}

// =========================================================================
// Test 3: Compliance enforcement
// =========================================================================

#[test]
fn test_compliance_enforcement() {
    let env = setup_env();
    let admin = new_address(&env);
    let sanctioned = new_address(&env);

    let source = Bytes::from_slice(&env, b"OFAC_SDN");
    let hash = BytesN::from_array(&env, &[2u8; 32]);

    let _ = ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash,
        1,
    );

    let entries = soroban_sdk::vec![&env, sanctioned.clone()];
    let _ = ComplianceFilter::load_list_entries(
        env.clone(),
        admin.clone(),
        source.clone(),
        entries,
        BytesN::from_array(&env, &[0u8; 32]),
    );

    let screening = ComplianceFilter::screen_address(env.clone(), sanctioned.clone());
    assert!(screening.is_err());

    let clean_user = new_address(&env);
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
    let admin = new_address(&env);
    let offender = new_address(&env);
    let source = Bytes::from_slice(&env, b"UN_LIST");
    let hash = BytesN::from_array(&env, &[3u8; 32]);

    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0)
        .unwrap();

    assert!(!ComplianceFilter::is_sanctioned(
        env.clone(),
        offender.clone()
    ));

    ComplianceFilter::add_to_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        offender.clone(),
        Bytes::from_slice(&env, b"terror financing"),
        Bytes::from_slice(&env, b"US"),
    )
    .unwrap();

    assert!(ComplianceFilter::is_sanctioned(
        env.clone(),
        offender.clone()
    ));
    let screening = ComplianceFilter::screen_address(env.clone(), offender.clone());
    assert!(screening.is_err());

    ComplianceFilter::remove_from_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        offender.clone(),
    )
    .unwrap();

    assert!(!ComplianceFilter::is_sanctioned(
        env.clone(),
        offender.clone()
    ));
}

// =========================================================================
// Test 4: ZK proof lifecycle
// =========================================================================

#[test]
fn test_zk_proof_lifecycle() {
    let env = setup_env();

    let circuit_id = Symbol::new(&env, "age_test");
    let name = Bytes::from_slice(&env, b"Age Range Proof");
    let description = Bytes::from_slice(&env, b"Prove age >= minimum without revealing exact age");
    let verifier_key = Bytes::from_slice(&env, b"test_verifier_key_32_bytes_long!");
    let public_input_count = 2;
    let private_input_count = 3;
    let circuit_type = CircuitType::RangeProof;
    let supported_attributes = soroban_sdk::vec![&env, Symbol::new(&env, "age_commitment")];

    let register_result = ZKAttestationContractClient::new(&env, &env.register(ZKAttestationContract, ())).register_circuit(
        env.clone(),
        circuit_id.clone(),
        name,
        description,
        verifier_key,
        public_input_count,
        private_input_count,
        circuit_type,
        supported_attributes,
    );
    assert!(register_result.is_ok());

    let public_inputs = soroban_sdk::vec![
        &env,
        Bytes::from_slice(&env, b"commitment_value_1"),
        Bytes::from_slice(&env, b"18"),
    ];
    let proof_bytes = Bytes::from_slice(&env, b"valid_zk_proof_data");
    let nullifier = Bytes::from_slice(&env, b"unique_nullifier_123");
    let revealed_attributes = soroban_sdk::vec![&env, Symbol::new(&env, "age_commitment")];
    let mut metadata = soroban_sdk::Map::new(&env);
    metadata.set(
        Symbol::new(&env, "context"),
        Bytes::from_slice(&env, b"age_verification"),
    );

    let proof_id = ZKAttestationContractClient::new(&env, &env.register(ZKAttestationContract, ())).submit_proof(
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
    let admin = new_address(&env);

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
    env.mock_all_auths();

    let key1 = &[1u8; 32];
    let key2 = &[2u8; 32];
    let key3 = &[3u8; 32];

    let user1 = new_address(&env);
    let user2 = new_address(&env);
    let user3 = new_address(&env);

    let did1 = make_did_bytes(&env, &user1);
    let did2 = make_did_bytes(&env, &user2);
    let did3 = make_did_bytes(&env, &user3);

    assert!(DIDRegistry::create_did(
        env.clone(),
        user1.clone(),
        did1.clone(),
        make_vm_vec(&env, soroban_sdk::vec![&env, make_vm(&env, "#key-1", key1)]),
        make_services(&env),
    )
    .is_ok());

    assert!(DIDRegistry::create_did(
        env.clone(),
        user2.clone(),
        did2.clone(),
        make_vm_vec(&env, soroban_sdk::vec![&env, make_vm(&env, "#key-1", key2)]),
        make_services(&env),
    )
    .is_ok());

    assert!(DIDRegistry::create_did(
        env.clone(),
        user3.clone(),
        did3.clone(),
        make_vm_vec(&env, soroban_sdk::vec![&env, make_vm(&env, "#key-1", key3)]),
        make_services(&env),
    )
    .is_ok());

    for user in [&user1, &user2, &user3] {
        let _ = ReputationScore::initialize_reputation(env.clone(), (*user).clone());
        let _ =
            ReputationScore::update_transaction_reputation(env.clone(), (*user).clone(), true, 500);
    }

    // Register issuer, then issue credential

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        user1.clone(),
        user2.clone(),
        soroban_sdk::vec![&env, Bytes::from_slice(&env, b"KYCCredential")],
        make_claims(&env),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert!(cred_id.is_ok());
    let cred_id = cred_id.unwrap();

    let user2_creds = CredentialIssuer::get_subject_credentials(env.clone(), user2.clone());
    assert_eq!(user2_creds.len(), 1);
    assert_eq!(user2_creds.get(0).unwrap(), cred_id);

    let user1_creds = CredentialIssuer::get_issuer_credentials(env.clone(), user1.clone());
    assert_eq!(user1_creds.len(), 1);

    let verification = CredentialIssuer::verify_credential(env.clone(), cred_id);
    assert!(verification.is_ok());
    assert!(verification.unwrap());

    let user3_score = ReputationScore::get_reputation_score(env.clone(), user3.clone());
    assert!(user3_score > 0);
}

// =========================================================================
// Test 7: Deterministic test
// =========================================================================

#[test]
fn test_deterministic_parallel_safe() {
    let env = setup_env();
    let alice = new_address(&env);
    let bob = new_address(&env);

    assert!(ReputationScore::initialize_reputation(env.clone(), alice.clone()).is_ok());
    assert!(ReputationScore::initialize_reputation(env.clone(), bob.clone()).is_ok());

    let alice_score = ReputationScore::get_reputation_score(env.clone(), alice.clone());
    let bob_score = ReputationScore::get_reputation_score(env.clone(), bob.clone());

    assert_eq!(alice_score, bob_score);

    for _ in 0..3 {
        let _ =
            ReputationScore::update_transaction_reputation(env.clone(), alice.clone(), true, 100);
    }

    let alice_after = ReputationScore::get_reputation_score(env.clone(), alice.clone());
    let bob_after = ReputationScore::get_reputation_score(env.clone(), bob.clone());

    assert!(alice_after > bob_after);
    assert_eq!(bob_after, bob_score);
}

// =========================================================================
// Test 8: Schema Registry lifecycle - register -> get -> update -> validate
// =========================================================================

#[test]
fn test_schema_registry_lifecycle() {
    let env = setup_env();
    let issuer = new_address(&env);
    let other_issuer = new_address(&env);

    let schema_id = Bytes::from_slice(&env, b"schema-kyc-v1");
    let definition_v1 =
        Bytes::from_slice(&env, b"{\"type\":\"KYC\",\"fields\":[\"name\",\"dob\"]}");
    let definition_v2 = Bytes::from_slice(
        &env,
        b"{\"type\":\"KYC\",\"fields\":[\"name\",\"dob\",\"address\"]}",
    );

    // Register schema
    assert!(CredentialSchemaRegistry::register_schema(
        env.clone(),
        issuer.clone(),
        schema_id.clone(),
        definition_v1.clone(),
    )
    .is_ok());

    // Get latest schema
    let schema = CredentialSchemaRegistry::get_schema(env.clone(), schema_id.clone(), None);
    assert!(schema.is_ok());
    let schema = schema.unwrap();
    assert_eq!(schema.version, 1);
    assert_eq!(schema.definition, definition_v1);
    assert_eq!(schema.issuer, issuer);

    // Try duplicate registration
    let duplicate = CredentialSchemaRegistry::register_schema(
        env.clone(),
        issuer.clone(),
        schema_id.clone(),
        definition_v1.clone(),
    );
    assert!(duplicate.is_err());
    assert_eq!(duplicate.unwrap_err(), SchemaRegistryError::AlreadyExists);

    // Update schema
    assert!(CredentialSchemaRegistry::update_schema(
        env.clone(),
        issuer.clone(),
        schema_id.clone(),
        definition_v2.clone(),
    )
    .is_ok());

    // Get latest schema after update
    let schema_updated = CredentialSchemaRegistry::get_schema(env.clone(), schema_id.clone(), None);
    assert!(schema_updated.is_ok());
    let schema_updated = schema_updated.unwrap();
    assert_eq!(schema_updated.version, 2);
    assert_eq!(schema_updated.definition, definition_v2);

    // Get specific version
    let schema_v1 = CredentialSchemaRegistry::get_schema(env.clone(), schema_id.clone(), Some(1));
    assert!(schema_v1.is_ok());
    assert_eq!(schema_v1.unwrap().version, 1);

    // Unauthorized update
    let unauthorized = CredentialSchemaRegistry::update_schema(
        env.clone(),
        other_issuer.clone(),
        schema_id.clone(),
        definition_v2.clone(),
    );
    assert!(unauthorized.is_err());
    assert_eq!(unauthorized.unwrap_err(), SchemaRegistryError::Unauthorized);

    // Validate schema exists
    assert!(
        CredentialSchemaRegistry::validate_schema_exists(env.clone(), schema_id.clone()).unwrap()
    );

    // Validate non-existent schema
    let non_existent_id = Bytes::from_slice(&env, b"non-existent");
    let validate_non_existent =
        CredentialSchemaRegistry::validate_schema_exists(env.clone(), non_existent_id);
    assert!(validate_non_existent.is_err());
}

// =========================================================================
// Test 9: Verifiable Presentation lifecycle — create, verify, expire,
//         selective disclosure, request/response protocol
// =========================================================================

#[test]
fn test_verifiable_presentation_lifecycle() {
    let env = setup_env();
    let holder = new_address(&env);
    let verifier = new_address(&env);

    // Issue two credentials for the holder
    let issuer = new_address(&env);
    let proof = Bytes::from_slice(&env, b"valid_signature");

    let cred1_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        holder.clone(),
        make_credential_type(&env, "KYCVerification"),
        Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
        None,
        proof.clone(),
    )
    .unwrap();

    let cred2_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        holder.clone(),
        make_credential_type(&env, "AgeVerification"),
        Bytes::from_slice(&env, b"{\"age\":25}"),
        None,
        proof.clone(),
    )
    .unwrap();

    let credential_ids = vec![&env, cred1_id.clone(), cred2_id.clone()];
    let pres_type = vec![&env, Bytes::from_slice(&env, b"VerifiablePresentation")];

    // Create a verifiable presentation
    let pres_id = PresentationManager::create_presentation(
        env.clone(),
        holder.clone(),
        credential_ids,
        pres_type.clone(),
        Some(proof.clone()),
        None,
    );
    assert!(pres_id.is_ok());
    let pres_id = pres_id.unwrap();

    // Get the presentation
    let presentation = PresentationManager::get_presentation(env.clone(), pres_id.clone());
    assert!(presentation.is_ok());
    let presentation = presentation.unwrap();
    assert_eq!(presentation.holder, holder);
    assert_eq!(presentation.credentials.len(), 2);

    // Verify the presentation
    let is_valid = PresentationManager::verify_presentation(env.clone(), pres_id.clone());
    assert!(is_valid.is_ok());
    assert!(is_valid.unwrap());

    // Get holder's presentations
    let holder_presentations = PresentationManager::get_holder_presentations(env.clone(), holder.clone());
    assert_eq!(holder_presentations.len(), 1);

    // Expire the presentation
    assert!(PresentationManager::expire_presentation(
        env.clone(),
        holder.clone(),
        pres_id.clone(),
    )
    .is_ok());

    // Verify after expiration
    let is_valid_after = PresentationManager::verify_presentation(env.clone(), pres_id.clone());
    assert!(is_valid_after.is_ok());
    assert!(!is_valid_after.unwrap());

    // Create selective disclosure presentation
    let disclosure_entry = SelectiveDisclosureEntry {
        credential_id: cred1_id.clone(),
        zk_proof_ids: Vec::new(&env),
        revealed_attributes: vec![&env, Symbol::new(&env, "name")],
    };
    let disclosures = vec![&env, disclosure_entry];

    let sd_pres_id = PresentationManager::create_sd_presentation(
        env.clone(),
        holder.clone(),
        pres_type.clone(),
        disclosures,
        Some(proof.clone()),
        None,
    );
    assert!(sd_pres_id.is_ok());
    let sd_pres_id = sd_pres_id.unwrap();

    // Get selective disclosures
    let disclosures_retrieved = PresentationManager::get_selective_disclosures(env.clone(), sd_pres_id.clone());
    assert_eq!(disclosures_retrieved.len(), 1);
    assert_eq!(disclosures_retrieved.get(0).unwrap().credential_id, cred1_id);

    // Verify selective disclosure presentation
    let sd_valid = PresentationManager::verify_presentation(env.clone(), sd_pres_id.clone());
    assert!(sd_valid.is_ok());
    assert!(sd_valid.unwrap());
}

#[test]
fn test_presentation_request_response_protocol() {
    let env = setup_env();
    let holder = new_address(&env);
    let verifier = new_address(&env);

    // Issue a credential for the holder
    let issuer = new_address(&env);
    let proof = Bytes::from_slice(&env, b"valid_signature");

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        holder.clone(),
        make_credential_type(&env, "KYCVerification"),
        Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
        None,
        proof.clone(),
    )
    .unwrap();

    // Create a presentation request
    let query = vec![&env, Bytes::from_slice(&env, b"KYCVerification")];
    let challenge = Bytes::from_slice(&env, b"nonce-123");
    let domain = Some(Bytes::from_slice(&env, b"example.com"));

    let req_id = PresentationManager::create_presentation_request(
        env.clone(),
        verifier.clone(),
        query,
        challenge,
        domain,
        None,
    );
    assert!(req_id.is_ok());
    let req_id = req_id.unwrap();

    // Get the request
    let request = PresentationManager::get_presentation_request(env.clone(), req_id.clone());
    assert!(request.is_ok());
    let request = request.unwrap();
    assert_eq!(request.verifier, verifier);

    // Holder creates a presentation in response
    let credential_ids = vec![&env, cred_id.clone()];
    let pres_type = vec![&env, Bytes::from_slice(&env, b"VerifiablePresentation")];

    let pres_id = PresentationManager::create_presentation(
        env.clone(),
        holder.clone(),
        credential_ids,
        pres_type,
        Some(proof.clone()),
        None,
    )
    .unwrap();

    // Fulfill the request
    assert!(PresentationManager::fulfill_presentation_request(
        env.clone(),
        holder.clone(),
        req_id.clone(),
        pres_id.clone(),
    )
    .is_ok());

    // Check fulfillment
    let fulfillment = PresentationManager::get_fulfillment(env.clone(), req_id.clone());
    assert!(fulfillment.is_some());
    let fulfillment = fulfillment.unwrap();
    assert_eq!(fulfillment.request_id, req_id);
    assert_eq!(fulfillment.presentation_id, pres_id);
    assert_eq!(fulfillment.responder, holder);

    // Try duplicate fulfillment (should fail)
    let dup_fulfill = PresentationManager::fulfill_presentation_request(
        env.clone(),
        holder.clone(),
        req_id.clone(),
        pres_id.clone(),
    );
    assert!(dup_fulfill.is_err());
    assert_eq!(dup_fulfill.unwrap_err(), PresentationError::RequestAlreadyFulfilled);
}

#[test]
fn test_presentation_validation_errors() {
    let env = setup_env();
    let holder = new_address(&env);
    let other = new_address(&env);

    // Empty credentials list
    let empty_creds = Vec::new(&env);
    let pres_type = vec![&env, Bytes::from_slice(&env, b"VerifiablePresentation")];
    let proof = Bytes::from_slice(&env, b"proof");

    let empty_result = PresentationManager::create_presentation(
        env.clone(),
        holder.clone(),
        empty_creds,
        pres_type.clone(),
        Some(proof.clone()),
        None,
    );
    assert!(empty_result.is_err());
    assert_eq!(empty_result.unwrap_err(), PresentationError::InvalidCredential);

    // Get non-existent presentation
    let non_existent_id = Bytes::from_slice(&env, b"non-existent-vp");
    let get_result = PresentationManager::get_presentation(env.clone(), non_existent_id);
    assert!(get_result.is_err());
    assert_eq!(get_result.unwrap_err(), PresentationError::NotFound);

    // Expire presentation not owned by caller
    let credential_ids = vec![&env, Bytes::from_slice(&env, b"dummy-cred")];
    let pres_id = PresentationManager::create_presentation(
        env.clone(),
        holder.clone(),
        credential_ids,
        pres_type.clone(),
        Some(proof.clone()),
        None,
    )
    .unwrap();

    let expire_result = PresentationManager::expire_presentation(
        env.clone(),
        other.clone(),
        pres_id.clone(),
    );
    assert!(expire_result.is_err());
    assert_eq!(expire_result.unwrap_err(), PresentationError::Unauthorized);

    // Empty query in request
    let empty_query = Vec::new(&env);
    let req_result = PresentationManager::create_presentation_request(
        env.clone(),
        holder.clone(),
        empty_query,
        Bytes::from_slice(&env, b"challenge"),
        None,
        None,
    );
    assert!(req_result.is_err());
    assert_eq!(req_result.unwrap_err(), PresentationError::InvalidFormat);
}
