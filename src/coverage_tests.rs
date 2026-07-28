//! Additional unit tests for uncovered contract paths (Issue #77).
//!
//! Targets:
//!   - DID Registry: format validation, auth guards, authentication method management
//!   - Credential Issuer: revocation edge cases, expiry, credential retrieval
//!   - Reputation Score: history pagination, percentile, threshold, trust attestation
//!   - ZK Attestation: nullifier reuse, circuit deactivation, expiry
//!   - Compliance Filter: sanctions removal, risk assessment helpers

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{
    compliance_filter::{ComplianceFilter, ComplianceFilterError},
    credential_issuer::{CredentialIssuer, CredentialIssuerError},
    did_registry::{DIDRegistry, DIDRegistryError},
    reputation_score::{Config, ReputationScore, ReputationScoreError},
    zk_attestation::{CircuitType, ZKAttestation, ZKAttestationError},
    Service, VerificationMethod,
};

// ── helpers ────────────────────────────────────────────────────────────────

fn setup() -> Env {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set(LedgerInfo {
        timestamp: 1_700_000_000,
        protocol_version: 22,
        sequence_number: 1000,
        network_id: [0u8; 32],
        base_reserve: 10,
        min_temp_entry_ttl: 50_000,
        min_persistent_entry_ttl: 50_000,
        max_entry_ttl: 50_000,
    });
    env
}

fn vm(env: &Env, id: &[u8], key: &[u8; 32]) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, id),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
        controller: Address::generate(env),
        public_key: BytesN::from_array(env, key),
    }
}

fn svc(env: &Env) -> Vec<Service> {
    vec![
        env,
        Service {
            id: Bytes::from_slice(env, b"#hub"),
            type_: Bytes::from_slice(env, b"IdentityHub"),
            endpoint: Bytes::from_slice(env, b"https://hub.example.com"),
        },
    ]
}

fn did_bytes(env: &Env, suffix: &[u8]) -> Bytes {
    let mut d = Bytes::from_slice(env, b"did:stellar:");
    d.append(&Bytes::from_slice(env, suffix));
    d
}

fn rep_config() -> Config {
    Config {
        max_score: 1000,
        transaction_success_weight: 10,
        transaction_failure_weight: 5,
        credential_valid_weight: 20,
        credential_invalid_weight: 15,
    }
}

fn issue(env: &Env, issuer: &Address, subject: &Address) -> Bytes {
    CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        subject.clone(),
        vec![env, Bytes::from_slice(env, b"TestCred")],
        Bytes::from_slice(env, b"data"),
        None,
        Bytes::from_slice(env, b"proof"),
    )
    .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// DID Registry – uncovered paths
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn did_create_invalid_prefix_rejected() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let bad_did = Bytes::from_slice(&env, b"stellar:nope");
    let result = DIDRegistry::create_did(
        env.clone(),
        ctrl,
        bad_did,
        Vec::new(&env),
        Vec::new(&env),
    );
    assert_eq!(result.unwrap_err(), DIDRegistryError::InvalidFormat);
}

#[test]
fn did_create_duplicate_rejected() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let d = did_bytes(&env, b"GDUP0001");
    let v = vm(&env, b"#k1", &[1u8; 32]);
    DIDRegistry::create_did(env.clone(), ctrl.clone(), d.clone(), vec![&env, v.clone()], svc(&env)).unwrap();
    let result = DIDRegistry::create_did(env.clone(), ctrl, d, vec![&env, v], svc(&env));
    assert_eq!(result.unwrap_err(), DIDRegistryError::AlreadyExists);
}

#[test]
fn did_exists_returns_correct_bool() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let d = did_bytes(&env, b"GEXISTS1");
    assert!(!DIDRegistry::did_exists(env.clone(), d.clone()));
    DIDRegistry::create_did(env.clone(), ctrl, d.clone(), Vec::new(&env), Vec::new(&env)).unwrap();
    assert!(DIDRegistry::did_exists(env.clone(), d));
}

#[test]
fn did_get_controller_did() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let d = did_bytes(&env, b"GCTRL001");
    DIDRegistry::create_did(env.clone(), ctrl.clone(), d.clone(), Vec::new(&env), Vec::new(&env)).unwrap();
    let stored = DIDRegistry::get_controller_did(env.clone(), ctrl).unwrap();
    assert_eq!(stored, d);
}

#[test]
fn did_add_remove_authentication() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let d = did_bytes(&env, b"GAUTH001");
    DIDRegistry::create_did(env.clone(), ctrl.clone(), d.clone(), Vec::new(&env), Vec::new(&env)).unwrap();

    let method = Bytes::from_slice(&env, b"#key-auth");
    DIDRegistry::add_authentication(env.clone(), ctrl.clone(), method.clone()).unwrap();
    let doc = DIDRegistry::resolve_did(env.clone(), d.clone()).unwrap();
    assert_eq!(doc.authentication.len(), 1);

    DIDRegistry::remove_authentication(env.clone(), ctrl.clone(), method.clone()).unwrap();
    let doc2 = DIDRegistry::resolve_did(env.clone(), d).unwrap();
    assert_eq!(doc2.authentication.len(), 0);
}

#[test]
fn did_remove_nonexistent_authentication_fails() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let d = did_bytes(&env, b"GAUTH002");
    DIDRegistry::create_did(env.clone(), ctrl.clone(), d, Vec::new(&env), Vec::new(&env)).unwrap();
    let result = DIDRegistry::remove_authentication(
        env.clone(),
        ctrl,
        Bytes::from_slice(&env, b"#missing"),
    );
    assert_eq!(result.unwrap_err(), DIDRegistryError::NotFound);
}

#[test]
fn did_add_authentication_on_deactivated_fails() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let d = did_bytes(&env, b"GAUTH003");
    DIDRegistry::create_did(env.clone(), ctrl.clone(), d, Vec::new(&env), Vec::new(&env)).unwrap();
    DIDRegistry::deactivate_did(env.clone(), ctrl.clone()).unwrap();
    let result = DIDRegistry::add_authentication(env.clone(), ctrl, Bytes::from_slice(&env, b"#k"));
    assert_eq!(result.unwrap_err(), DIDRegistryError::Deactivated);
}

#[test]
fn did_update_nonexistent_fails() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let result = DIDRegistry::update_did(env.clone(), ctrl, None, None);
    assert_eq!(result.unwrap_err(), DIDRegistryError::NotFound);
}

// ═══════════════════════════════════════════════════════════════════════════
// Credential Issuer – uncovered paths
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn credential_verify_not_found() {
    let env = setup();
    let fake = Bytes::from_slice(&env, b"no-such-cred");
    let result = CredentialIssuer::verify_credential(env.clone(), fake);
    assert_eq!(result.unwrap_err(), CredentialIssuerError::NotFound);
}

#[test]
fn credential_revoke_twice_fails() {
    let env = setup();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    let cid = issue(&env, &issuer, &subject);
    CredentialIssuer::revoke_credential(env.clone(), issuer.clone(), cid.clone(), None).unwrap();
    let result = CredentialIssuer::revoke_credential(env.clone(), issuer, cid, None);
    assert_eq!(result.unwrap_err(), CredentialIssuerError::AlreadyRevoked);
}

#[test]
fn credential_revoke_wrong_issuer_fails() {
    let env = setup();
    let issuer = Address::generate(&env);
    let other = Address::generate(&env);
    let subject = Address::generate(&env);
    let cid = issue(&env, &issuer, &subject);
    let result = CredentialIssuer::revoke_credential(env.clone(), other, cid, None);
    assert_eq!(result.unwrap_err(), CredentialIssuerError::Unauthorized);
}

#[test]
fn credential_revoke_nonexistent_fails() {
    let env = setup();
    let issuer = Address::generate(&env);
    let result = CredentialIssuer::revoke_credential(
        env.clone(),
        issuer,
        Bytes::from_slice(&env, b"ghost"),
        None,
    );
    assert_eq!(result.unwrap_err(), CredentialIssuerError::NotFound);
}

#[test]
fn credential_verify_revoked_returns_false() {
    let env = setup();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    let cid = issue(&env, &issuer, &subject);
    CredentialIssuer::revoke_credential(env.clone(), issuer, cid.clone(), None).unwrap();
    let valid = CredentialIssuer::verify_credential(env.clone(), cid).unwrap();
    assert!(!valid);
}

#[test]
fn credential_verify_expired_returns_false() {
    let env = setup();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    // Expire in the past (timestamp before ledger time)
    let cid = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        vec![&env, Bytes::from_slice(&env, b"ExpCred")],
        Bytes::from_slice(&env, b"data"),
        Some(1_000_000_000u64), // far in the past
        Bytes::from_slice(&env, b"proof"),
    )
    .unwrap();
    let valid = CredentialIssuer::verify_credential(env.clone(), cid).unwrap();
    assert!(!valid);
}

#[test]
fn credential_get_not_found() {
    let env = setup();
    let result = CredentialIssuer::get_credential(env.clone(), Bytes::from_slice(&env, b"nope"));
    assert_eq!(result.unwrap_err(), CredentialIssuerError::NotFound);
}

#[test]
fn credential_empty_type_rejected() {
    let env = setup();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    let result = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        Vec::new(&env),
        Bytes::from_slice(&env, b"data"),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert_eq!(result.unwrap_err(), CredentialIssuerError::InvalidCredential);
}

#[test]
fn credential_empty_data_rejected() {
    let env = setup();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    let result = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        vec![&env, Bytes::from_slice(&env, b"Type")],
        Bytes::new(&env),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert_eq!(result.unwrap_err(), CredentialIssuerError::InvalidCredential);
}

#[test]
fn credential_subject_and_issuer_index_populated() {
    let env = setup();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    assert!(CredentialIssuer::get_issuer_credentials(env.clone(), issuer.clone()).is_empty());
    assert!(CredentialIssuer::get_subject_credentials(env.clone(), subject.clone()).is_empty());
    issue(&env, &issuer, &subject);
    assert_eq!(CredentialIssuer::get_issuer_credentials(env.clone(), issuer).len(), 1);
    assert_eq!(CredentialIssuer::get_subject_credentials(env.clone(), subject).len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Reputation Score – uncovered paths
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn reputation_initialize_contract_then_user() {
    let env = setup();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
    let score = ReputationScore::get_reputation_score(env.clone(), user);
    assert!(score > 0);
}

#[test]
fn reputation_initialize_contract_twice_fails() {
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin.clone(), rep_config()).unwrap();
    let result = ReputationScore::initialize(env.clone(), admin, rep_config());
    assert_eq!(result.unwrap_err(), ReputationScoreError::AlreadyInitialized);
}

#[test]
fn reputation_history_paginated() {
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    let user = Address::generate(&env);
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
    for _ in 0..5 {
        ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 100).unwrap();
    }
    let page = ReputationScore::get_reputation_history_paginated(env.clone(), user.clone(), 0, 3).unwrap();
    assert_eq!(page.data.len(), 3);
    assert!(page.has_more);
    assert_eq!(page.total, 5);
}

#[test]
fn reputation_history_zero_limit_fails() {
    let env = setup();
    let user = Address::generate(&env);
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
    let result = ReputationScore::get_reputation_history(env.clone(), user, 0);
    assert_eq!(result.unwrap_err(), ReputationScoreError::InvalidInput);
}

#[test]
fn reputation_failed_transaction_lowers_score() {
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    let user = Address::generate(&env);
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
    let before = ReputationScore::get_reputation_score(env.clone(), user.clone());
    ReputationScore::update_transaction_reputation(env.clone(), user.clone(), false, 0).unwrap();
    let after = ReputationScore::get_reputation_score(env.clone(), user);
    assert!(after < before);
}

#[test]
fn reputation_meets_threshold() {
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    let user = Address::generate(&env);
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
    // Base score is 800 (80 * SCORE_SCALE=10). Threshold of 50 → 500 scaled ≤ 800.
    let meets = ReputationScore::meets_reputation_threshold(env.clone(), user.clone(), 50).unwrap();
    assert!(meets);
    // Threshold of 1000 → 10000 scaled > 800.
    let above = ReputationScore::meets_reputation_threshold(env.clone(), user, 1000).unwrap();
    assert!(!above);
}

#[test]
fn reputation_percentile_single_user() {
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    let user = Address::generate(&env);
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
    let pct = ReputationScore::get_reputation_percentile(env.clone(), user).unwrap();
    assert_eq!(pct, 100);
}

#[test]
fn reputation_credential_update() {
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    let user = Address::generate(&env);
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
    let before = ReputationScore::get_reputation_score(env.clone(), user.clone());
    ReputationScore::update_credential_reputation(
        env.clone(),
        user.clone(),
        true,
        Bytes::from_slice(&env, b"KYC"),
    )
    .unwrap();
    let after = ReputationScore::get_reputation_score(env.clone(), user);
    assert!(after > before);
}

#[test]
fn reputation_score_increases_after_success() {
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    let user = Address::generate(&env);
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
    let before = ReputationScore::get_reputation_score(env.clone(), user.clone());
    ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 500).unwrap();
    let after = ReputationScore::get_reputation_score(env.clone(), user);
    assert!(after > before);
}

// ═══════════════════════════════════════════════════════════════════════════
// ZK Attestation – uncovered paths
// ═══════════════════════════════════════════════════════════════════════════

fn register_circuit(env: &Env, id: &str) {
    ZKAttestation::register_circuit(
        env.clone(),
        Symbol::new(env, id),
        Bytes::from_slice(env, b"Test Circuit"),
        Bytes::from_slice(env, b"desc"),
        Bytes::from_slice(env, b"verifier_key_32_bytes_here!!!!!"),
        2,
        3,
        CircuitType::RangeProof,
        vec![env, Symbol::new(env, "attr")],
    )
    .unwrap();
}

fn submit_proof(env: &Env, circuit_id: &str, nullifier: &[u8]) -> Bytes {
    ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(env, circuit_id),
        vec![
            env,
            Bytes::from_slice(env, b"input1"),
            Bytes::from_slice(env, b"input2"),
        ],
        Bytes::from_slice(env, b"proof_bytes"),
        Bytes::from_slice(env, nullifier),
        vec![env, Symbol::new(env, "attr")],
        None,
        Map::new(env),
    )
    .unwrap()
}

#[test]
fn zk_duplicate_circuit_rejected() {
    let env = setup();
    register_circuit(&env, "circ1");
    let result = ZKAttestation::register_circuit(
        env.clone(),
        Symbol::new(&env, "circ1"),
        Bytes::from_slice(&env, b"name"),
        Bytes::from_slice(&env, b"desc"),
        Bytes::from_slice(&env, b"key"),
        1,
        1,
        CircuitType::RangeProof,
        Vec::new(&env),
    );
    assert_eq!(result.unwrap_err(), ZKAttestationError::InvalidCircuit);
}

#[test]
fn zk_nullifier_reuse_rejected() {
    let env = setup();
    register_circuit(&env, "circ2");
    submit_proof(&env, "circ2", b"nullifier_unique_1");
    let result = ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "circ2"),
        vec![
            &env,
            Bytes::from_slice(&env, b"input1"),
            Bytes::from_slice(&env, b"input2"),
        ],
        Bytes::from_slice(&env, b"proof_bytes"),
        Bytes::from_slice(&env, b"nullifier_unique_1"),
        vec![&env, Symbol::new(&env, "attr")],
        None,
        Map::new(&env),
    );
    assert_eq!(result.unwrap_err(), ZKAttestationError::NullifierAlreadyUsed);
}

#[test]
fn zk_wrong_input_count_rejected() {
    let env = setup();
    register_circuit(&env, "circ3");
    // Circuit expects 2 public inputs; we send 1
    let result = ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "circ3"),
        vec![&env, Bytes::from_slice(&env, b"only_one")],
        Bytes::from_slice(&env, b"proof"),
        Bytes::from_slice(&env, b"null_a"),
        Vec::new(&env),
        None,
        Map::new(&env),
    );
    assert_eq!(result.unwrap_err(), ZKAttestationError::InvalidPublicInputs);
}

#[test]
fn zk_unknown_circuit_rejected() {
    let env = setup();
    let result = ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "ghost_circuit"),
        Vec::new(&env),
        Bytes::from_slice(&env, b"proof"),
        Bytes::from_slice(&env, b"null_b"),
        Vec::new(&env),
        None,
        Map::new(&env),
    );
    assert_eq!(result.unwrap_err(), ZKAttestationError::InvalidCircuit);
}

#[test]
fn zk_verify_unknown_proof_fails() {
    let env = setup();
    let result = ZKAttestation::verify_proof(env.clone(), Bytes::from_slice(&env, b"no_proof"));
    assert_eq!(result.unwrap_err(), ZKAttestationError::NotFound);
}

#[test]
fn zk_active_circuits_list() {
    let env = setup();
    register_circuit(&env, "circ4");
    register_circuit(&env, "circ5");
    let circuits = ZKAttestation::get_active_circuits(env.clone());
    assert!(circuits.len() >= 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// Compliance Filter – uncovered paths
// ═══════════════════════════════════════════════════════════════════════════

fn cf_init(env: &Env) -> Address {
    let admin = Address::generate(env);
    ComplianceFilter::initialize(env.clone(), admin.clone()).unwrap();
    admin
}

#[test]
fn compliance_clean_address_passes() {
    let env = setup();
    cf_init(&env);
    let clean = Address::generate(&env);
    let result = ComplianceFilter::screen_address(env.clone(), clean);
    assert!(result.is_ok());
}

#[test]
fn compliance_sanctioned_address_fails() {
    let env = setup();
    let admin = cf_init(&env);
    let target = Address::generate(&env);
    let source = Bytes::from_slice(&env, b"TEST_LIST");
    let hash = BytesN::from_array(&env, &[5u8; 32]);

    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0).unwrap();
    ComplianceFilter::add_to_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        target.clone(),
        Bytes::from_slice(&env, b"reason"),
        Bytes::from_slice(&env, b"US"),
    )
    .unwrap();

    assert!(ComplianceFilter::is_sanctioned(env.clone(), target.clone()));
    assert!(ComplianceFilter::screen_address(env.clone(), target).is_err());
}

#[test]
fn compliance_remove_from_sanctions_clears_flag() {
    let env = setup();
    let admin = cf_init(&env);
    let target = Address::generate(&env);
    let source = Bytes::from_slice(&env, b"RMLIST");
    let hash = BytesN::from_array(&env, &[6u8; 32]);

    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0).unwrap();
    ComplianceFilter::add_to_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        target.clone(),
        Bytes::from_slice(&env, b"fraud"),
        Bytes::from_slice(&env, b"EU"),
    )
    .unwrap();
    assert!(ComplianceFilter::is_sanctioned(env.clone(), target.clone()));

    ComplianceFilter::remove_from_sanctions_list(env.clone(), admin, source, target.clone()).unwrap();
    assert!(!ComplianceFilter::is_sanctioned(env.clone(), target));
}

#[test]
fn compliance_deactivated_list_persists() {
    let env = setup();
    let admin = cf_init(&env);
    let source = Bytes::from_slice(&env, b"DALIST");
    let hash = BytesN::from_array(&env, &[7u8; 32]);

    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0).unwrap();
    let before = ComplianceFilter::get_sanctions_list(env.clone(), source.clone()).unwrap();
    assert!(before.active);

    ComplianceFilter::deactivate_sanctions_list(env.clone(), admin, source.clone()).unwrap();
    let after = ComplianceFilter::get_sanctions_list(env.clone(), source).unwrap();
    assert!(!after.active);
}

#[test]
fn compliance_load_list_entries() {
    let env = setup();
    let admin = cf_init(&env);
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let source = Bytes::from_slice(&env, b"BULK_LIST");
    let hash = BytesN::from_array(&env, &[8u8; 32]);

    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0).unwrap();
    ComplianceFilter::load_list_entries(env.clone(), admin, source, vec![&env, a.clone(), b.clone()]).unwrap();

    assert!(ComplianceFilter::is_sanctioned(env.clone(), a));
    assert!(ComplianceFilter::is_sanctioned(env.clone(), b));
}
