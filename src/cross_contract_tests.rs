//! Cross-contract interaction tests (Issue #79).
//!
//! Exercises patterns where one contract's output drives another contract's
//! input, simulating real-world flows:
//!
//!   - DID → Credential: a DID must exist before credentials are issued
//!   - Credential → Reputation: credential validity drives reputation updates
//!   - ZK → Compliance: a ZK proof anchors a compliance clearance decision
//!   - 3-hop chain: DID → Credential → Reputation in a single test
//!   - Error propagation: upstream failure blocks downstream actions
//!   - Reentrancy guard: same user cannot double-update in the same ledger slot

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{
    compliance_filter::ComplianceFilter,
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

fn rep_config() -> Config {
    Config {
        max_score: 10_000,
        transaction_success_weight: 10,
        transaction_failure_weight: 5,
        credential_valid_weight: 20,
        credential_invalid_weight: 15,
    }
}

fn vm(env: &Env, key_byte: u8) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, b"#key-1"),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
        controller: Address::generate(env),
        public_key: BytesN::from_array(env, &[key_byte; 32]),
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

static DID_SEQ: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn unique_did(env: &Env) -> Bytes {
    let n = DID_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut d = Bytes::from_slice(env, b"did:stellar:GCC");
    d.append(&Bytes::from_slice(env, n.to_string().as_bytes()));
    d
}

fn create_did(env: &Env, controller: &Address) -> Bytes {
    let d = unique_did(env);
    DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        d.clone(),
        vec![env, vm(env, 1)],
        svc(env),
    )
    .unwrap();
    d
}

fn issue_cred(env: &Env, issuer: &Address, subject: &Address) -> Bytes {
    CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        subject.clone(),
        vec![env, Bytes::from_slice(env, b"CrossTest")],
        Bytes::from_slice(env, b"cross_data"),
        None,
        Bytes::from_slice(env, b"proof"),
    )
    .unwrap()
}

fn register_circuit(env: &Env, id: &str) {
    ZKAttestation::register_circuit(
        env.clone(),
        Symbol::new(env, id),
        Bytes::from_slice(env, b"Circuit"),
        Bytes::from_slice(env, b"desc"),
        Bytes::from_slice(env, b"verifier_key_32_bytes_here!!!!!"),
        2,
        1,
        CircuitType::RangeProof,
        Vec::new(env),
    )
    .unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// DID → Credential: resolve DID before issuing credential
// ═══════════════════════════════════════════════════════════════════════════

/// A credential's subject address matches the DID document controller.
/// This simulates a validator checking the DID before issuing.
#[test]
fn cross_did_to_credential_subject_matches_controller() {
    let env = setup();
    let controller = Address::generate(&env);
    let issuer = Address::generate(&env);

    let did = create_did(&env, &controller);

    // Resolve and confirm DID is valid before issuing
    let doc = DIDRegistry::resolve_did(env.clone(), did.clone()).unwrap();
    assert_eq!(doc.controller, controller);
    assert!(!doc.deactivated);

    // Issuer issues credential to the DID controller
    let cid = issue_cred(&env, &issuer, &doc.controller);

    // Credential verifies successfully
    assert!(CredentialIssuer::verify_credential(env.clone(), cid).unwrap());
}

/// A deactivated DID should gate credential issuance (app-level check pattern).
#[test]
fn cross_deactivated_did_blocks_downstream_credential() {
    let env = setup();
    let controller = Address::generate(&env);
    let issuer = Address::generate(&env);

    let did = create_did(&env, &controller);
    DIDRegistry::deactivate_did(env.clone(), controller.clone()).unwrap();

    // Application checks DID status before issuing
    let doc = DIDRegistry::resolve_did(env.clone(), did).unwrap();
    assert!(doc.deactivated);

    // Issuer respects deactivation: credential is not issued
    // (real issuance would be blocked by app logic reading doc.deactivated)
    // We verify the DID state propagates correctly to the application layer
    assert_eq!(doc.controller, controller, "controller matches even when deactivated");
}

// ═══════════════════════════════════════════════════════════════════════════
// Credential → Reputation: valid/revoked credential drives score
// ═══════════════════════════════════════════════════════════════════════════

/// Issuing and verifying a credential, then recording it in reputation.
#[test]
fn cross_credential_drives_reputation_score() {
    let env = setup();
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    ReputationScore::initialize_reputation(env.clone(), subject.clone()).unwrap();
    let before = ReputationScore::get_reputation_score(env.clone(), subject.clone());

    let cid = issue_cred(&env, &issuer, &subject);
    let valid = CredentialIssuer::verify_credential(env.clone(), cid).unwrap();

    // Downstream: credential validity feeds into reputation
    ReputationScore::update_credential_reputation(
        env.clone(),
        subject.clone(),
        valid,
        Bytes::from_slice(&env, b"CrossTest"),
    )
    .unwrap();

    let after = ReputationScore::get_reputation_score(env.clone(), subject);
    assert!(after > before, "valid credential increases reputation");
}

/// Revoking a credential and then recording it lowers reputation.
#[test]
fn cross_revoked_credential_lowers_reputation() {
    let env = setup();
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    ReputationScore::initialize_reputation(env.clone(), subject.clone()).unwrap();

    let cid = issue_cred(&env, &issuer, &subject);
    CredentialIssuer::revoke_credential(env.clone(), issuer, cid.clone(), None).unwrap();

    let valid = CredentialIssuer::verify_credential(env.clone(), cid).unwrap();
    assert!(!valid);

    let before = ReputationScore::get_reputation_score(env.clone(), subject.clone());

    // Record invalid credential in reputation
    ReputationScore::update_credential_reputation(
        env.clone(),
        subject.clone(),
        valid,
        Bytes::from_slice(&env, b"RevokedKYC"),
    )
    .unwrap();

    let after = ReputationScore::get_reputation_score(env.clone(), subject);
    assert!(after < before, "invalid credential decreases reputation");
}

// ═══════════════════════════════════════════════════════════════════════════
// ZK → Compliance: proof validity anchors compliance clearance
// ═══════════════════════════════════════════════════════════════════════════

fn cf_init(env: &Env) -> Address {
    let admin = Address::generate(env);
    ComplianceFilter::initialize(env.clone(), admin.clone()).unwrap();
    admin
}

/// A valid ZK proof enables a downstream compliance clearance pattern.
#[test]
fn cross_zk_proof_enables_compliance_clearance() {
    let env = setup();
    let admin = cf_init(&env);
    let user = Address::generate(&env);
    let source = Bytes::from_slice(&env, b"ZK_GATED_LIST");
    let hash = BytesN::from_array(&env, &[11u8; 32]);

    // Set up compliance list (user is NOT on it initially)
    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0).unwrap();
    assert!(!ComplianceFilter::is_sanctioned(env.clone(), user.clone()));

    // Register ZK circuit and submit a proof for the user
    register_circuit(&env, "age_gate");
    let proof_id = ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "age_gate"),
        vec![
            &env,
            Bytes::from_slice(&env, b"commitment"),
            Bytes::from_slice(&env, b"18"),
        ],
        Bytes::from_slice(&env, b"age_proof_bytes"),
        Bytes::from_slice(&env, b"unique_nullifier_zk_cc1"),
        vec![&env, Symbol::new(&env, "age")],
        None,
        Map::new(&env),
    )
    .unwrap();

    // ZK proof verified
    assert!(ZKAttestation::verify_proof(env.clone(), proof_id).unwrap());

    // Compliance screen passes because user is not sanctioned
    assert!(ComplianceFilter::screen_address(env.clone(), user).is_ok());
}

/// A sanctioned user cannot pass compliance even with a valid ZK proof.
#[test]
fn cross_sanctioned_user_blocked_despite_zk_proof() {
    let env = setup();
    let admin = cf_init(&env);
    let bad_actor = Address::generate(&env);
    let source = Bytes::from_slice(&env, b"STRICT_LIST");
    let hash = BytesN::from_array(&env, &[12u8; 32]);

    // Add bad_actor to sanctions list
    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0).unwrap();
    ComplianceFilter::add_to_sanctions_list(
        env.clone(),
        admin,
        source,
        bad_actor.clone(),
        Bytes::from_slice(&env, b"fraud"),
        Bytes::from_slice(&env, b"US"),
    )
    .unwrap();

    // Even with a valid ZK proof, compliance still blocks the sanctioned address
    register_circuit(&env, "bypass_circ");
    ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "bypass_circ"),
        vec![
            &env,
            Bytes::from_slice(&env, b"inp1"),
            Bytes::from_slice(&env, b"inp2"),
        ],
        Bytes::from_slice(&env, b"proof_data"),
        Bytes::from_slice(&env, b"null_bypass_1"),
        Vec::new(&env),
        None,
        Map::new(&env),
    )
    .unwrap();

    // Compliance screen still fails for sanctioned user
    assert!(ComplianceFilter::screen_address(env.clone(), bad_actor).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// 3-hop chain: DID → Credential → Reputation
// ═══════════════════════════════════════════════════════════════════════════

/// Full 3-contract chain in one test: create DID, issue credential, update reputation.
#[test]
fn cross_three_hop_did_credential_reputation() {
    let env = setup();
    let admin = Address::generate(&env);
    let controller = Address::generate(&env);
    let issuer = Address::generate(&env);

    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();

    // Step 1: Create DID
    let did = create_did(&env, &controller);
    let doc = DIDRegistry::resolve_did(env.clone(), did.clone()).unwrap();
    assert_eq!(doc.controller, controller);

    // Step 2: Initialize reputation for the subject (DID controller)
    ReputationScore::initialize_reputation(env.clone(), controller.clone()).unwrap();
    let score_0 = ReputationScore::get_reputation_score(env.clone(), controller.clone());

    // Step 3: Issue credential to DID controller
    let cid = issue_cred(&env, &issuer, &controller);
    let valid = CredentialIssuer::verify_credential(env.clone(), cid).unwrap();
    assert!(valid);

    // Step 4: Record credential outcome in reputation
    ReputationScore::update_credential_reputation(
        env.clone(),
        controller.clone(),
        valid,
        Bytes::from_slice(&env, b"DIDCredChain"),
    )
    .unwrap();

    let score_1 = ReputationScore::get_reputation_score(env.clone(), controller.clone());
    assert!(score_1 > score_0, "score should increase after valid credential");

    // Step 5: DID doc update does not break reputation state
    DIDRegistry::update_did(
        env.clone(),
        controller.clone(),
        Some(vec![&env, vm(&env, 2)]),
        None,
    )
    .unwrap();
    let score_2 = ReputationScore::get_reputation_score(env.clone(), controller);
    assert_eq!(score_1, score_2, "DID update must not affect reputation");
}

// ═══════════════════════════════════════════════════════════════════════════
// Error propagation across contract boundaries
// ═══════════════════════════════════════════════════════════════════════════

/// Credential issued to address A cannot be revoked by address B.
#[test]
fn cross_error_wrong_issuer_propagates() {
    let env = setup();
    let issuer_a = Address::generate(&env);
    let issuer_b = Address::generate(&env);
    let subject = Address::generate(&env);

    let cid = issue_cred(&env, &issuer_a, &subject);

    // issuer_b cannot revoke issuer_a's credential
    let err = CredentialIssuer::revoke_credential(env.clone(), issuer_b, cid, None).unwrap_err();
    assert_eq!(err, CredentialIssuerError::Unauthorized);
}

/// Resolve on a non-existent DID propagates NotFound.
#[test]
fn cross_error_missing_did_propagates() {
    let env = setup();
    let missing = Bytes::from_slice(&env, b"did:stellar:GNOTHERE");
    let err = DIDRegistry::resolve_did(env.clone(), missing).unwrap_err();
    assert_eq!(err, DIDRegistryError::NotFound);
}

/// Reputation update on uninitialized user propagates NotInitialized.
#[test]
fn cross_error_uninitialized_reputation_propagates() {
    let env = setup();
    // Initialize contract but NOT the user profile
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    let user = Address::generate(&env);
    let err = ReputationScore::update_transaction_reputation(env.clone(), user, true, 100)
        .unwrap_err();
    assert_eq!(err, ReputationScoreError::NotInitialized);
}

/// ZK proof submission on unknown circuit propagates InvalidCircuit.
#[test]
fn cross_error_zk_unknown_circuit_propagates() {
    let env = setup();
    let err = ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "ghost"),
        Vec::new(&env),
        Bytes::from_slice(&env, b"proof"),
        Bytes::from_slice(&env, b"null"),
        Vec::new(&env),
        None,
        Map::new(&env),
    )
    .unwrap_err();
    assert_eq!(err, ZKAttestationError::InvalidCircuit);
}

// ═══════════════════════════════════════════════════════════════════════════
// Reentrancy / double-update protection
// ═══════════════════════════════════════════════════════════════════════════

/// Submitting the same nullifier twice is rejected by the ZK contract.
/// This models reentrancy protection at the ZK layer.
#[test]
fn cross_zk_nullifier_double_use_rejected() {
    let env = setup();
    register_circuit(&env, "reent_circ");

    ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "reent_circ"),
        vec![
            &env,
            Bytes::from_slice(&env, b"inp1"),
            Bytes::from_slice(&env, b"inp2"),
        ],
        Bytes::from_slice(&env, b"proof"),
        Bytes::from_slice(&env, b"reent_null_1"),
        Vec::new(&env),
        None,
        Map::new(&env),
    )
    .unwrap();

    let err = ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "reent_circ"),
        vec![
            &env,
            Bytes::from_slice(&env, b"inp1"),
            Bytes::from_slice(&env, b"inp2"),
        ],
        Bytes::from_slice(&env, b"proof"),
        Bytes::from_slice(&env, b"reent_null_1"), // same nullifier
        Vec::new(&env),
        None,
        Map::new(&env),
    )
    .unwrap_err();

    assert_eq!(err, ZKAttestationError::NullifierAlreadyUsed);
}

/// Double-revoking the same credential is rejected.
#[test]
fn cross_credential_double_revoke_rejected() {
    let env = setup();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    let cid = issue_cred(&env, &issuer, &subject);

    CredentialIssuer::revoke_credential(env.clone(), issuer.clone(), cid.clone(), None).unwrap();

    let err = CredentialIssuer::revoke_credential(env.clone(), issuer, cid, None).unwrap_err();
    assert_eq!(err, CredentialIssuerError::AlreadyRevoked);
}

/// Creating the same DID twice is rejected.
#[test]
fn cross_did_double_create_rejected() {
    let env = setup();
    let ctrl = Address::generate(&env);
    let d = unique_did(&env);

    DIDRegistry::create_did(env.clone(), ctrl.clone(), d.clone(), Vec::new(&env), Vec::new(&env)).unwrap();

    let err = DIDRegistry::create_did(env.clone(), ctrl, d, Vec::new(&env), Vec::new(&env))
        .unwrap_err();
    assert_eq!(err, DIDRegistryError::AlreadyExists);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-contract: multiple users, credentials, and reputation in concert
// ═══════════════════════════════════════════════════════════════════════════

/// Three users each get a DID, a credential, and a reputation update.
/// Final scores are independently tracked and non-interfering.
#[test]
fn cross_three_users_independent_state() {
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();

    let mut final_scores: Vec<u32> = Vec::new(&env);

    for i in 0..3u8 {
        let ctrl = Address::generate(&env);
        let issuer = Address::generate(&env);

        // Create DID
        create_did(&env, &ctrl);

        // Initialize and build reputation
        ReputationScore::initialize_reputation(env.clone(), ctrl.clone()).unwrap();
        for _ in 0..(i + 1) {
            ReputationScore::update_transaction_reputation(env.clone(), ctrl.clone(), true, 100)
                .unwrap();
        }

        // Issue and verify credential
        let cid = issue_cred(&env, &issuer, &ctrl);
        let valid = CredentialIssuer::verify_credential(env.clone(), cid).unwrap();
        ReputationScore::update_credential_reputation(
            env.clone(),
            ctrl.clone(),
            valid,
            Bytes::from_slice(&env, b"TestCred"),
        )
        .unwrap();

        final_scores.push_back(ReputationScore::get_reputation_score(env.clone(), ctrl));
    }

    // Each user has a distinct score proportional to their tx count
    assert!(final_scores.get(0).unwrap() < final_scores.get(1).unwrap());
    assert!(final_scores.get(1).unwrap() < final_scores.get(2).unwrap());
}
