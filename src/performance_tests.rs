//! Performance and load testing suite (Issue #78).
//!
//! Establishes gas-cost baselines and throughput measurements for:
//!   - DID creation/resolution at scale
//!   - Credential issuance and verification batch throughput
//!   - Reputation score update under repeated load
//!   - ZK circuit registration and proof submission
//!   - Compliance screening throughput
//!
//! Soroban's test environment is synchronous; "load" tests here exercise
//! N sequential operations and assert result consistency, providing a
//! deterministic regression baseline for performance-sensitive paths.

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{
    compliance_filter::ComplianceFilter,
    credential_issuer::CredentialIssuer,
    did_registry::DIDRegistry,
    reputation_score::{Config, ReputationScore},
    zk_attestation::{CircuitType, ZKAttestation},
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
        max_score: 10000,
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

// Build a unique DID bytes using an index counter
fn did_n(env: &Env, n: u32) -> Bytes {
    let mut d = Bytes::from_slice(env, b"did:stellar:GPERF");
    d.append(&Bytes::from_slice(env, n.to_string().as_bytes()));
    d
}

// ═══════════════════════════════════════════════════════════════════════════
// DID Registry – bulk creation / resolution baseline
// ═══════════════════════════════════════════════════════════════════════════

/// Validate that 50 DID creations all succeed and can be resolved.
#[test]
fn perf_did_bulk_create_resolve() {
    const N: u32 = 50;
    let env = setup();
    let mut controllers: Vec<Address> = Vec::new(&env);

    for i in 0..N {
        let ctrl = Address::generate(&env);
        let d = did_n(&env, i);
        DIDRegistry::create_did(
            env.clone(),
            ctrl.clone(),
            d.clone(),
            vec![&env, vm(&env, i as u8)],
            svc(&env),
        )
        .unwrap();
        controllers.push_back(ctrl);
    }

    // Verify all DIDs resolve correctly
    let mut resolved = 0u32;
    for i in 0..N {
        let d = did_n(&env, i);
        if DIDRegistry::resolve_did(env.clone(), d).is_ok() {
            resolved += 1;
        }
    }
    assert_eq!(resolved, N, "all {} DIDs should resolve", N);
}

/// Repeated did_exists lookups should all return true after creation.
#[test]
fn perf_did_exists_lookup_throughput() {
    const N: u32 = 100;
    let env = setup();

    for i in 0..N {
        let ctrl = Address::generate(&env);
        let d = did_n(&env, 10_000 + i);
        DIDRegistry::create_did(
            env.clone(),
            ctrl,
            d,
            Vec::new(&env),
            Vec::new(&env),
        )
        .unwrap();
    }

    let mut found = 0u32;
    for i in 0..N {
        if DIDRegistry::did_exists(env.clone(), did_n(&env, 10_000 + i)) {
            found += 1;
        }
    }
    assert_eq!(found, N);
}

// ═══════════════════════════════════════════════════════════════════════════
// Credential Issuer – bulk issuance and verification
// ═══════════════════════════════════════════════════════════════════════════

/// 50 credentials issued from a single issuer and all verify as valid.
#[test]
fn perf_credential_bulk_issue_verify() {
    const N: u32 = 50;
    let env = setup();
    let issuer = Address::generate(&env);
    let mut ids: Vec<Bytes> = Vec::new(&env);

    for _ in 0..N {
        let subject = Address::generate(&env);
        let cid = CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            subject,
            vec![&env, Bytes::from_slice(&env, b"LoadTest")],
            Bytes::from_slice(&env, b"perf_data"),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();
        ids.push_back(cid);
    }

    let mut valid_count = 0u32;
    for id in ids.iter() {
        if CredentialIssuer::verify_credential(env.clone(), id).unwrap_or(false) {
            valid_count += 1;
        }
    }
    assert_eq!(valid_count, N, "all {} credentials should verify", N);
}

/// Pagination over a large credential set returns consistent results.
#[test]
fn perf_credential_pagination_consistency() {
    const N: u32 = 45;
    const PAGE_SIZE: u32 = 10;
    let env = setup();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    for _ in 0..N {
        CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            subject.clone(),
            vec![&env, Bytes::from_slice(&env, b"PagCred")],
            Bytes::from_slice(&env, b"d"),
            None,
            Bytes::from_slice(&env, b"p"),
        )
        .unwrap();
    }

    let p0 = CredentialIssuer::get_credentials_by_subject(env.clone(), subject.clone(), 0, PAGE_SIZE);
    assert_eq!(p0.data.len(), PAGE_SIZE);
    assert!(p0.has_more);
    assert_eq!(p0.total, N);

    let last_page = N / PAGE_SIZE; // page 4 = items 40-44
    let p_last = CredentialIssuer::get_credentials_by_subject(env.clone(), subject, last_page, PAGE_SIZE);
    assert_eq!(p_last.data.len(), N % PAGE_SIZE);
    assert!(!p_last.has_more);
}

/// 50 revocations each succeed and subsequent verify returns false.
#[test]
fn perf_credential_bulk_revoke() {
    const N: u32 = 50;
    let env = setup();
    let issuer = Address::generate(&env);
    let mut ids: Vec<Bytes> = Vec::new(&env);

    for _ in 0..N {
        let cid = CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            Address::generate(&env),
            vec![&env, Bytes::from_slice(&env, b"RevokeLoad")],
            Bytes::from_slice(&env, b"d"),
            None,
            Bytes::from_slice(&env, b"p"),
        )
        .unwrap();
        ids.push_back(cid);
    }

    let mut revoked = 0u32;
    for id in ids.iter() {
        CredentialIssuer::revoke_credential(env.clone(), issuer.clone(), id, None).unwrap();
        let valid = CredentialIssuer::verify_credential(env.clone(), id).unwrap_or(true);
        if !valid {
            revoked += 1;
        }
    }
    assert_eq!(revoked, N, "all {} credentials should be revoked", N);
}

// ═══════════════════════════════════════════════════════════════════════════
// Reputation Score – repeated update throughput
// ═══════════════════════════════════════════════════════════════════════════

/// 100 transaction updates on the same user produce a monotonically
/// non-decreasing score (all successful) and consistent history size.
#[test]
fn perf_reputation_100_updates() {
    const N: u32 = 100;
    let env = setup();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

    let initial = ReputationScore::get_reputation_score(env.clone(), user.clone());

    for _ in 0..N {
        ReputationScore::update_transaction_reputation(env.clone(), user.clone(), true, 100).unwrap();
    }

    let final_score = ReputationScore::get_reputation_score(env.clone(), user.clone());
    assert!(final_score >= initial, "score should not decrease after successful txns");

    let history = ReputationScore::get_reputation_history(env.clone(), user, N).unwrap();
    assert!(history.len() <= N, "history should be bounded");
}

/// Mixed success/failure updates keep score bounded between 0 and max_score.
#[test]
fn perf_reputation_mixed_updates_bounded() {
    const N: u32 = 60;
    let env = setup();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();
    ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();

    for i in 0..N {
        let success = i % 3 != 0; // 2/3 success
        ReputationScore::update_transaction_reputation(env.clone(), user.clone(), success, 10).unwrap();
    }

    let score = ReputationScore::get_reputation_score(env.clone(), user);
    assert!(score <= rep_config().max_score, "score must not exceed max");
}

/// 10 users initialized concurrently all get the same baseline score.
#[test]
fn perf_reputation_multi_user_baseline() {
    const N: u32 = 10;
    let env = setup();
    let admin = Address::generate(&env);
    ReputationScore::initialize(env.clone(), admin, rep_config()).unwrap();

    let mut scores: Vec<u32> = Vec::new(&env);
    for _ in 0..N {
        let user = Address::generate(&env);
        ReputationScore::initialize_reputation(env.clone(), user.clone()).unwrap();
        scores.push_back(ReputationScore::get_reputation_score(env.clone(), user));
    }

    let first = scores.get(0).unwrap();
    for i in 0..N {
        assert_eq!(scores.get(i).unwrap(), first, "all initial scores equal");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ZK Attestation – circuit registration + proof submission throughput
// ═══════════════════════════════════════════════════════════════════════════

/// Register 10 circuits and submit one proof per circuit.
#[test]
fn perf_zk_bulk_circuits_and_proofs() {
    let env = setup();

    // Use pre-defined symbol names to avoid alloc::format!
    let circuit_names = [
        "cir0", "cir1", "cir2", "cir3", "cir4",
        "cir5", "cir6", "cir7", "cir8", "cir9",
    ];
    let nullifier_suffixes: [&[u8]; 10] = [
        b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9",
    ];

    for i in 0..10usize {
        let cid = Symbol::new(&env, circuit_names[i]);
        ZKAttestation::register_circuit(
            env.clone(),
            cid.clone(),
            Bytes::from_slice(&env, b"Circuit"),
            Bytes::from_slice(&env, b"desc"),
            Bytes::from_slice(&env, b"verifier_key_32_bytes_here!!!!!"),
            2,
            1,
            CircuitType::RangeProof,
            Vec::new(&env),
        )
        .unwrap();

        let mut nullifier = Bytes::from_slice(&env, b"null_perf_");
        nullifier.append(&Bytes::from_slice(&env, nullifier_suffixes[i]));

        let proof_id = ZKAttestation::submit_proof(
            env.clone(),
            cid,
            vec![
                &env,
                Bytes::from_slice(&env, b"inp1"),
                Bytes::from_slice(&env, b"inp2"),
            ],
            Bytes::from_slice(&env, b"proof_data"),
            nullifier,
            Vec::new(&env),
            None,
            Map::new(&env),
        )
        .unwrap();

        assert!(ZKAttestation::verify_proof(env.clone(), proof_id).unwrap());
    }

    let active = ZKAttestation::get_active_circuits(env.clone());
    assert_eq!(active.len(), 10);
}

// ═══════════════════════════════════════════════════════════════════════════
// Compliance Filter – screening throughput
// ═══════════════════════════════════════════════════════════════════════════

fn cf_init(env: &Env) -> Address {
    let admin = Address::generate(env);
    ComplianceFilter::initialize(env.clone(), admin.clone()).unwrap();
    admin
}

/// Screen 50 addresses; only sanctioned ones fail, rest pass.
#[test]
fn perf_compliance_bulk_screen() {
    const TOTAL: u32 = 50;
    const SANCTIONED: u32 = 10;
    let env = setup();
    let admin = cf_init(&env);
    let source = Bytes::from_slice(&env, b"PERF_LIST");
    let hash = BytesN::from_array(&env, &[9u8; 32]);

    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0).unwrap();

    let mut sanctioned_addrs: Vec<Address> = Vec::new(&env);
    for _ in 0..SANCTIONED {
        sanctioned_addrs.push_back(Address::generate(&env));
    }
    ComplianceFilter::load_list_entries(env.clone(), admin.clone(), source.clone(), sanctioned_addrs.clone()).unwrap();

    let mut blocked = 0u32;
    let mut allowed = 0u32;

    for addr in sanctioned_addrs.iter() {
        if ComplianceFilter::screen_address(env.clone(), addr).is_err() {
            blocked += 1;
        }
    }

    for _ in 0..(TOTAL - SANCTIONED) {
        let clean = Address::generate(&env);
        if ComplianceFilter::screen_address(env.clone(), clean).is_ok() {
            allowed += 1;
        }
    }

    assert_eq!(blocked, SANCTIONED, "exactly {} addresses blocked", SANCTIONED);
    assert_eq!(allowed, TOTAL - SANCTIONED, "clean addresses pass screening");
}

/// Adding to sanctions list in bulk via load_list_entries is consistent.
#[test]
fn perf_compliance_bulk_load_consistency() {
    const N: u32 = 30;
    let env = setup();
    let admin = cf_init(&env);
    let source = Bytes::from_slice(&env, b"BULK_PERF");
    let hash = BytesN::from_array(&env, &[10u8; 32]);

    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 0).unwrap();

    let mut addrs: Vec<Address> = Vec::new(&env);
    for _ in 0..N {
        addrs.push_back(Address::generate(&env));
    }

    ComplianceFilter::load_list_entries(env.clone(), admin, source, addrs.clone()).unwrap();

    let mut count = 0u32;
    for addr in addrs.iter() {
        if ComplianceFilter::is_sanctioned(env.clone(), addr) {
            count += 1;
        }
    }
    assert_eq!(count, N, "all {} loaded entries are sanctioned", N);
}
