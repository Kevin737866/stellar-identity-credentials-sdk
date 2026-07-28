#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{
    compliance_filter::ComplianceFilter,
    credential_issuer::{BatchIssuanceItem, CredentialIssuer},
    credential_schema::{CredentialSchema, FieldValidation},
    did_registry::{DIDRegistry, Signer},
    reputation_score::{Config, ReputationScore},
    zk_attestation::{CircuitType, ZKAttestation},
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

fn make_vm(env: &Env, id: &str, key: &[u8; 32]) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, id.as_bytes()),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
        controller: Address::generate(env),
        public_key: BytesN::from_array(env, key),
    }
}

fn make_did_bytes(env: &Env) -> Bytes {
    Bytes::from_slice(env, b"did:stellar:GABCDEF123456789")
}

#[test]
fn bench_create_did() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);
    let services = soroban_sdk::vec![
        &env,
        Service {
            id: Bytes::from_slice(&env, b"#hub"),
            type_: Bytes::from_slice(&env, b"IdentityHub"),
            endpoint: Bytes::from_slice(&env, b"https://hub.example.com"),
        },
    ];

    let result = DIDRegistry::create_did(env.clone(), controller, did, soroban_sdk::vec![&env, vm], services);
    assert!(result.is_ok());
    std::println!("[BENCH] create_did            OK");
}

#[test]
fn bench_resolve_did() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);
    let _ = DIDRegistry::create_did(
        env.clone(),
        controller,
        did.clone(),
        soroban_sdk::vec![&env, vm],
        Vec::new(&env),
    );

    let result = DIDRegistry::resolve_did(env.clone(), did);
    assert!(result.is_ok());
    std::println!("[BENCH] resolve_did           OK");
}

#[test]
fn bench_issue_credential() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    let result = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        soroban_sdk::vec![&env, Bytes::from_slice(&env, b"KYCVerification")],
        Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
        None,
        Bytes::from_slice(&env, b"proof"),
    );
    assert!(result.is_ok());
    std::println!("[BENCH] issue_credential      OK");
}

#[test]
fn bench_verify_credential() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);
    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer,
        subject,
        soroban_sdk::vec![&env, Bytes::from_slice(&env, b"KYC")],
        Bytes::from_slice(&env, b"{\"v\":1}"),
        None,
        Bytes::from_slice(&env, b"proof"),
    )
    .unwrap();

    let result = CredentialIssuer::verify_credential(env.clone(), cred_id);
    assert!(result.is_ok());
    assert!(result.unwrap());
    std::println!("[BENCH] verify_credential     OK");
}

#[test]
fn bench_initialize_reputation() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let config = Config {
        max_score: 100,
        transaction_success_weight: 10,
        transaction_failure_weight: 5,
        credential_valid_weight: 20,
        credential_invalid_weight: 15,
    };
    ReputationScore::initialize(env.clone(), admin, config);

    let result = ReputationScore::initialize_reputation(env.clone(), user);
    assert!(result.is_ok());
    std::println!("[BENCH] initialize_reputation OK");
}

#[test]
fn bench_update_reputation() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let config = Config {
        max_score: 100,
        transaction_success_weight: 10,
        transaction_failure_weight: 5,
        credential_valid_weight: 20,
        credential_invalid_weight: 15,
    };
    ReputationScore::initialize(env.clone(), admin, config);
    let _ = ReputationScore::initialize_reputation(env.clone(), user.clone());

    let result = ReputationScore::update_transaction_reputation(env.clone(), user, true, 1000);
    assert!(result.is_ok());
    std::println!("[BENCH] update_tx_reputation  OK");
}

#[test]
fn bench_register_circuit() {
    let env = setup_env();

    let result = ZKAttestation::register_circuit(
        env.clone(),
        Symbol::new(&env, "bench_circ"),
        Bytes::from_slice(&env, b"Bench Circuit"),
        Bytes::from_slice(&env, b"desc"),
        Bytes::from_slice(&env, b"verifier_key_data_here!!"),
        2,
        3,
        CircuitType::RangeProof,
        soroban_sdk::vec![&env, Symbol::new(&env, "attr")],
    );
    assert!(result.is_ok());
    std::println!("[BENCH] register_circuit      OK");
}

#[test]
fn bench_screen_address() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let source = Bytes::from_slice(&env, b"OFAC_SDN");
    let hash = BytesN::from_array(&env, &[2u8; 32]);
    let _ = ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        hash,
        1,
    );
    let sanctioned = Address::generate(&env);
    let _ = ComplianceFilter::load_list_entries(
        env.clone(),
        admin,
        source,
        soroban_sdk::vec![&env, sanctioned.clone()],
    );

    let clean = Address::generate(&env);
    let result = ComplianceFilter::screen_address(env.clone(), clean);
    assert!(result.is_ok());
    std::println!("[BENCH] screen_address(clear) OK");
}

#[test]
fn bench_paginated_credentials() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    for _ in 0..25 {
        let _ = CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            subject.clone(),
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Bytes::from_slice(&env, b"proof"),
        );
    }

    let result = CredentialIssuer::get_credentials_by_subject(env.clone(), subject, 0, 10);
    assert_eq!(result.data.len(), 10);
    assert_eq!(result.total, 25);
    assert!(result.has_more);
    std::println!("[BENCH] paginated_creds(p0)   items={}", result.data.len());
}

#[test]
fn bench_register_schema() {
    let env = setup_env();
    let admin = Address::generate(&env);

    let required = soroban_sdk::vec![
        &env,
        Bytes::from_slice(&env, b"name"),
        Bytes::from_slice(&env, b"dob"),
    ];
    let optional = soroban_sdk::vec![&env, Bytes::from_slice(&env, b"middle_name")];
    let validations: Map<Bytes, FieldValidation> = Map::new(&env);

    let result = CredentialSchema::register_schema(
        env.clone(),
        admin,
        Bytes::from_slice(&env, b"kyc_v1"),
        Bytes::from_slice(&env, b"KYCSchema"),
        required,
        optional,
        validations,
    );
    assert!(result.is_ok());
    std::println!("[BENCH] register_schema       OK");
}

#[test]
fn bench_update_did() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);
    let _ = DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        did.clone(),
        soroban_sdk::vec![&env, vm],
        Vec::new(&env),
    );

    let new_vm = make_vm(&env, "#key-2", &[2u8; 32]);
    let result = DIDRegistry::update_did(
        env.clone(),
        controller,
        Some(soroban_sdk::vec![&env, new_vm]),
        None,
    );
    assert!(result.is_ok());
    std::println!("[BENCH] update_did            OK");
}

#[test]
fn bench_deactivate_did() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);
    let _ = DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        did.clone(),
        soroban_sdk::vec![&env, vm],
        Vec::new(&env),
    );

    let result = DIDRegistry::deactivate_did(env.clone(), controller);
    assert!(result.is_ok());
    std::println!("[BENCH] deactivate_did        OK");
}

#[test]
fn bench_configure_multisig() {
    let env = setup_env();
    env.mock_all_auths();
    let controller = Address::generate(&env);
    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);
    let _ = DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        did.clone(),
        soroban_sdk::vec![&env, vm],
        Vec::new(&env),
    );

    let signers = soroban_sdk::vec![
        &env,
        Signer {
            address: Address::generate(&env),
            weight: 1,
        },
        Signer {
            address: Address::generate(&env),
            weight: 1,
        },
        Signer {
            address: Address::generate(&env),
            weight: 1,
        },
    ];

    let result = DIDRegistry::configure_multisig(env.clone(), controller, signers, 2);
    assert!(result.is_ok());
    std::println!("[BENCH] configure_multisig    OK");
}

#[test]
fn bench_multisig_operation_lifecycle() {
    let env = setup_env();
    env.mock_all_auths();
    let controller = Address::generate(&env);
    let did = make_did_bytes(&env);
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);
    let _ = DIDRegistry::create_did(
        env.clone(),
        controller.clone(),
        did.clone(),
        soroban_sdk::vec![&env, vm],
        Vec::new(&env),
    );

    let signer1_addr = Address::generate(&env);
    let signer2_addr = Address::generate(&env);
    let signers = soroban_sdk::vec![
        &env,
        Signer {
            address: signer1_addr.clone(),
            weight: 1,
        },
        Signer {
            address: signer2_addr.clone(),
            weight: 1,
        },
        Signer {
            address: Address::generate(&env),
            weight: 1,
        },
    ];
    DIDRegistry::configure_multisig(env.clone(), controller.clone(), signers, 2).unwrap();

    let op_data = Bytes::from_slice(&env, b"update_vm");
    let op_id = DIDRegistry::create_multisig_operation(
        env.clone(),
        controller.clone(),
        did.clone(),
        op_data.clone(),
    );
    assert!(op_id.is_ok());

    let _ = DIDRegistry::sign_multisig_operation(env.clone(), signer1_addr, op_id.clone().unwrap());
    let _ = DIDRegistry::sign_multisig_operation(env.clone(), signer2_addr, op_id.clone().unwrap());

    let result = DIDRegistry::execute_multisig_operation(env.clone(), controller, op_id.unwrap());
    assert!(result.is_ok());
    std::println!("[BENCH] multisig_lifecycle     OK");
}

#[test]
fn bench_revoke_credential() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    let cred_id = CredentialIssuer::issue_credential(
        env.clone(),
        issuer.clone(),
        subject,
        soroban_sdk::vec![&env, Bytes::from_slice(&env, b"KYC")],
        Bytes::from_slice(&env, b"{\"v\":1}"),
        None,
        Bytes::from_slice(&env, b"proof"),
    )
    .unwrap();

    let result = CredentialIssuer::revoke_credential(
        env.clone(),
        issuer,
        cred_id,
        Some(Bytes::from_slice(&env, b"compromised")),
    );
    assert!(result.is_ok());
    std::println!("[BENCH] revoke_credential     OK");
}

#[test]
fn bench_batch_issue_credentials() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject1 = Address::generate(&env);
    let subject2 = Address::generate(&env);

    let items = soroban_sdk::vec![
        &env,
        BatchIssuanceItem {
            subject: subject1,
            credential_type: soroban_sdk::vec![&env, Bytes::from_slice(&env, b"KYC")],
            credential_data: Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
            expiration_date: None,
            proof: Bytes::from_slice(&env, b"proof1"),
        },
        BatchIssuanceItem {
            subject: subject2,
            credential_type: soroban_sdk::vec![&env, Bytes::from_slice(&env, b"AML")],
            credential_data: Bytes::from_slice(&env, b"{\"name\":\"Bob\"}"),
            expiration_date: None,
            proof: Bytes::from_slice(&env, b"proof2"),
        },
    ];

    let result = CredentialIssuer::batch_issue_credentials(env.clone(), issuer, items);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
    std::println!("[BENCH] batch_issue_creds(2)  OK");
}

#[test]
fn bench_batch_verify_credentials() {
    let env = setup_env();
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    let cred_ids = soroban_sdk::vec![
        &env,
        CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            subject.clone(),
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"KYC1")],
            Bytes::from_slice(&env, b"{\"v\":1}"),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap(),
        CredentialIssuer::issue_credential(
            env.clone(),
            issuer.clone(),
            subject.clone(),
            soroban_sdk::vec![&env, Bytes::from_slice(&env, b"KYC2")],
            Bytes::from_slice(&env, b"{\"v\":2}"),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap(),
    ];

    let results = CredentialIssuer::batch_verify_credentials(env.clone(), cred_ids);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|&r| r));
    std::println!("[BENCH] batch_verify_creds(2) OK");
}

#[test]
fn bench_update_credential_reputation() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let config = Config {
        max_score: 100,
        transaction_success_weight: 10,
        transaction_failure_weight: 5,
        credential_valid_weight: 20,
        credential_invalid_weight: 15,
    };
    ReputationScore::initialize(env.clone(), admin, config);
    let _ = ReputationScore::initialize_reputation(env.clone(), user.clone());

    let result =
        ReputationScore::update_credential_reputation(env.clone(), user, true, Bytes::from_slice(&env, b"KYC"));
    assert!(result.is_ok());
    std::println!("[BENCH] update_cred_reputation OK");
}

#[test]
fn bench_batch_update_transaction_reputation() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    let config = Config {
        max_score: 100,
        transaction_success_weight: 10,
        transaction_failure_weight: 5,
        credential_valid_weight: 20,
        credential_invalid_weight: 15,
    };
    ReputationScore::initialize(env.clone(), admin, config);
    let _ = ReputationScore::initialize_reputation(env.clone(), user1.clone());
    let _ = ReputationScore::initialize_reputation(env.clone(), user2.clone());

    let updates = soroban_sdk::vec![
        &env,
        (user1, true, 1000i128),
        (user2, true, 2000i128),
    ];

    let result = ReputationScore::batch_update_transaction_reputation(env.clone(), updates);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
    std::println!("[BENCH] batch_update_tx_rep(2) OK");
}

#[test]
fn bench_attest_trust() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let truster = Address::generate(&env);
    let subject = Address::generate(&env);
    let config = Config {
        max_score: 100,
        transaction_success_weight: 10,
        transaction_failure_weight: 5,
        credential_valid_weight: 20,
        credential_invalid_weight: 15,
    };
    ReputationScore::initialize(env.clone(), admin, config);
    let _ = ReputationScore::initialize_reputation(env.clone(), truster.clone());
    let _ = ReputationScore::initialize_reputation(env.clone(), subject.clone());

    let result = ReputationScore::attest_trust(
        env.clone(),
        truster,
        subject,
        50,
        Bytes::from_slice(&env, b"reliable partner"),
    );
    assert!(result.is_ok());
    std::println!("[BENCH] attest_trust           OK");
}

#[test]
fn bench_submit_proof() {
    let env = setup_env();

    let circuit_id = Symbol::new(&env, "bench_circ");
    ZKAttestation::register_circuit(
        env.clone(),
        circuit_id,
        Bytes::from_slice(&env, b"Bench Circuit"),
        Bytes::from_slice(&env, b"desc"),
        Bytes::from_slice(&env, b"verifier_key_data_here!!"),
        2,
        3,
        CircuitType::RangeProof,
        soroban_sdk::vec![&env, Symbol::new(&env, "attr")],
    )
    .unwrap();

    let public_inputs = soroban_sdk::vec![
        &env,
        Bytes::from_slice(&env, b"pub1"),
        Bytes::from_slice(&env, b"pub2"),
    ];
    let metadata: Map<Symbol, Bytes> = Map::new(&env);

    let result = ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "bench_circ"),
        public_inputs,
        Bytes::from_slice(&env, b"fake_proof_bytes_for_benchmark"),
        Bytes::from_slice(&env, b"nullifier123"),
        soroban_sdk::vec![&env, Symbol::new(&env, "age")],
        None,
        metadata,
    );
    assert!(result.is_ok());
    std::println!("[BENCH] submit_proof           OK");
}

#[test]
fn bench_verify_proof() {
    let env = setup_env();

    let circuit_id = Symbol::new(&env, "bench_circ2");
    ZKAttestation::register_circuit(
        env.clone(),
        circuit_id,
        Bytes::from_slice(&env, b"Bench Circuit 2"),
        Bytes::from_slice(&env, b"desc"),
        Bytes::from_slice(&env, b"verifier_key_data_here!!"),
        2,
        3,
        CircuitType::RangeProof,
        soroban_sdk::vec![&env, Symbol::new(&env, "attr")],
    )
    .unwrap();

    let public_inputs = soroban_sdk::vec![
        &env,
        Bytes::from_slice(&env, b"pub1"),
        Bytes::from_slice(&env, b"pub2"),
    ];
    let metadata: Map<Symbol, Bytes> = Map::new(&env);

    let proof_id = ZKAttestation::submit_proof(
        env.clone(),
        Symbol::new(&env, "bench_circ2"),
        public_inputs,
        Bytes::from_slice(&env, b"fake_proof_bytes_for_benchmark"),
        Bytes::from_slice(&env, b"nullifier456"),
        soroban_sdk::vec![&env, Symbol::new(&env, "age")],
        None,
        metadata,
    )
    .unwrap();

    let result = ZKAttestation::verify_proof(env.clone(), proof_id);
    assert!(result.is_ok());
    std::println!("[BENCH] verify_proof           OK");
}

#[test]
fn bench_batch_verify_proofs() {
    let env = setup_env();

    let circuit_id = Symbol::new(&env, "bench_circ3");
    ZKAttestation::register_circuit(
        env.clone(),
        circuit_id,
        Bytes::from_slice(&env, b"Bench Circuit 3"),
        Bytes::from_slice(&env, b"desc"),
        Bytes::from_slice(&env, b"verifier_key_data_here!!"),
        2,
        3,
        CircuitType::RangeProof,
        soroban_sdk::vec![&env, Symbol::new(&env, "attr")],
    )
    .unwrap();

    let proof_ids = soroban_sdk::vec![
        &env,
        {
            let public_inputs = soroban_sdk::vec![&env, Bytes::from_slice(&env, b"pub1"), Bytes::from_slice(&env, b"pub2")];
            let metadata: Map<Symbol, Bytes> = Map::new(&env);
            ZKAttestation::submit_proof(
                env.clone(),
                Symbol::new(&env, "bench_circ3"),
                public_inputs,
                Bytes::from_slice(&env, b"proof_a"),
                Bytes::from_slice(&env, b"null_a"),
                soroban_sdk::vec![&env, Symbol::new(&env, "age")],
                None,
                metadata,
            ).unwrap()
        },
        {
            let public_inputs = soroban_sdk::vec![&env, Bytes::from_slice(&env, b"pub1"), Bytes::from_slice(&env, b"pub2")];
            let metadata: Map<Symbol, Bytes> = Map::new(&env);
            ZKAttestation::submit_proof(
                env.clone(),
                Symbol::new(&env, "bench_circ3"),
                public_inputs,
                Bytes::from_slice(&env, b"proof_b"),
                Bytes::from_slice(&env, b"null_b"),
                soroban_sdk::vec![&env, Symbol::new(&env, "age")],
                None,
                metadata,
            ).unwrap()
        },
    ];

    let results = ZKAttestation::batch_verify_proofs(env.clone(), proof_ids);
    assert_eq!(results.len(), 2);
    std::println!("[BENCH] batch_verify_proofs(2) OK");
}

#[test]
fn bench_batch_screen_addresses() {
    let env = setup_env();
    let admin = Address::generate(&env);

    let source = Bytes::from_slice(&env, b"OFAC_SDN");
    let hash = BytesN::from_array(&env, &[2u8; 32]);
    ComplianceFilter::update_sanctions_list(env.clone(), admin.clone(), source.clone(), hash, 1).unwrap();

    let addresses = soroban_sdk::vec![
        &env,
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    ];
    ComplianceFilter::load_list_entries(
        env.clone(),
        admin.clone(),
        source.clone(),
        addresses.clone(),
        hash,
    )
    .unwrap();

    let to_screen = soroban_sdk::vec![
        &env,
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    ];

    let result = ComplianceFilter::batch_screen_addresses(env.clone(), to_screen);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 5);
    std::println!("[BENCH] batch_screen(5)       OK");
}

#[test]
fn bench_update_sanctions_list() {
    let env = setup_env();
    let admin = Address::generate(&env);
    ComplianceFilter::initialize(env.clone(), admin.clone()).unwrap();

    let result = ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin,
        Bytes::from_slice(&env, b"OFAC_SDN"),
        BytesN::from_array(&env, &[3u8; 32]),
        100,
    );
    assert!(result.is_ok());
    std::println!("[BENCH] update_sanctions_list OK");
}

#[test]
fn bench_add_to_sanctions_list() {
    let env = setup_env();
    let admin = Address::generate(&env);
    ComplianceFilter::initialize(env.clone(), admin.clone()).unwrap();

    let source = Bytes::from_slice(&env, b"OFAC_SDN");
    ComplianceFilter::update_sanctions_list(
        env.clone(),
        admin.clone(),
        source.clone(),
        BytesN::from_array(&env, &[4u8; 32]),
        1,
    )
    .unwrap();

    let target = Address::generate(&env);
    let result = ComplianceFilter::add_to_sanctions_list(
        env.clone(),
        admin,
        source,
        target,
        Bytes::from_slice(&env, b"sanctioned"),
        Bytes::from_slice(&env, b"US"),
    );
    assert!(result.is_ok());
    std::println!("[BENCH] add_sanctioned_addr   OK");
}
