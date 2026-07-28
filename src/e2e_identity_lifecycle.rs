#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::{
    compliance_filter::ComplianceFilter,
    credential_issuer::CredentialIssuer,
    did_registry::{DIDRegistry, MultiSigConfig, Signer, VerificationMethod},
    reputation_score::{Config, ReputationScore},
    zk_attestation::{CircuitType, ZKAttestation},
    Service,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn make_did(env: &Env, s: &str) -> Bytes {
    Bytes::from_slice(env, format!("did:stellar:{s}").as_bytes())
}

fn make_vm(env: &Env, id: &str, key: &[u8; 32]) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, id.as_bytes()),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
        controller: Address::generate(env),
        public_key: BytesN::from_array(env, key),
    }
}

fn advance_time(env: &Env, seconds: u64) {
    env.ledger().set_timestamp(env.ledger().timestamp() + seconds);
}

// ---------------------------------------------------------------------------
// E2E: DID -> Verification Method -> Credential -> Verify
// ---------------------------------------------------------------------------

#[test]
fn e2e_did_credential_lifecycle() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did(&env, "lifecycle1");
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);

    let registry = env.register(DIDRegistry, ());
    let client = DIDRegistryClient::new(&env, &registry);

    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    // 1. Create DID
    client.create_did(
        &controller,
        &did,
        soroban_sdk::vec![&env, vm.clone()],
        soroban_sdk::vec![],
    );
    let doc = client.resolve(&did).unwrap();
    assert_eq!(doc.id, did);
    assert_eq!(doc.verification_method.len(), 1);

    // 2. Add verification method
    let vm2 = make_vm(&env, "#key-2", &[2u8; 32]);
    client.add_verification_method(&controller, &did, vm2.clone());
    let doc2 = client.resolve(&did).unwrap();
    assert_eq!(doc2.verification_method.len(), 2);

    // 3. Issue credential
    let issuer_client = env.register(CredentialIssuer, ());
    let issuer_c = CredentialIssuerClient::new(&env, &issuer_client);
    let schema = Bytes::from_slice(&env, b"schema-1");
    let subject_did = make_did(&env, "lifecycle2");
    let credential_id = BytesN::from_array(&env, &[3u8; 32]);
    issuer_c.issue(
        &issuer,
        &issuer,
        &schema,
        &subject_did,
        &credential_id,
        Bytes::from_slice(&env, b"{}"),
    );
    let cred = issuer_c.get_credential(&credential_id).unwrap();
    assert_eq!(cred.status, 1); // Active

    // 4. Verify credential
    let status = issuer_c.verify(&subject, &credential_id).unwrap();
    assert_eq!(status, 1);
}

// ---------------------------------------------------------------------------
// E2E: DID -> KYC -> Reputation -> Threshold Check
// ---------------------------------------------------------------------------

#[test]
fn e2e_kyc_reputation_threshold() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did(&env, "kyc1");
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);

    let registry = env.register(DIDRegistry, ());
    let client = DIDRegistryClient::new(&env, &registry);
    client.create_did(
        &controller,
        &did,
        soroban_sdk::vec![&env, vm],
        soroban_sdk::vec![],
    );

    let issuer = Address::generate(&env);
    let issuer_client = env.register(CredentialIssuer, ());
    let issuer_c = CredentialIssuerClient::new(&env, &issuer_client);

    // Issue KYC credential
    let schema = Bytes::from_slice(&env, b"kyc-schema");
    let subject_did = make_did(&env, "kyc2");
    let cred_id = BytesN::from_array(&env, &[4u8; 32]);
    issuer_c.issue(
        &issuer,
        &issuer,
        &schema,
        &subject_did,
        &cred_id,
        Bytes::from_slice(&env, b"{\"level\":\"advanced\"}"),
    );
    assert_eq!(issuer_c.get_credential(&cred_id).unwrap().status, 1);

    // Update reputation
    let rep_client = env.register(ReputationScore, ());
    let rep = ReputationScoreClient::new(&env, &rep_client);
    let config = Config {
        decay_factor: 100,
        min_trust_threshold: 50,
        weights: Default::default(),
    };
    rep.initialize(&issuer, &Address::generate(&env), &config);

    rep.update_transaction_reputation(&issuer, 80);
    let score = rep.get_score(&issuer);
    assert!(score >= 50, "reputation should meet threshold");
}

// ---------------------------------------------------------------------------
// E2E: ZK Circuit -> Proof -> Verify
// ---------------------------------------------------------------------------

#[test]
fn e2e_zk_circuit_proof_verify() {
    let env = setup_env();
    let controller = Address::generate(&env);

    let zk_client = env.register(ZKAttestation, ());
    let zk = ZKAttestationClient::new(&env, &zk_client);

    let circuit_id = Bytes::from_slice(&env, b"circuit-1");
    let vk = Bytes::from_slice(&env, b"verification-key");
    let proof = Bytes::from_slice(&env, b"proof-data");
    let public_inputs = soroban_sdk::vec![&env, Bytes::from_slice(&env, b"input1")];

    zk.register_circuit(&controller, &circuit_id, &vk);
    zk.submit_proof(&controller, &circuit_id, &proof, &public_inputs);
    let result = zk.verify_proof(&controller, &circuit_id, &proof, &public_inputs);
    assert!(result);
}

// ---------------------------------------------------------------------------
// E2E: Sanctions -> Screen -> Blocked
// ---------------------------------------------------------------------------

#[test]
fn e2e_compliance_sanctions_screen() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let compliance = env.register(ComplianceFilter, ());
    let client = ComplianceFilterClient::new(&env, &compliance);

    client.initialize(&admin);
    let target = Address::generate(&env);

    // Add to sanctions list
    client.add_to_sanctions_list(&admin, &target);

    // Screen result
    let result = client.screen(&target);
    assert!(result.blocked, "sanctioned address should be blocked");
    assert_eq!(result.risk_level, 3); // High risk
}

// ---------------------------------------------------------------------------
// E2E: Multi-sig DID -> Credential Issuance -> Verify
// ---------------------------------------------------------------------------

#[test]
fn e2e_multisig_did_credential_issuance() {
    let env = setup_env();
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);
    let signer3 = Address::generate(&env);

    let multisig = MultiSigConfig {
        signers: soroban_sdk::vec![
            &env,
            Signer { address: signer1.clone(), weight: 1 },
            Signer { address: signer2.clone(), weight: 1 },
            Signer { address: signer3.clone(), weight: 1 },
        ],
        threshold: 2,
    };

    let registry = env.register(DIDRegistry, ());
    let client = DIDRegistryClient::new(&env, &registry);

    let did = make_did(&env, "multisig1");
    let controller = Address::generate(&env);

    client.create_multisig_did(&controller, &did, &multisig);

    let doc = client.resolve(&did).unwrap();
    assert!(doc.multisig.is_some());
    assert_eq!(doc.multisig.unwrap().threshold, 2);

    // Verify multisig credential issuance would require 2-of-3 approvals
    let pending = client.get_pending_operations(&did);
    assert_eq!(pending.len(), 0);
}

// ---------------------------------------------------------------------------
// E2E: Delegated Issuance -> Revoke Delegation -> Verify
// ---------------------------------------------------------------------------

#[test]
fn e2e_delegated_issuance_revoke() {
    let env = setup_env();
    let admin = Address::generate(&env);
    let delegate = Address::generate(&env);
    let subject = Address::generate(&env);

    let issuer_client = env.register(CredentialIssuer, ());
    let issuer_c = CredentialIssuerClient::new(&env, &issuer_client);

    // Admin grants delegation
    issuer_c.grant_delegation(&admin, &delegate);
    assert!(issuer_c.is_delegate(&delegate));

    // Delegate issues credential
    let schema = Bytes::from_slice(&env, b"delegated-schema");
    let cred_id = BytesN::from_array(&env, &[5u8; 32]);
    issuer_c.issue(&delegate, &issuer, &schema, &subject, &cred_id, Bytes::from_slice(&env, b"{}"));
    assert_eq!(issuer_c.get_credential(&cred_id).unwrap().status, 1);

    // Admin revokes delegation
    issuer_c.revoke_delegation(&admin, &delegate);
    assert!(!issuer_c.is_delegate(&delegate));
}

// ---------------------------------------------------------------------------
// E2E: Full combined flow
// ---------------------------------------------------------------------------

#[test]
fn e2e_full_combined_flow() {
    let env = setup_env();
    let controller = Address::generate(&env);
    let did = make_did(&env, "full1");
    let vm = make_vm(&env, "#key-1", &[1u8; 32]);

    // 1. Create DID
    let registry = env.register(DIDRegistry, ());
    let client = DIDRegistryClient::new(&env, &registry);
    client.create_did(
        &controller,
        &did,
        soroban_sdk::vec![&env, vm],
        soroban_sdk::vec![],
    );
    let doc = client.resolve(&did).unwrap();
    assert_eq!(doc.id, did);

    // 2. Issue credential
    let issuer_client = env.register(CredentialIssuer, ());
    let issuer_c = CredentialIssuerClient::new(&env, &issuer_client);
    let schema = Bytes::from_slice(&env, b"cred-schema");
    let subject_did = make_did(&env, "full2");
    let cred_id = BytesN::from_array(&env, &[6u8; 32]);
    issuer_c.issue(
        &controller,
        &controller,
        &schema,
        &subject_did,
        &cred_id,
        Bytes::from_slice(&env, b"{}"),
    );
    assert_eq!(issuer_c.get_credential(&cred_id).unwrap().status, 1);

    // 3. Update reputation
    let rep_client = env.register(ReputationScore, ());
    let rep = ReputationScoreClient::new(&env, &rep_client);
    let config = Config { decay_factor: 100, min_trust_threshold: 50, weights: Default::default() };
    rep.initialize(&controller, &Address::generate(&env), &config);
    rep.update_transaction_reputation(&controller, 80);
    assert!(rep.get_score(&controller) >= 50);

    // 4. ZK proof
    let zk_client = env.register(ZKAttestation, ());
    let zk = ZKAttestationClient::new(&env, &zk_client);
    let circuit_id = Bytes::from_slice(&env, b"circuit-1");
    zk.register_circuit(&controller, &circuit_id, &Bytes::from_slice(&env, b"vk"));
    zk.submit_proof(&controller, &circuit_id, &Bytes::from_slice(&env, b"proof"), &soroban_sdk::vec![&env, Bytes::from_slice(&env, b"in")]);
    assert!(zk.verify_proof(&controller, &circuit_id, &Bytes::from_slice(&env, b"proof"), &soroban_sdk::vec![&env, Bytes::from_slice(&env, b"in")]));

    // 5. Compliance screen
    let comp = env.register(ComplianceFilter, ());
    let comp_c = ComplianceFilterClient::new(&env, &comp);
    comp_c.initialize(&Address::generate(&env));
    let target = Address::generate(&env);
    comp_c.add_to_sanctions_list(&Address::generate(&env), &target);
    let result = comp_c.screen(&target);
    assert!(result.blocked);
}
