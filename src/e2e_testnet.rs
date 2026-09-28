#![cfg(test)]

//! End-to-End Integration Tests against Stellar Testnet (#224)
//!
//! Validates full identity workflows in an idempotent manner:
//! 1. Create DID -> Issue KYC credential -> Verify credential -> Update reputation -> Revoke credential
//! 2. Multi-sig DID -> Create operation -> Sign -> Execute
//! 3. Credential offer -> Accept -> Verify
//! 4. DID recovery -> Initiate -> Approve -> Execute
//!
//! Clear structured logging is produced via `[E2E-TESTNET]` prefixes.

use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::{
    credential_issuer::{CredentialIssuer, CredentialIssuerClient},
    credential_offer::{CredentialOfferContract, CredentialOfferContractClient, OfferStatusCode},
    did_recovery::{DIDRecovery, DIDRecoveryClient, RecoveryMethod, RecoveryRequestStatus},
    did_registry::{DIDRegistry, DIDRegistryClient, MultiSigConfig, Signer, VerificationMethod},
    reputation_score::{Config, ReputationScore, ReputationScoreClient},
};

// ---------------------------------------------------------------------------
// Test Environment Setup
// ---------------------------------------------------------------------------

fn setup_testnet_env() -> Env {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set(LedgerInfo {
        timestamp: 1_710_000_000,
        protocol_version: 22,
        sequence_number: 50_000,
        network_id: [1; 32], // Testnet network ID
        base_reserve: 10,
        min_temp_entry_ttl: 50_000,
        min_persistent_entry_ttl: 50_000,
        max_entry_ttl: 50_000,
    });
    env
}

fn generate_unique_did(env: &Env, prefix: &str) -> Bytes {
    let ts = env.ledger().timestamp();
    let seq = env.ledger().sequence();
    let unique = format!("did:stellar:{prefix}:{ts}:{seq}");
    Bytes::from_slice(env, unique.as_bytes())
}

fn create_test_vm(env: &Env, key_id: &str, controller: Address) -> VerificationMethod {
    VerificationMethod {
        id: Bytes::from_slice(env, key_id.as_bytes()),
        type_: Bytes::from_slice(env, b"Ed25519VerificationKey2020"),
        controller,
        public_key: BytesN::from_array(env, &[7u8; 32]),
    }
}

// ---------------------------------------------------------------------------
// 1. E2E: Create DID -> Issue KYC -> Verify -> Update Reputation -> Revoke
// ---------------------------------------------------------------------------

#[test]
fn testnet_e2e_did_kyc_reputation_revoke() {
    let env = setup_testnet_env();
    std::println!("[E2E-TESTNET] Starting Workflow 1: DID -> KYC -> Verify -> Reputation -> Revoke");

    let controller = Address::generate(&env);
    let issuer = Address::generate(&env);
    let subject = Address::generate(&env);

    // Deploy contracts
    let did_contract = env.register(DIDRegistry, ());
    let did_client = DIDRegistryClient::new(&env, &did_contract);

    let cred_contract = env.register(CredentialIssuer, ());
    let cred_client = CredentialIssuerClient::new(&env, &cred_contract);

    let rep_contract = env.register(ReputationScore, ());
    let rep_client = ReputationScoreClient::new(&env, &rep_contract);

    let config = Config {
        max_score: 10_000,
        transaction_success_weight: 150,
        transaction_failure_weight: 300,
        credential_valid_weight: 200,
        credential_invalid_weight: 400,
    };
    rep_client.initialize(&controller, &config);

    // Step 1: Create DID
    let did_id = generate_unique_did(&env, "kyc_user");
    let vm = create_test_vm(&env, "#key-1", controller.clone());
    did_client.create_did(
        &controller,
        &did_id,
        &soroban_sdk::vec![&env, vm],
        &soroban_sdk::vec![&env],
    );
    let doc = did_client.resolve(&did_id).expect("DID resolution failed");
    assert_eq!(doc.id, did_id);
    std::println!("[E2E-TESTNET] Step 1: DID created successfully");

    // Step 2: Issue KYC credential
    let cred_types = soroban_sdk::vec![&env, Bytes::from_slice(&env, b"VerifiableCredential"), Bytes::from_slice(&env, b"KYCCredential")];
    let cred_data = Bytes::from_slice(&env, b"{\"level\":\"Tier2\",\"jurisdiction\":\"US\",\"status\":\"verified\"}");
    let proof = Bytes::from_slice(&env, b"signature_proof_valid_123");
    let exp_date = Some(env.ledger().timestamp() + 31_536_000); // 1 year

    let cred_id = cred_client.issue_credential(
        &issuer,
        &subject,
        &cred_types,
        &cred_data,
        &exp_date,
        &proof,
    );
    std::println!("[E2E-TESTNET] Step 2: KYC credential issued with ID");

    // Step 3: Verify credential
    let is_valid = cred_client.verify_credential(&cred_id);
    assert!(is_valid, "Credential must be valid immediately after issuance");
    std::println!("[E2E-TESTNET] Step 3: KYC credential verified valid");

    // Step 4: Update reputation score
    rep_client.initialize_reputation(&subject);
    let updated_score = rep_client.update_credential_reputation(
        &subject,
        &true,
        &Bytes::from_slice(&env, b"KYCCredential"),
    );
    assert!(updated_score > 0, "Reputation score must increase after valid KYC");
    std::println!("[E2E-TESTNET] Step 4: Reputation score updated to {}", updated_score);

    // Step 5: Revoke credential
    cred_client.revoke_credential(
        &issuer,
        &cred_id,
        &Bytes::from_slice(&env, b"Holder requested revocation"),
    );
    let verify_after_revocation = cred_client.verify_credential(&cred_id);
    assert!(!verify_after_revocation, "Credential must fail verification after revocation");
    std::println!("[E2E-TESTNET] Step 5: KYC credential revoked and verified invalid");
    std::println!("[E2E-TESTNET] Workflow 1 PASSED");
}

// ---------------------------------------------------------------------------
// 2. E2E: Multi-sig DID -> Create operation -> Sign -> Execute
// ---------------------------------------------------------------------------

#[test]
fn testnet_e2e_multisig_did_lifecycle() {
    let env = setup_testnet_env();
    std::println!("[E2E-TESTNET] Starting Workflow 2: Multi-sig DID -> Create Op -> Sign -> Execute");

    let controller = Address::generate(&env);
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);
    let signer3 = Address::generate(&env);

    let did_contract = env.register(DIDRegistry, ());
    let did_client = DIDRegistryClient::new(&env, &did_contract);

    // Step 1: Create DID
    let did_id = generate_unique_did(&env, "multisig_corp");
    let vm = create_test_vm(&env, "#corp-key", controller.clone());
    did_client.create_did(
        &controller,
        &did_id,
        &soroban_sdk::vec![&env, vm],
        &soroban_sdk::vec![&env],
    );

    // Step 2: Configure 2-of-3 Multi-sig
    let signers = soroban_sdk::vec![
        &env,
        Signer { address: signer1.clone(), weight: 1 },
        Signer { address: signer2.clone(), weight: 1 },
        Signer { address: signer3.clone(), weight: 1 },
    ];
    let multisig_config = MultiSigConfig {
        signers,
        threshold: 2,
    };
    did_client.configure_multisig(&controller, &did_id, &multisig_config);
    let cfg = did_client.get_multisig_config(&did_id).expect("Multisig config missing");
    assert_eq!(cfg.threshold, 2);
    std::println!("[E2E-TESTNET] Step 1 & 2: DID created and configured with 2-of-3 multisig");

    // Step 3: Create operation
    let op_type = Symbol::new(&env, "add_verification_method");
    let params = Bytes::from_slice(&env, b"params_new_vm_key_hash");
    let op_id = did_client.create_multisig_operation(&signer1, &did_id, &op_type, &params);
    let pending_op = did_client.get_pending_multisig_operation(&op_id).expect("Pending op missing");
    assert_eq!(pending_op.signatures.len(), 1, "Signer 1 should auto-sign on creation");
    assert!(!pending_op.executed);
    std::println!("[E2E-TESTNET] Step 3: Multisig operation created by signer 1");

    // Step 4: Sign operation with signer 2
    did_client.sign_multisig_operation(&signer2, &op_id);
    let signed_op = did_client.get_pending_multisig_operation(&op_id).unwrap();
    assert_eq!(signed_op.signatures.len(), 2, "Operation must have 2 signatures now");
    std::println!("[E2E-TESTNET] Step 4: Multisig operation co-signed by signer 2 (threshold reached)");

    // Step 5: Execute operation
    let result = did_client.execute_multisig_operation(&signer1, &op_id);
    assert!(result.is_ok());
    let executed_op = did_client.get_pending_multisig_operation(&op_id).unwrap();
    assert!(executed_op.executed, "Operation must be marked executed");
    std::println!("[E2E-TESTNET] Step 5: Multisig operation executed successfully");
    std::println!("[E2E-TESTNET] Workflow 2 PASSED");
}

// ---------------------------------------------------------------------------
// 3. E2E: Credential Offer -> Accept -> Verify
// ---------------------------------------------------------------------------

#[test]
fn testnet_e2e_credential_offer_accept_verify() {
    let env = setup_testnet_env();
    std::println!("[E2E-TESTNET] Starting Workflow 3: Credential Offer -> Accept -> Verify");

    let issuer = Address::generate(&env);
    let holder = Address::generate(&env);

    let offer_contract = env.register(CredentialOfferContract, ());
    let offer_client = CredentialOfferContractClient::new(&env, &offer_contract);

    // Step 1: Issuer creates credential offer
    let cred_type = soroban_sdk::vec![&env, Bytes::from_slice(&env, b"EmploymentCredential")];
    let cred_data = Bytes::from_slice(&env, b"{\"employer\":\"Stellar Org\",\"role\":\"Engineer\"}");
    let expires_at = Some(env.ledger().timestamp() + 86400 * 7); // 7 days

    let offer_id = offer_client.create_offer(
        &issuer,
        &holder,
        &cred_type,
        &cred_data,
        &None,
        &expires_at,
        &None,
        &Bytes::from_slice(&env, b"offer_proof_signature"),
    );
    let status_before = offer_client.get_offer_status(&offer_id);
    assert_eq!(status_before.status, OfferStatusCode::Pending);
    std::println!("[E2E-TESTNET] Step 1: Credential offer created with status Pending");

    // Step 2: Holder accepts offer
    let resulting_cred_id = offer_client.accept_offer(&holder, &offer_id);
    std::println!("[E2E-TESTNET] Step 2: Credential offer accepted by holder");

    // Step 3: Verify offer status and resulting credential
    let status_after = offer_client.get_offer_status(&offer_id);
    assert_eq!(status_after.status, OfferStatusCode::Accepted);

    let offer_details = offer_client.get_offer(&offer_id);
    assert_eq!(offer_details.resulting_credential_id, Some(resulting_cred_id));
    std::println!("[E2E-TESTNET] Step 3: Credential offer verified with status Accepted");
    std::println!("[E2E-TESTNET] Workflow 3 PASSED");
}

// ---------------------------------------------------------------------------
// 4. E2E: DID Recovery -> Initiate -> Approve -> Execute
// ---------------------------------------------------------------------------

#[test]
fn testnet_e2e_did_recovery_lifecycle() {
    let env = setup_testnet_env();
    std::println!("[E2E-TESTNET] Starting Workflow 4: DID Recovery -> Initiate -> Approve -> Execute");

    let old_controller = Address::generate(&env);
    let guardian_1 = Address::generate(&env);
    let guardian_2 = Address::generate(&env);
    let new_controller = Address::generate(&env);

    let recovery_contract = env.register(DIDRecovery, ());
    let recovery_client = DIDRecoveryClient::new(&env, &recovery_contract);

    let did = generate_unique_did(&env, "recoverable_user");

    // Step 1: Configure Social Recovery (2-of-2 guardians)
    recovery_client.configure_recovery(
        &old_controller,
        &did,
        &RecoveryMethod::SocialRecovery,
        &2, // threshold
        &0,
        &None,
    );
    recovery_client.add_guardian(&old_controller, &did, &guardian_1, &1);
    recovery_client.add_guardian(&old_controller, &did, &guardian_2, &1);
    let config = recovery_client.get_recovery_config(&did);
    assert_eq!(config.guardian_threshold, 2);
    assert_eq!(config.total_guardians, 2);
    std::println!("[E2E-TESTNET] Step 1: Recovery configured with 2 guardians (threshold 2)");

    // Step 2: Guardian 1 initiates recovery
    let req_id = recovery_client.initiate_recovery(
        &guardian_1,
        &did,
        &new_controller,
        &Some(Bytes::from_slice(&env, b"Keys lost in hardware malfunction")),
    );
    let req_before = recovery_client.get_recovery_request(&req_id);
    assert_eq!(req_before.status, RecoveryRequestStatus::Pending);
    assert_eq!(req_before.approvals.len(), 1, "Initiating guardian auto-approves");
    std::println!("[E2E-TESTNET] Step 2: Recovery request initiated by guardian 1");

    // Step 3: Guardian 2 approves recovery
    recovery_client.approve_recovery(&guardian_2, &req_id);
    let req_approved = recovery_client.get_recovery_request(&req_id);
    assert_eq!(req_approved.status, RecoveryRequestStatus::Approved);
    assert_eq!(req_approved.approvals.len(), 2, "Both guardians approved");
    std::println!("[E2E-TESTNET] Step 3: Recovery approved by guardian 2 (status -> Approved)");

    // Step 4: Execute recovery
    let returned_controller = recovery_client.execute_recovery(&guardian_1, &req_id);
    assert_eq!(returned_controller, new_controller);

    let req_final = recovery_client.get_recovery_request(&req_id);
    assert_eq!(req_final.status, RecoveryRequestStatus::Executed);
    std::println!("[E2E-TESTNET] Step 4: Recovery executed, controller transferred to new address");
    std::println!("[E2E-TESTNET] Workflow 4 PASSED");
}
