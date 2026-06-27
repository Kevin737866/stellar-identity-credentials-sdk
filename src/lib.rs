extern crate alloc;

pub mod admin;
pub mod audit_trail;
pub mod compliance_filter;
pub mod credential_issuer;
pub mod credential_offer;
pub mod did_recovery;
pub mod did_registry;
pub mod gas_benchmark;
pub mod performance_optimizer;
pub mod rate_limiter;
pub mod reentrancy_guard;
pub mod reputation_oracle;
pub mod reputation_score;
pub mod schema_registry;
pub mod status_list;
pub mod storage_optimization;
pub mod zk_attestation;

#[cfg(test)]
mod fuzz_test_script;
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod e2e_identity_lifecycle;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec};

pub use compliance_filter::ComplianceFilter;
pub use compliance_filter::RiskAssessment;
pub use compliance_filter::RiskFactor;
pub use compliance_filter::RiskLevel;
pub use credential_issuer::CredentialIssuer;
pub use credential_offer::CredentialOffer;
pub use credential_offer::CredentialOfferContract;
pub use credential_offer::CredentialOfferError;
pub use credential_offer::OfferStatus;
pub use credential_offer::OfferStatusCode;
pub use credential_offer::PaginatedOffers;
pub use did_recovery::DIDRecovery;
pub use did_recovery::DIDRecoveryError;
pub use did_recovery::GuardianRecord;
pub use did_recovery::RecoveryConfig;
pub use did_recovery::RecoveryMethod;
pub use did_recovery::RecoveryRequest;
pub use did_recovery::RecoveryRequestStatus;
pub use did_registry::DIDRegistry;
pub use did_registry::MultiSigConfig;
pub use did_registry::PendingMultiSigOperation;
pub use did_registry::Signer;
pub use reputation_oracle::DisputeStatus;
pub use reputation_oracle::OracleDataFeed;
pub use reputation_oracle::OracleDispute;
pub use reputation_oracle::OracleRecord;
pub use reputation_oracle::OracleStatus;
pub use reputation_oracle::PaginatedFeeds;
pub use reputation_oracle::ReputationOracle;
pub use reputation_oracle::ReputationOracleError;
pub use reputation_score::ReputationScore;
pub use admin::AdminError;
pub use schema_registry::CredentialSchemaRegistry;
pub use status_list::BitstringStatusList;
pub use status_list::StatusListError;
pub use status_list::StatusListMeta;
pub use zk_attestation::ZKAttestationContract;
pub use zk_attestation::ZKAttestationContractClient;
pub use zk_attestation::ZKAttestationRecord;
pub use zk_attestation::SelectiveDisclosureProof;
pub use zk_attestation::PredicateType;
pub use zk_attestation::PredicateInfo;
pub use zk_attestation::CombinedDisclosureProof;

pub use status_list::BitstringStatusList;
pub use status_list::StatusListError;
pub use status_list::StatusListMeta;

#[contracttype]
#[derive(Clone)]
pub struct DIDDocument {
    pub id: Bytes,
    pub controller: Address,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<Bytes>,
    pub service: Vec<Service>,
    pub created: u64,
    pub updated: u64,
    pub deactivated: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct CredentialSchema {
    pub id: Bytes,
    pub issuer: Address,
    pub version: u32,
    pub definition: Bytes,
    pub created: u64,
    pub updated: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct VerificationMethod {
    pub id: Bytes,
    pub type_: Bytes,
    pub controller: Address,
    pub public_key: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub struct Service {
    pub id: Bytes,
    pub type_: Bytes,
    pub endpoint: Bytes,
}

#[contracttype]
#[derive(Clone)]
pub struct VerifiableCredential {
    pub id: Bytes,
    pub issuer: Address,
    pub subject: Address,
    pub type_: Vec<Bytes>,
    pub credential_data: Bytes,
    pub issuance_date: u64,
    pub expiration_date: Option<u64>,
    pub schema_id: Option<Bytes>,
    pub revocation: Option<Bytes>,
    pub proof: Option<Bytes>,
}

// ---------------------------------------------------------------------------
// Pagination (#56)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedCredentials {
    pub data: Vec<Bytes>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedAddresses {
    pub data: Vec<Address>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedCircuits {
    pub data: Vec<Symbol>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedReputationHistory {
    pub data: Vec<reputation_score::ReputationHistoryEntry>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

pub const DEFAULT_PAGE_SIZE: u32 = 10;
pub const MAX_PAGE_SIZE: u32 = 50;

pub fn clamp_page_size(page_size: u32) -> u32 {
    if page_size == 0 {
        DEFAULT_PAGE_SIZE
    } else if page_size > MAX_PAGE_SIZE {
        MAX_PAGE_SIZE
    } else {
        page_size
    }
}

// ---------------------------------------------------------------------------
// Storage key namespacing (#58) — avoids collisions across contracts
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub enum StorageKey {
    DidRegistry,
    CredentialIssuer,
    SchemaRegistry,
    PresentationManager,
    ReputationScore,
    ZkAttestation,
    ComplianceFilter,
}

// ---------------------------------------------------------------------------
// Verifiable Presentation (W3C) — #95
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct VerifiablePresentation {
    pub id: Bytes,
    pub holder: Address,
    pub credentials: Vec<Bytes>,
    pub type_: Vec<Bytes>,
    pub proof: Option<Bytes>,
    pub created: u64,
    pub expires_at: Option<u64>,
}

#[contracttype]
#[derive(Clone)]
pub struct PresentationRequest {
    pub id: Bytes,
    pub verifier: Address,
    pub query: Vec<Bytes>,
    pub challenge: Bytes,
    pub domain: Option<Bytes>,
    pub expires_at: Option<u64>,
    pub created: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct PresentationResponse {
    pub request_id: Bytes,
    pub presentation_id: Bytes,
    pub responder: Address,
    pub created: u64,
}

#[contract]
pub struct StellarIdentity;

#[contractimpl]
impl StellarIdentity {
    pub fn initialize(
        env: Env,
        did_registry_address: Address,
        credential_issuer_address: Address,
        schema_registry_address: Address,
        presentation_manager_address: Address,
        reputation_score_address: Address,
        zk_attestation_address: Address,
        compliance_filter_address: Address,
    ) {
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "did_registry"), &did_registry_address);
        env.storage().instance().set(
            &Symbol::new(&env, "credential_issuer"),
            &credential_issuer_address,
        );
        env.storage().instance().set(
            &Symbol::new(&env, "schema_registry"),
            &schema_registry_address,
        );
        env.storage().instance().set(
            &Symbol::new(&env, "reputation_score"),
            &reputation_score_address,
        );
        env.storage().instance().set(
            &Symbol::new(&env, "zk_attestation"),
            &zk_attestation_address,
        );
        env.storage().instance().set(
            &Symbol::new(&env, "compliance_filter"),
            &compliance_filter_address,
        );
    }

    pub fn get_did_registry_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::DidRegistry)
    }

    pub fn get_credential_issuer_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::CredentialIssuer)
    }

    pub fn get_schema_registry_address(env: Env) -> Option<Address> {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "schema_registry"))
    }

    pub fn get_reputation_score_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::ReputationScore)
    }

    pub fn get_zk_attestation_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::ZkAttestation)
    }

    pub fn get_compliance_filter_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&StorageKey::ComplianceFilter)
    }
}
