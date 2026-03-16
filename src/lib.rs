pub mod did_registry;
pub mod credential_issuer;
pub mod reputation_score;
pub mod zk_attestation;
pub mod compliance_filter;

use soroban_sdk::{contractimpl, Address, Env, Bytes, BytesN, Symbol};

// Re-export all contract types and functions
pub use did_registry::{DIDRegistry, DIDRegistryClient};
pub use credential_issuer::{CredentialIssuer, CredentialIssuerClient};
pub use reputation_score::{ReputationScore, ReputationScoreClient};
pub use zk_attestation::{ZKAttestation, ZKAttestationClient};
pub use compliance_filter::{ComplianceFilter, ComplianceFilterClient};

// Common types used across contracts
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DIDDocument {
    pub id: Bytes,
    pub controller: Address,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<Bytes>,
    pub service: Vec<Service>,
    pub created: u64,
    pub updated: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationMethod {
    pub id: Bytes,
    pub type_: Bytes,
    pub controller: Address,
    pub public_key: BytesN<32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    pub id: Bytes,
    pub type_: Bytes,
    pub endpoint: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiableCredential {
    pub id: Bytes,
    pub issuer: Address,
    pub subject: Address,
    pub type_: Vec<Bytes>,
    pub credential_data: Bytes,
    pub issuance_date: u64,
    pub expiration_date: Option<u64>,
    pub revocation: Option<Bytes>,
    pub proof: Option<Bytes>,
}

// Cross-contract interface constants
pub const DID_REGISTRY_CONTRACT: &str = "DID_REGISTRY";
pub const CREDENTIAL_ISSUER_CONTRACT: &str = "CREDENTIAL_ISSUER";
pub const REPUTATION_SCORE_CONTRACT: &str = "REPUTATION_SCORE";
pub const ZK_ATTESTATION_CONTRACT: &str = "ZK_ATTESTATION";
pub const COMPLIANCE_FILTER_CONTRACT: &str = "COMPLIANCE_FILTER";

// Main contract that coordinates all identity operations
pub struct StellarIdentity;

#[contractimpl]
impl StellarIdentity {
    /// Initialize all identity contracts with proper cross-contract references
    pub fn initialize(
        env: Env,
        did_registry_address: Address,
        credential_issuer_address: Address,
        reputation_score_address: Address,
        zk_attestation_address: Address,
        compliance_filter_address: Address,
    ) {
        // Store contract addresses for cross-contract calls
        env.storage().instance().set(&Symbol::new(&env, "did_registry"), &did_registry_address);
        env.storage().instance().set(&Symbol::new(&env, "credential_issuer"), &credential_issuer_address);
        env.storage().instance().set(&Symbol::new(&env, "reputation_score"), &reputation_score_address);
        env.storage().instance().set(&Symbol::new(&env, "zk_attestation"), &zk_attestation_address);
        env.storage().instance().set(&Symbol::new(&env, "compliance_filter"), &compliance_filter_address);
    }

    /// Get DID registry contract address
    pub fn get_did_registry_address(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "did_registry"))
            .unwrap()
    }

    /// Get credential issuer contract address
    pub fn get_credential_issuer_address(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "credential_issuer"))
            .unwrap()
    }

    /// Get reputation score contract address
    pub fn get_reputation_score_address(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "reputation_score"))
            .unwrap()
    }

    /// Get ZK attestation contract address
    pub fn get_zk_attestation_address(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "zk_attestation"))
            .unwrap()
    }

    /// Get compliance filter contract address
    pub fn get_compliance_filter_address(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(&env, "compliance_filter"))
            .unwrap()
    }
}
