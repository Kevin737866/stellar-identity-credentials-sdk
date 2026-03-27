pub mod did_registry;
pub mod credential_issuer;
pub mod reputation_score;
pub mod zk_attestation;
pub mod compliance_filter;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec};

pub use did_registry::DIDRegistry;
pub use credential_issuer::CredentialIssuer;
pub use reputation_score::ReputationScore;
pub use zk_attestation::ZKAttestation;
pub use compliance_filter::ComplianceFilter;

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
    pub claims: Bytes,
    pub issuance_date: u64,
    pub expiration_date: Option<u64>,
    pub parent_credential: Option<Bytes>,
    pub schema_id: Option<Bytes>,
    pub revocation: Option<Bytes>,
    pub proof: Option<Bytes>,
}

#[contract]
pub struct StellarIdentity;

#[contractimpl]
impl StellarIdentity {
    pub fn initialize(
        env: Env,
        did_registry_address: Address,
        credential_issuer_address: Address,
        reputation_score_address: Address,
        zk_attestation_address: Address,
        compliance_filter_address: Address,
    ) {
        env.storage().instance().set(&Symbol::new(&env, "did_registry"), &did_registry_address);
        env.storage().instance().set(&Symbol::new(&env, "credential_issuer"), &credential_issuer_address);
        env.storage().instance().set(&Symbol::new(&env, "reputation_score"), &reputation_score_address);
        env.storage().instance().set(&Symbol::new(&env, "zk_attestation"), &zk_attestation_address);
        env.storage().instance().set(&Symbol::new(&env, "compliance_filter"), &compliance_filter_address);
    }

    pub fn get_did_registry_address(env: Env) -> Address {
        env.storage().instance().get(&Symbol::new(&env, "did_registry")).unwrap()
    }

    pub fn get_credential_issuer_address(env: Env) -> Address {
        env.storage().instance().get(&Symbol::new(&env, "credential_issuer")).unwrap()
    }

    pub fn get_reputation_score_address(env: Env) -> Address {
        env.storage().instance().get(&Symbol::new(&env, "reputation_score")).unwrap()
    }

    pub fn get_zk_attestation_address(env: Env) -> Address {
        env.storage().instance().get(&Symbol::new(&env, "zk_attestation")).unwrap()
    }

    pub fn get_compliance_filter_address(env: Env) -> Address {
        env.storage().instance().get(&Symbol::new(&env, "compliance_filter")).unwrap()
    }
}
