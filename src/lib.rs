pub mod did_registry;
pub mod credential_issuer;
pub mod schema_registry;
pub mod reputation_score;
pub mod zk_attestation;
pub mod compliance_filter;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec};
use core::fmt::Write;

pub use did_registry::DIDRegistry;
pub use credential_issuer::CredentialIssuer;
pub use schema_registry::CredentialSchemaRegistry;
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
        schema_registry_address: Address,
        reputation_score_address: Address,
        zk_attestation_address: Address,
        compliance_filter_address: Address,
    ) {
        env.storage().instance().set(&Symbol::new(&env, "did_registry"), &did_registry_address);
        env.storage().instance().set(&Symbol::new(&env, "credential_issuer"), &credential_issuer_address);
        env.storage().instance().set(&Symbol::new(&env, "schema_registry"), &schema_registry_address);
        env.storage().instance().set(&Symbol::new(&env, "reputation_score"), &reputation_score_address);
        env.storage().instance().set(&Symbol::new(&env, "zk_attestation"), &zk_attestation_address);
        env.storage().instance().set(&Symbol::new(&env, "compliance_filter"), &compliance_filter_address);
    }

    pub fn get_did_registry_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&Symbol::new(&env, "did_registry"))
    }

    pub fn get_credential_issuer_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&Symbol::new(&env, "credential_issuer"))
    }

    pub fn get_schema_registry_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&Symbol::new(&env, "schema_registry"))
    }

    pub fn get_reputation_score_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&Symbol::new(&env, "reputation_score"))
    }

    pub fn get_zk_attestation_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&Symbol::new(&env, "zk_attestation"))
    }

    pub fn get_compliance_filter_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&Symbol::new(&env, "compliance_filter"))
    }
}
