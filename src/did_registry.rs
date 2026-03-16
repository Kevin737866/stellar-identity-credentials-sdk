use soroban_sdk::{
    contract, contracterror, contractimpl, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::{DIDDocument, Service, VerificationMethod};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DIDRegistryError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidFormat = 4,
    Expired = 5,
}

#[contract]
pub struct DIDRegistry;

#[contractimpl]
impl DIDRegistry {
    /// Create a new DID document for a Stellar address
    /// DID format: did:stellar:<stellar_address>
    pub fn create_did(
        env: Env,
        controller: Address,
        verification_methods: Vec<VerificationMethod>,
        services: Vec<Service>,
    ) -> Result<(), DIDRegistryError> {
        // Verify controller authorization
        controller.require_auth();

        // Generate DID from Stellar address
        let did = Self::generate_did(&env, &controller);

        // Check if DID already exists
        if env.storage().persistent().has(&did) {
            return Err(DIDRegistryError::AlreadyExists);
        }

        // Create DID document
        let now = env.ledger().timestamp();
        let did_document = DIDDocument {
            id: did.clone(),
            controller: controller.clone(),
            verification_method: verification_methods.to_vec(&env),
            authentication: Vec::new(&env), // Will be populated separately
            service: services.to_vec(&env),
            created: now,
            updated: now,
        };

        // Store DID document
        env.storage().persistent().set(&did, &did_document);

        // Store reverse mapping from controller to DID
        env.storage().persistent().set(&controller, &did);

        Ok(())
    }

    /// Resolve a DID document
    pub fn resolve_did(env: Env, did: Bytes) -> Result<DIDDocument, DIDRegistryError> {
        let did_document: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        // Check if document has expired (if expiration is set)
        if let Some(expiration) = did_document.verification_method.first().and_then(|vm| {
            // This is a simplified check - in practice, you'd have a separate expiration field
            None
        }) {
            if env.ledger().timestamp() > *expiration {
                return Err(DIDRegistryError::Expired);
            }
        }

        Ok(did_document)
    }

    /// Update DID document
    pub fn update_did(
        env: Env,
        controller: Address,
        verification_methods: Option<Vec<VerificationMethod>>,
        services: Option<Vec<Service>>,
    ) -> Result<(), DIDRegistryError> {
        // Verify controller authorization
        controller.require_auth();

        // Get existing DID
        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut did_document: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        // Update verification methods if provided
        if let Some(new_methods) = verification_methods {
            did_document.verification_method = new_methods.to_vec(&env);
        }

        // Update services if provided
        if let Some(new_services) = services {
            did_document.service = new_services.to_vec(&env);
        }

        // Update timestamp
        did_document.updated = env.ledger().timestamp();

        // Store updated document
        env.storage().persistent().set(&did, &did_document);

        Ok(())
    }

    /// Deactivate a DID document
    pub fn deactivate_did(env: Env, controller: Address) -> Result<(), DIDRegistryError> {
        // Verify controller authorization
        controller.require_auth();

        // Get DID from controller
        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        // Remove DID document
        env.storage().persistent().remove(&did);

        // Remove reverse mapping
        env.storage().persistent().remove(&controller);

        Ok(())
    }

    /// Add authentication method to DID
    pub fn add_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        // Verify controller authorization
        controller.require_auth();

        // Get existing DID
        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut did_document: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        // Add authentication method
        did_document.authentication.push_back(authentication_method);

        // Update timestamp
        did_document.updated = env.ledger().timestamp();

        // Store updated document
        env.storage().persistent().set(&did, &did_document);

        Ok(())
    }

    /// Remove authentication method from DID
    pub fn remove_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        // Verify controller authorization
        controller.require_auth();

        // Get existing DID
        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut did_document: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        // Remove authentication method
        let mut found = false;
        let mut new_auth = Vec::new(&env);
        for auth in did_document.authentication.iter() {
            if auth != authentication_method {
                new_auth.push_back(auth);
            } else {
                found = true;
            }
        }

        if !found {
            return Err(DIDRegistryError::NotFound);
        }

        did_document.authentication = new_auth;
        did_document.updated = env.ledger().timestamp();

        // Store updated document
        env.storage().persistent().set(&did, &did_document);

        Ok(())
    }

    /// Check if a DID exists
    pub fn did_exists(env: Env, did: Bytes) -> bool {
        env.storage().persistent().has(&did)
    }

    /// Get DID for a controller address
    pub fn get_controller_did(env: Env, controller: Address) -> Option<Bytes> {
        env.storage().persistent().get(&controller)
    }

    /// Generate DID from Stellar address
    fn generate_did(env: &Env, address: &Address) -> Bytes {
        let stellar_address = address.to_string();
        let did_string = format!("did:stellar:{}", stellar_address);
        Bytes::from_slice(env, did_string.as_bytes())
    }

    /// Validate DID format
    pub fn validate_did_format(did: &Bytes) -> bool {
        let did_str = String::from_utf8_lossy(did.to_array().as_slice());
        did_str.starts_with("did:stellar:")
    }

    /// Get all DIDs (for admin purposes)
    pub fn get_all_dids(env: Env) -> Vec<Bytes> {
        // This would require a more complex implementation with tracking
        // For now, return empty vector
        Vec::new(&env)
    }
}
