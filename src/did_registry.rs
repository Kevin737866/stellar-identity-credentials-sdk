use soroban_sdk::{
    contract, contracterror, contractimpl, Address, Bytes, BytesN, Env, Vec,
};

use crate::{DIDDocument, Service, VerificationMethod};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DIDRegistryError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidFormat = 4,
    Deactivated = 5,
    InvalidSignature = 6,
}

#[contract]
pub struct DIDRegistry;

#[contractimpl]
impl DIDRegistry {
    /// Register a new DID anchored to a Stellar account.
    ///
    /// `did_id` is the full DID string as UTF-8 bytes, e.g.
    /// `b"did:stellar:GAA...4Z"` or `b"did:stellar:GAA...4Z:entity-123"`.
    /// The client SDK computes this from the Stellar public key.
    pub fn create_did(
        env: Env,
        controller: Address,
        did_id: Bytes,
        verification_methods: Vec<VerificationMethod>,
        services: Vec<Service>,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        if !Self::check_did_prefix(&env, &did_id) {
            return Err(DIDRegistryError::InvalidFormat);
        }

        if env.storage().persistent().has(&did_id) {
            return Err(DIDRegistryError::AlreadyExists);
        }

        let now = env.ledger().timestamp();
        let doc = DIDDocument {
            id: did_id.clone(),
            controller: controller.clone(),
            verification_method: verification_methods,
            authentication: Vec::new(&env),
            service: services,
            created: now,
            updated: now,
            deactivated: false,
        };

        env.storage().persistent().set(&did_id, &doc);
        env.storage().persistent().set(&controller, &did_id);

        Ok(())
    }

    /// Resolve a DID document by its DID string.
    /// Returns the document even when deactivated (W3C DID Core §7.1.2).
    pub fn resolve_did(env: Env, did: Bytes) -> Result<DIDDocument, DIDRegistryError> {
        env.storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)
    }

    /// Update verification methods and/or service endpoints.
    /// Deactivated DIDs cannot be updated.
    pub fn update_did(
        env: Env,
        controller: Address,
        verification_methods: Option<Vec<VerificationMethod>>,
        services: Option<Vec<Service>>,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        if let Some(methods) = verification_methods {
            doc.verification_method = methods;
        }
        if let Some(svcs) = services {
            doc.service = svcs;
        }

        doc.updated = env.ledger().timestamp();
        env.storage().persistent().set(&did, &doc);

        Ok(())
    }

    /// Soft-delete a DID document (tombstone).
    /// The document is preserved on-chain with `deactivated = true` for audit.
    pub fn deactivate_did(env: Env, controller: Address) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        doc.deactivated = true;
        doc.updated = env.ledger().timestamp();
        env.storage().persistent().set(&did, &doc);

        Ok(())
    }

    /// Add a verification method fragment ID to the authentication array.
    pub fn add_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        doc.authentication.push_back(authentication_method);
        doc.updated = env.ledger().timestamp();
        env.storage().persistent().set(&did, &doc);

        Ok(())
    }

    /// Remove a verification method fragment ID from the authentication array.
    pub fn remove_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&controller)
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let mut found = false;
        let mut new_auth: Vec<Bytes> = Vec::new(&env);
        for auth in doc.authentication.iter() {
            if auth != authentication_method {
                new_auth.push_back(auth);
            } else {
                found = true;
            }
        }

        if !found {
            return Err(DIDRegistryError::NotFound);
        }

        doc.authentication = new_auth;
        doc.updated = env.ledger().timestamp();
        env.storage().persistent().set(&did, &doc);

        Ok(())
    }

    /// Verify an ed25519 signature using the DID's primary verification key.
    ///
    /// `env.crypto().ed25519_verify()` panics (rolls back the transaction)
    /// if the signature is invalid — this is the correct on-chain behaviour.
    pub fn verify_signature(
        env: Env,
        did: Bytes,
        message: Bytes,
        signature: BytesN<64>,
    ) -> Result<bool, DIDRegistryError> {
        let doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let vm = doc
            .verification_method
            .get(0)
            .ok_or(DIDRegistryError::NotFound)?;

        env.crypto().ed25519_verify(&vm.public_key, &message, &signature);

        Ok(true)
    }

    /// Verify an ed25519 signature using a specific verification method by index.
    pub fn verify_signature_with_method(
        env: Env,
        did: Bytes,
        message: Bytes,
        signature: BytesN<64>,
        method_index: u32,
    ) -> Result<bool, DIDRegistryError> {
        let doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&did)
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let vm = doc
            .verification_method
            .get(method_index)
            .ok_or(DIDRegistryError::NotFound)?;

        env.crypto().ed25519_verify(&vm.public_key, &message, &signature);

        Ok(true)
    }

    /// Returns `true` if a DID document exists (active or tombstoned).
    pub fn did_exists(env: Env, did: Bytes) -> bool {
        env.storage().persistent().has(&did)
    }

    /// Returns the DID Bytes for a given controller address, or `None`.
    pub fn get_controller_did(env: Env, controller: Address) -> Option<Bytes> {
        env.storage().persistent().get(&controller)
    }

    fn check_did_prefix(env: &Env, did: &Bytes) -> bool {
        let prefix = Bytes::from_slice(env, b"did:stellar:");
        let prefix_len = prefix.len();

        if did.len() < prefix_len {
            return false;
        }

        for i in 0..prefix_len {
            if did.get(i) != prefix.get(i) {
                return false;
            }
        }

        true
    }
}
