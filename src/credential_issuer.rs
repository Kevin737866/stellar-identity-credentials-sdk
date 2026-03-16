use soroban_sdk::{
    contract, contracterror, contractimpl, Address, Bytes, BytesN, Env, Symbol, Vec, Map,
};

use crate::VerifiableCredential;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum CredentialIssuerError {
    Unauthorized = 1,
    NotFound = 2,
    InvalidCredential = 3,
    AlreadyRevoked = 4,
    Expired = 5,
    InvalidSignature = 6,
    InvalidIssuer = 7,
}

#[contract]
pub struct CredentialIssuer;

#[contractimpl]
impl CredentialIssuer {
    /// Issue a new verifiable credential
    pub fn issue_credential(
        env: Env,
        issuer: Address,
        subject: Address,
        credential_type: Vec<Bytes>,
        credential_data: Bytes,
        expiration_date: Option<u64>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialIssuerError> {
        // Verify issuer authorization
        issuer.require_auth();

        // Generate credential ID
        let credential_id = Self::generate_credential_id(&env, &issuer, &subject);

        // Create verifiable credential
        let now = env.ledger().timestamp();
        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            type_: credential_type.to_vec(&env),
            credential_data: credential_data.clone(),
            issuance_date: now,
            expiration_date,
            revocation: None,
            proof: Some(proof.clone()),
        };

        // Validate credential
        Self::validate_credential(&env, &credential)?;

        // Store credential
        env.storage().persistent().set(&credential_id, &credential);

        // Add to issuer's credentials list
        let mut issuer_credentials: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&issuer)
            .unwrap_or_else(|| Vec::new(&env));
        issuer_credentials.push_back(credential_id.clone());
        env.storage().persistent().set(&issuer, &issuer_credentials);

        // Add to subject's credentials list
        let mut subject_credentials: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&subject)
            .unwrap_or_else(|| Vec::new(&env));
        subject_credentials.push_back(credential_id.clone());
        env.storage().persistent().set(&subject, &subject_credentials);

        // Store credential status
        env.storage().persistent().set(
            &Symbol::new(&env, &format!("status:{}", credential_id.to_string())),
            &Bytes::from_slice(&env, b"active"),
        );

        Ok(credential_id)
    }

    /// Verify a verifiable credential
    pub fn verify_credential(
        env: Env,
        credential_id: Bytes,
    ) -> Result<bool, CredentialIssuerError> {
        // Get credential
        let credential: VerifiableCredential = env
            .storage()
            .persistent()
            .get(&credential_id)
            .ok_or(CredentialIssuerError::NotFound)?;

        // Check if credential is revoked
        let status_key = Symbol::new(&env, &format!("status:{}", credential_id.to_string()));
        if let Some(status) = env.storage().persistent().get(&status_key) {
            if status == Bytes::from_slice(&env, b"revoked") {
                return Ok(false);
            }
        }

        // Check expiration
        if let Some(expiration) = credential.expiration_date {
            if env.ledger().timestamp() > expiration {
                return Ok(false);
            }
        }

        // Verify proof (simplified - in practice, you'd verify cryptographic signature)
        if let Some(proof) = credential.proof {
            Self::verify_proof(&env, &proof, &credential)?;
        }

        Ok(true)
    }

    /// Revoke a verifiable credential
    pub fn revoke_credential(
        env: Env,
        issuer: Address,
        credential_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<(), CredentialIssuerError> {
        // Verify issuer authorization
        issuer.require_auth();

        // Get credential
        let mut credential: VerifiableCredential = env
            .storage()
            .persistent()
            .get(&credential_id)
            .ok_or(CredentialIssuerError::NotFound)?;

        // Check if issuer is authorized
        if credential.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        // Check if already revoked
        let status_key = Symbol::new(&env, &format!("status:{}", credential_id.to_string()));
        if let Some(status) = env.storage().persistent().get(&status_key) {
            if status == Bytes::from_slice(&env, b"revoked") {
                return Err(CredentialIssuerError::AlreadyRevoked);
            }
        }

        // Update credential with revocation info
        credential.revocation = Some(Bytes::from_slice(&env, env.ledger().timestamp().to_string().as_bytes()));
        
        // Store updated credential
        env.storage().persistent().set(&credential_id, &credential);

        // Update status
        env.storage().persistent().set(&status_key, &Bytes::from_slice(&env, b"revoked"));

        // Store revocation reason if provided
        if let Some(reason_bytes) = reason {
            let reason_key = Symbol::new(&env, &format!("reason:{}", credential_id.to_string()));
            env.storage().persistent().set(&reason_key, &reason_bytes);
        }

        Ok(())
    }

    /// Get credential details
    pub fn get_credential(
        env: Env,
        credential_id: Bytes,
    ) -> Result<VerifiableCredential, CredentialIssuerError> {
        env.storage()
            .persistent()
            .get(&credential_id)
            .ok_or(CredentialIssuerError::NotFound)
    }

    /// Get all credentials for an issuer
    pub fn get_issuer_credentials(env: Env, issuer: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&issuer)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get all credentials for a subject
    pub fn get_subject_credentials(env: Env, subject: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&subject)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get credential status
    pub fn get_credential_status(env: Env, credential_id: Bytes) -> Bytes {
        let status_key = Symbol::new(&env, &format!("status:{}", credential_id.to_string()));
        env.storage()
            .persistent()
            .get(&status_key)
            .unwrap_or_else(|| Bytes::from_slice(&env, b"unknown"))
    }

    /// Batch verify multiple credentials
    pub fn batch_verify_credentials(
        env: Env,
        credential_ids: Vec<Bytes>,
    ) -> Vec<bool> {
        let mut results = Vec::new(&env);
        for credential_id in credential_ids.iter() {
            let is_valid = Self::verify_credential(env.clone(), credential_id.clone()).unwrap_or(false);
            results.push_back(is_valid);
        }
        results
    }

    /// Generate credential ID
    fn generate_credential_id(env: &Env, issuer: &Address, subject: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let id_string = format!("vc:{}:{}:{}", issuer.to_string(), subject.to_string(), timestamp);
        Bytes::from_slice(env, id_string.as_bytes())
    }

    /// Validate credential structure
    fn validate_credential(env: &Env, credential: &VerifiableCredential) -> Result<(), CredentialIssuerError> {
        // Check required fields
        if credential.credential_data.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }

        if credential.type_.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }

        // Validate proof format
        if let Some(proof) = &credential.proof {
            if proof.is_empty() {
                return Err(CredentialIssuerError::InvalidSignature);
            }
        }

        Ok(())
    }

    /// Verify credential proof (simplified implementation)
    fn verify_proof(env: &Env, proof: &Bytes, credential: &VerifiableCredential) -> Result<(), CredentialIssuerError> {
        // In practice, this would verify the cryptographic signature
        // For now, just check that proof exists and is not empty
        if proof.is_empty() {
            return Err(CredentialIssuerError::InvalidSignature);
        }
        Ok(())
    }

    /// Get revocation reason
    pub fn get_revocation_reason(env: Env, credential_id: Bytes) -> Option<Bytes> {
        let reason_key = Symbol::new(&env, &format!("reason:{}", credential_id.to_string()));
        env.storage().persistent().get(&reason_key)
    }

    /// Search credentials by type
    pub fn search_credentials_by_type(
        env: Env,
        credential_type: Bytes,
        max_results: u32,
    ) -> Vec<Bytes> {
        // This would require indexing by credential type
        // For now, return empty vector
        Vec::new(&env)
    }
}
