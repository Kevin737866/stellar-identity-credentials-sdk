use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, log, Address, Bytes, Env, Map, Symbol, Vec,
};
use sha2::{Digest, Sha256};

// ── Confidential transactions and private credentials (#192, #193) ─────────

/// Length of a SHA-256 digest, which is what every commitment here must be.
const SHA256_DIGEST_LEN: u32 = 32;
const XLM_IN_STROOPS: u64 = 10_000_000;
/// Score a successful confidential transaction earns before any tier bonus.
const CONFIDENTIAL_BASE_SCORE: u32 = 1;
/// Declared tier magnitude that earns one bonus point.
const CONFIDENTIAL_SCORE_UNIT: u64 = 100 * XLM_IN_STROOPS;
/// Ceiling on the tier bonus, so a large tier cannot dominate scoring.
const MAX_CONFIDENTIAL_SCORE: u32 = 100;
/// Longest refresh chain `verify_credential_chain` will walk.
const MAX_REFRESH_DEPTH: u32 = 8;

const CONFIDENTIAL_TX_DOMAIN: &[u8] = b"confidential-tx-v1";
const CONFIDENTIAL_AMOUNT_DOMAIN: &[u8] = b"amount-v1";
const CREDENTIAL_DOMAIN: &[u8] = b"credential-v1";
const CREDENTIAL_COMMITMENT_DOMAIN: &[u8] = b"credential-commitment-v1";
const ATTRIBUTES_DOMAIN: &[u8] = b"attributes-v1";

const CONFIDENTIAL_POLICY: &str = "confidential_policy";
const CONFIDENTIAL_TIERED_COUNT: &str = "confidential_tiered_count";
const CONFIDENTIAL_HIDDEN_COUNT: &str = "confidential_hidden_count";
const CONFIDENTIAL_SCORE_TOTAL: &str = "confidential_score_total";

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PrivacyError {
    InvalidNullifier = 1,
    RevokedCredential = 2,
    InsufficientPrivacy = 3,
    DoubleSpending = 4,
    InvalidCommitment = 5,
    ContextMismatch = 6,
    /// Tier bounds are inverted, empty, or beyond the plausibility ceiling.
    InvalidRange = 7,
    /// No record for the supplied proof or credential id.
    UnknownCredential = 8,
    /// The ownership proof was absent or malformed.
    OwnershipProofFailed = 9,
    /// The refresh chain is longer than `MAX_REFRESH_DEPTH`.
    ChainTooDeep = 10,
    /// An argument was empty, zero, or already in the past.
    InvalidInput = 11,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct PrivacyConfig {
    pub min_anonymity_set_size: u32,
    pub nullifier_lifetime: u64,
    pub revocation_check_interval: u64,
    pub selective_disclosure_required: bool,
    pub zero_knowledge_verification: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct NullifierState {
    pub nullifier: Bytes,
    pub context: Bytes,
    pub created_at: u64,
    pub expires_at: u64,
    pub usage_count: u32,
    pub credential_commitment: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct RevocationProof {
    pub credential_commitment: Bytes,
    pub revocation_hash: Bytes,
    pub proof_valid_until: u64,
    pub anonymity_set_hash: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct SelectiveDisclosure {
    pub credential_id: Bytes,
    pub revealed_attributes: Vec<Symbol>,
    pub hidden_attributes: Vec<Symbol>,
    pub disclosure_hash: Bytes,
    pub validity_proof: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum TransactionPrivacyLevel {
    /// Amount written on-chain.
    Public = 1,
    /// Amount hidden; only the tier it falls into is recorded.
    Tiered = 2,
    /// Amount hidden and not bucketed either.
    Hidden = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ConfidentialPolicy {
    pub min_privacy_level: TransactionPrivacyLevel,
    pub max_tier_min: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct AmountRangeProof {
    pub proof_id: Bytes,
    pub tx_hash: Bytes,
    /// SHA-256 over the amount and its salt. The amount is never stored.
    pub amount_commitment: Bytes,
    pub tier_min: u64,
    pub tier_max: u64,
    pub privacy_level: TransactionPrivacyLevel,
    pub was_successful: bool,
    pub score_awarded: u32,
    pub created_at: u64,
    /// Set when a disclosure contradicted the claim and the score was clawed back.
    pub challenged_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct RangeProofResult {
    pub proof_id: Bytes,
    /// False when the caller inspected the proof without revealing anything.
    pub disclosed: bool,
    pub commitment_matches: bool,
    pub amount_in_declared_tier: bool,
    pub score_awarded: u32,
    pub score_retained: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct PrivateCredential {
    pub credential_id: Bytes,
    /// Per-credential identity digest. Distinct from `attributes_commitment`,
    /// which two credentials sharing attributes would also share.
    pub credential_commitment: Bytes,
    pub schema_hash: Bytes,
    /// Sealed attributes. The plaintext is never held by this contract.
    pub attributes_commitment: Bytes,
    pub holder_commitment: Bytes,
    pub issued_at: u64,
    pub expires_at: u64,
    pub refresh_count: u32,
    /// `credential_commitment` of the predecessor, or None at the root.
    pub refreshed_from: Option<Bytes>,
    pub revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CredentialRefreshLink {
    pub old_commitment: Bytes,
    pub new_credential_id: Bytes,
    pub nullifier: Bytes,
    pub refreshed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct PrivacyAttestation {
    pub credential_commitment: Bytes,
    pub privacy_level: u8, // 1-5, where 5 is maximum privacy
    pub anonymity_set_size: u32,
    pub revocation_status: bool,
    pub last_verified: u64,
    pub metadata: Map<Symbol, Bytes>,
}

#[contract]
pub struct PrivacyFeatures;

#[contractimpl]
impl PrivacyFeatures {
    /// Initialize privacy configuration
    pub fn initialize_privacy_config(
        env: Env,
        min_anonymity_set_size: u32,
        nullifier_lifetime: u64,
        revocation_check_interval: u64,
        selective_disclosure_required: bool,
        zero_knowledge_verification: bool,
    ) {
        let config = PrivacyConfig {
            min_anonymity_set_size,
            nullifier_lifetime,
            revocation_check_interval,
            selective_disclosure_required,
            zero_knowledge_verification,
        };

        log!(&env, "TRACE: initialize_privacy_config - Configured privacy settings");
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "privacy_config"), &config);
    }

    /// Generate nullifier for privacy-preserving identification
    pub fn generate_nullifier(
        env: Env,
        credential_commitment: Bytes,
        context: Bytes,
        user_secret: Bytes,
        expires_at: u64,
    ) -> Result<Bytes, PrivacyError> {
        // Check privacy configuration
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400, // 24 hours
                revocation_check_interval: 3600, // 1 hour
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        // Generate nullifier using cryptographic hash
        let mut hasher = Sha256::new();
        hasher.update(credential_commitment.to_array().as_slice());
        hasher.update(context.to_array().as_slice());
        hasher.update(user_secret.to_array().as_slice());
        hasher.update(env.ledger().timestamp().to_be_bytes());
        let nullifier_bytes = hasher.finalize();
        let nullifier = Bytes::from_slice(&env, &nullifier_bytes);

        // Check if nullifier already exists (prevent double-spending)
        let nullifier_key = Symbol::new(&env, &format!("nullifier:{}", nullifier.to_string()));
        if env.storage().persistent().has(&nullifier_key) {
            log!(&env, "ERROR: generate_nullifier - Double spending attempt detected");
            return Err(PrivacyError::DoubleSpending);
        }

        log!(&env, "TRACE: generate_nullifier - Nullifier successfully generated and checked");
        // Store nullifier state
        let nullifier_state = NullifierState {
            nullifier: nullifier.clone(),
            context: context.clone(),
            created_at: env.ledger().timestamp(),
            expires_at,
            usage_count: 1,
            credential_commitment: credential_commitment.clone(),
        };

        env.storage()
            .persistent()
            .set(&nullifier_key, &nullifier_state);

        // Set expiration
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, &format!("expires:{}", nullifier.to_string())), &expires_at);

        Ok(nullifier)
    }

    /// Verify nullifier is valid and not expired
    pub fn verify_nullifier(env: Env, nullifier: Bytes, context: Bytes) -> Result<bool, PrivacyError> {
        let nullifier_key = Symbol::new(&env, &format!("nullifier:{}", nullifier.to_string()));
        
        let nullifier_state: NullifierState = env
            .storage()
            .persistent()
            .get(&nullifier_key)
            .ok_or(PrivacyError::InvalidNullifier)?;

        // Check context matches
        if nullifier_state.context != context {
            log!(&env, "ERROR: verify_nullifier - Context mismatch");
            return Err(PrivacyError::ContextMismatch);
        }

        // Check expiration
        if env.ledger().timestamp() > nullifier_state.expires_at {
            log!(&env, "ERROR: verify_nullifier - Nullifier expired");
            return Err(PrivacyError::InvalidNullifier);
        }

        // Check usage limits
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        if nullifier_state.usage_count > 3 {
            return Err(PrivacyError::DoubleSpending);
        }

        // Increment usage count
        let mut updated_state = nullifier_state;
        updated_state.usage_count += 1;
        env.storage()
            .persistent()
            .set(&nullifier_key, &updated_state);

        Ok(true)
    }

    /// Create revocation-proof credential verification
    pub fn create_revocation_proof(
        env: Env,
        credential_commitment: Bytes,
        revocation_list_root: Bytes,
        anonymity_set: Vec<Bytes>,
        proof_valid_until: u64,
    ) -> Result<RevocationProof, PrivacyError> {
        // Check minimum anonymity set size
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        if anonymity_set.len() < config.min_anonymity_set_size as usize {
            return Err(PrivacyError::InsufficientPrivacy);
        }

        // Generate revocation hash (simplified - in practice would use ZK proof)
        let mut hasher = Sha256::new();
        hasher.update(credential_commitment.to_array().as_slice());
        hasher.update(revocation_list_root.to_array().as_slice());
        
        for commitment in anonymity_set.iter() {
            hasher.update(commitment.to_array().as_slice());
        }
        
        let revocation_hash_bytes = hasher.finalize();
        let revocation_hash = Bytes::from_slice(&env, &revocation_hash_bytes);

        // Generate anonymity set hash
        let mut set_hasher = Sha256::new();
        for commitment in anonymity_set.iter() {
            set_hasher.update(commitment.to_array().as_slice());
        }
        let anonymity_set_hash_bytes = set_hasher.finalize();
        let anonymity_set_hash = Bytes::from_slice(&env, &anonymity_set_hash_bytes);

        let revocation_proof = RevocationProof {
            credential_commitment,
            revocation_hash,
            proof_valid_until,
            anonymity_set_hash,
        };

        // Store revocation proof
        let proof_key = Symbol::new(&env, &format!("rev_proof:{}", revocation_hash.to_string()));
        env.storage()
            .persistent()
            .set(&proof_key, &revocation_proof);

        Ok(revocation_proof)
    }

    /// Verify credential is not revoked using revocation proof
    pub fn verify_revocation_proof(
        env: Env,
        credential_commitment: Bytes,
        revocation_proof: RevocationProof,
        current_revocation_root: Bytes,
    ) -> Result<bool, PrivacyError> {
        // Check proof validity period
        if env.ledger().timestamp() > revocation_proof.proof_valid_until {
            return Err(PrivacyError::RevokedCredential);
        }

        // Verify credential commitment matches
        if revocation_proof.credential_commitment != credential_commitment {
            return Err(PrivacyError::InvalidCommitment);
        }

        // In a real implementation, this would verify the ZK proof
        // For now, we'll simulate verification by checking the hash
        let mut hasher = Sha256::new();
        hasher.update(credential_commitment.to_array().as_slice());
        hasher.update(current_revocation_root.to_array().as_slice());
        hasher.update(revocation_proof.anonymity_set_hash.to_array().as_slice());
        
        let expected_hash_bytes = hasher.finalize();
        let expected_hash = Bytes::from_slice(&env, &expected_hash_bytes);

        Ok(expected_hash == revocation_proof.revocation_hash)
    }

    /// Create selective disclosure proof
    pub fn create_selective_disclosure(
        env: Env,
        credential_id: Bytes,
        all_attributes: Map<Symbol, Bytes>,
        revealed_attributes: Vec<Symbol>,
        validity_proof: Bytes,
    ) -> Result<SelectiveDisclosure, PrivacyError> {
        // Validate selective disclosure requirement
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        if config.selective_disclosure_required && revealed_attributes.is_empty() {
            return Err(PrivacyError::InsufficientPrivacy);
        }

        // Determine hidden attributes
        let mut hidden_attributes = Vec::new(&env);
        for (attr_name, _) in all_attributes.iter() {
            let is_revealed = revealed_attributes.iter().any(|revealed| revealed == attr_name);
            if !is_revealed {
                hidden_attributes.push_back(attr_name);
            }
        }

        // Generate disclosure hash
        let mut hasher = Sha256::new();
        hasher.update(credential_id.to_array().as_slice());
        
        // Hash revealed attributes
        for attr_name in revealed_attributes.iter() {
            if let Some(attr_value) = all_attributes.get(attr_name) {
                hasher.update(attr_name.to_string().as_bytes());
                hasher.update(attr_value.to_array().as_slice());
            }
        }
        
        // Hash hidden attribute names only (not values)
        for attr_name in hidden_attributes.iter() {
            hasher.update(attr_name.to_string().as_bytes());
        }
        
        let disclosure_hash_bytes = hasher.finalize();
        let disclosure_hash = Bytes::from_slice(&env, &disclosure_hash_bytes);

        let selective_disclosure = SelectiveDisclosure {
            credential_id,
            revealed_attributes: revealed_attributes.clone(),
            hidden_attributes,
            disclosure_hash,
            validity_proof,
        };

        // Store selective disclosure
        let disclosure_key = Symbol::new(&env, &format!("disclosure:{}", disclosure_hash.to_string()));
        env.storage()
            .persistent()
            .set(&disclosure_key, &selective_disclosure);

        Ok(selective_disclosure)
    }

    /// Verify selective disclosure proof
    pub fn verify_selective_disclosure(
        env: Env,
        credential_id: Bytes,
        selective_disclosure: SelectiveDisclosure,
        all_attributes: Map<Symbol, Bytes>,
    ) -> Result<bool, PrivacyError> {
        // Verify credential ID matches
        if selective_disclosure.credential_id != credential_id {
            return Err(PrivacyError::InvalidCommitment);
        }

        // Re-compute disclosure hash
        let mut hasher = Sha256::new();
        hasher.update(credential_id.to_array().as_slice());
        
        // Hash revealed attributes
        for attr_name in selective_disclosure.revealed_attributes.iter() {
            if let Some(attr_value) = all_attributes.get(attr_name) {
                hasher.update(attr_name.to_string().as_bytes());
                hasher.update(attr_value.to_array().as_slice());
            }
        }
        
        // Hash hidden attribute names only
        for attr_name in selective_disclosure.hidden_attributes.iter() {
            hasher.update(attr_name.to_string().as_bytes());
        }
        
        let expected_hash_bytes = hasher.finalize();
        let expected_hash = Bytes::from_slice(&env, &expected_hash_bytes);

        Ok(expected_hash == selective_disclosure.disclosure_hash)
    }

    /// Create privacy attestation
    pub fn create_privacy_attestation(
        env: Env,
        credential_commitment: Bytes,
        privacy_level: u8,
        anonymity_set_size: u32,
        metadata: Map<Symbol, Bytes>,
    ) -> Result<PrivacyAttestation, PrivacyError> {
        // Validate privacy level
        if privacy_level < 1 || privacy_level > 5 {
            return Err(PrivacyError::InsufficientPrivacy);
        }

        // Check minimum anonymity set size
        let config: PrivacyConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            });

        if anonymity_set_size < config.min_anonymity_set_size {
            return Err(PrivacyError::InsufficientPrivacy);
        }

        let attestation = PrivacyAttestation {
            credential_commitment: credential_commitment.clone(),
            privacy_level,
            anonymity_set_size,
            revocation_status: false, // Assume not revoked initially
            last_verified: env.ledger().timestamp(),
            metadata: metadata.clone(),
        };

        // Store privacy attestation
        let attestation_key = Symbol::new(&env, &format!("privacy_attest:{}", credential_commitment.to_string()));
        env.storage()
            .persistent()
            .set(&attestation_key, &attestation);

        Ok(attestation)
    }

    /// Update revocation status for privacy attestation
    pub fn update_revocation_status(
        env: Env,
        credential_commitment: Bytes,
        is_revoked: bool,
    ) -> Result<(), PrivacyError> {
        let attestation_key = Symbol::new(&env, &format!("privacy_attest:{}", credential_commitment.to_string()));
        let mut attestation: PrivacyAttestation = env
            .storage()
            .persistent()
            .get(&attestation_key)
            .ok_or(PrivacyError::InvalidCommitment)?;

        attestation.revocation_status = is_revoked;
        attestation.last_verified = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&attestation_key, &attestation);

        Ok(())
    }

    /// Get privacy configuration
    pub fn get_privacy_config(env: Env) -> PrivacyConfig {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "privacy_config"))
            .unwrap_or(PrivacyConfig {
                min_anonymity_set_size: 10,
                nullifier_lifetime: 86400,
                revocation_check_interval: 3600,
                selective_disclosure_required: true,
                zero_knowledge_verification: true,
            })
    }

    /// Clean up expired nullifiers
    pub fn cleanup_expired_nullifiers(env: Env) -> Result<u32, PrivacyError> {
        let current_time = env.ledger().timestamp();
        let mut cleaned_count = 0;

        // This is a simplified cleanup - in practice would need more sophisticated iteration
        let config = Self::get_privacy_config(env.clone());
        
        // For demo purposes, we'll just return 0
        // In a real implementation, would iterate through nullifier keys and remove expired ones
        
        Ok(cleaned_count)
    }

    /// Get privacy metrics
    pub fn get_privacy_metrics(env: Env) -> Map<Symbol, Bytes> {
        let mut metrics = Map::new(&env);
        
        // Get current timestamp
        let current_time = env.ledger().timestamp();
        metrics.set(
            Symbol::new(&env, "current_time"),
            Bytes::from_slice(&env, &current_time.to_be_bytes()),
        );

        // Get privacy config
        let config = Self::get_privacy_config(env.clone());
        metrics.set(
            Symbol::new(&env, "min_anonymity_set_size"),
            Bytes::from_slice(&env, &config.min_anonymity_set_size.to_be_bytes()),
        );
        metrics.set(
            Symbol::new(&env, "nullifier_lifetime"),
            Bytes::from_slice(&env, &config.nullifier_lifetime.to_be_bytes()),
        );

        metrics
    }

    // ── Confidential transactions (#192) ─────────────────────────────────────

    /// Record a transaction whose amount is never written on-chain.
    ///
    /// What is stored is a commitment to the amount plus the *tier* the amount
    /// falls into — the bounds the caller asserts it satisfies, e.g. "at least
    /// 100 XLM". Success or failure is recorded directly, so scoring accuracy
    /// survives the amount staying hidden: scoring reads the tier, never the
    /// value.
    ///
    /// `was_successful` and the tier bounds are both caller assertions. They are
    /// cheap to make and unverifiable on-chain, which is exactly why
    /// `score_confidential_transaction` exists: a holder who chooses to
    /// disclose can have the claim checked, and a claim that turns out to be
    /// false costs the points it bought.
    pub fn submit_confidential_transaction(
        env: Env,
        tx_hash: Bytes,
        amount_commitment: Bytes,
        tier_min: u64,
        tier_max: u64,
        privacy_level: TransactionPrivacyLevel,
        was_successful: bool,
    ) -> Result<Bytes, PrivacyError> {
        let policy = Self::get_confidential_policy(env.clone());

        // A caller cannot opt into less privacy than the policy requires.
        if (privacy_level as u8) < (policy.min_privacy_level as u8) {
            log!(&env, "ERROR: submit_confidential_transaction - privacy level below policy");
            return Err(PrivacyError::InsufficientPrivacy);
        }

        // Rejected up front rather than stored and clawed back later: an
        // implausible tier is never going to be disclosed, so the clawback
        // path would never fire for it.
        if tier_min > policy.max_tier_min {
            log!(&env, "ERROR: submit_confidential_transaction - implausible tier");
            return Err(PrivacyError::InvalidRange);
        }

        if tier_min > tier_max {
            log!(&env, "ERROR: submit_confidential_transaction - inverted tier bounds");
            return Err(PrivacyError::InvalidRange);
        }

        if amount_commitment.len() != SHA256_DIGEST_LEN {
            log!(&env, "ERROR: submit_confidential_transaction - commitment must be a SHA-256 digest");
            return Err(PrivacyError::InvalidCommitment);
        }

        let nonce = Self::next_nonce(&env, "confidential_nonce");
        let proof_id = Self::digest_fields(
            &env,
            CONFIDENTIAL_TX_DOMAIN,
            &[tx_hash.clone(), amount_commitment.clone(), Self::u64_bytes(&env, nonce)],
        );

        let score_awarded = Self::confidential_score(tier_min, was_successful);
        let proof = AmountRangeProof {
            proof_id: proof_id.clone(),
            tx_hash,
            amount_commitment,
            tier_min,
            tier_max,
            privacy_level,
            was_successful,
            score_awarded,
            created_at: env.ledger().timestamp(),
            challenged_at: None,
        };

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, &Self::confidential_tx_key(&proof_id)), &proof);

        if privacy_level == TransactionPrivacyLevel::Hidden {
            Self::bump_u32(&env, CONFIDENTIAL_HIDDEN_COUNT);
        } else {
            Self::bump_u32(&env, CONFIDENTIAL_TIERED_COUNT);
        }
        Self::bump_u64(&env, CONFIDENTIAL_SCORE_TOTAL, score_awarded as u64);

        log!(&env, "TRACE: submit_confidential_transaction - amount withheld, tier recorded");
        env.events().publish(
            (Symbol::new(&env, "ConfidentialTransactionSubmitted"), proof_id),
            (tier_min, privacy_level as u8, score_awarded),
        );

        Ok(proof_id)
    }

    /// Optionally disclose a withheld amount to have the claim checked.
    ///
    /// Pass `None` for both arguments to inspect a proof without revealing
    /// anything: the tier stands and nothing is challenged. Pass both to have
    /// the commitment recomputed and the tier bounds checked; if either fails
    /// the score is clawed back to zero.
    ///
    /// Passing one but not the other is a context mismatch rather than a silent
    /// skip, so a partial disclosure can never be misread as "nothing to check".
    pub fn score_confidential_transaction(
        env: Env,
        proof_id: Bytes,
        disclosed_amount: Option<u64>,
        salt: Option<Bytes>,
    ) -> Result<RangeProofResult, PrivacyError> {
        let mut proof: AmountRangeProof = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, &Self::confidential_tx_key(&proof_id)))
            .ok_or(PrivacyError::UnknownCredential)?;

        // Nothing disclosed: the tier stands and no claim is asserted either way.
        if disclosed_amount.is_none() && salt.is_none() {
            return Ok(RangeProofResult {
                proof_id: proof_id.clone(),
                disclosed: false,
                commitment_matches: false,
                amount_in_declared_tier: false,
                score_awarded: proof.score_awarded,
                score_retained: true,
            });
        }

        let (amount, salt) = match (disclosed_amount, salt) {
            (Some(a), Some(s)) => (a, s),
            _ => {
                log!(&env, "ERROR: score_confidential_transaction - partial disclosure");
                return Err(PrivacyError::ContextMismatch);
            }
        };

        let recomputed = Self::digest_fields(
            &env,
            CONFIDENTIAL_AMOUNT_DOMAIN,
            &[Self::u64_bytes(&env, amount), salt],
        );
        let commitment_matches = recomputed == proof.amount_commitment;
        let amount_in_declared_tier = amount >= proof.tier_min && amount <= proof.tier_max;

        // Only a disclosure that contradicts the stored claim costs the score.
        let score_retained = commitment_matches && amount_in_declared_tier;
        if !score_retained && proof.score_awarded > 0 {
            log!(&env, "ERROR: score_confidential_transaction - tier claim contradicted");
            let clawed_back = proof.score_awarded;
            proof.score_awarded = 0;
            proof.challenged_at = Some(env.ledger().timestamp());
            env.storage()
                .persistent()
                .set(&Symbol::new(&env, &Self::confidential_tx_key(&proof_id)), &proof);
            Self::drop_u64(&env, CONFIDENTIAL_SCORE_TOTAL, clawed_back as u64);
        }

        env.events().publish(
            (Symbol::new(&env, "ConfidentialTransactionChallenged"), proof_id.clone()),
            (commitment_matches, amount_in_declared_tier, score_retained),
        );

        Ok(RangeProofResult {
            proof_id,
            disclosed: true,
            commitment_matches,
            amount_in_declared_tier,
            score_awarded: proof.score_awarded,
            score_retained,
        })
    }

    pub fn get_confidential_transaction(
        env: Env,
        proof_id: Bytes,
    ) -> Result<AmountRangeProof, PrivacyError> {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, &Self::confidential_tx_key(&proof_id)))
            .ok_or(PrivacyError::UnknownCredential)
    }

    /// Minimum privacy level and plausibility ceiling for confidential
    /// transactions. Kept separate from `PrivacyConfig` so the existing
    /// settings struct — and its seven literals — stay untouched.
    pub fn set_confidential_policy(
        env: Env,
        min_privacy_level: TransactionPrivacyLevel,
        max_tier_min: u64,
    ) {
        env.storage().persistent().set(
            &Symbol::new(&env, CONFIDENTIAL_POLICY),
            &ConfidentialPolicy {
                min_privacy_level,
                max_tier_min,
            },
        );
    }

    pub fn get_confidential_policy(env: Env) -> ConfidentialPolicy {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, CONFIDENTIAL_POLICY))
            .unwrap_or(ConfidentialPolicy {
                min_privacy_level: TransactionPrivacyLevel::Tiered,
                max_tier_min: 1_000_000 * XLM_IN_STROOPS,
            })
    }

    /// Confidential transaction counts and score totals.
    pub fn get_confidential_metrics(env: Env) -> Map<Symbol, Bytes> {
        let mut metrics = Map::new(&env);

        let tiered: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, CONFIDENTIAL_TIERED_COUNT))
            .unwrap_or(0u32);
        let hidden: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, CONFIDENTIAL_HIDDEN_COUNT))
            .unwrap_or(0u32);
        let score: u64 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, CONFIDENTIAL_SCORE_TOTAL))
            .unwrap_or(0u64);

        metrics.set(
            Symbol::new(&env, "confidential_tiered_count"),
            Bytes::from_slice(&env, &tiered.to_be_bytes()),
        );
        metrics.set(
            Symbol::new(&env, "confidential_hidden_count"),
            Bytes::from_slice(&env, &hidden.to_be_bytes()),
        );
        metrics.set(
            Symbol::new(&env, "confidential_score_total"),
            Bytes::from_slice(&env, &score.to_be_bytes()),
        );

        // Share of transactions that withheld their amount. Guarded so a fresh
        // contract reports 0 rather than dividing by zero.
        let total = tiered as u64 + hidden as u64;
        let hidden_pct: u32 = if total > 0 {
            ((hidden as u64 * 100) / total) as u32
        } else {
            0
        };
        metrics.set(
            Symbol::new(&env, "confidential_hidden_percent"),
            Bytes::from_slice(&env, &hidden_pct.to_be_bytes()),
        );

        metrics
    }

    // ── Private credential refresh (#193) ───────────────────────────────────

    /// Issue a credential whose attributes are sealed on-chain.
    ///
    /// Only a commitment to the attributes is ever stored, so the contract
    /// cannot leak them — not even to itself on refresh. Presentation and
    /// decryption happen off-chain against the issuer.
    pub fn issue_private_credential(
        env: Env,
        schema_hash: Bytes,
        attributes: Vec<Bytes>,
        holder_commitment: Bytes,
        expires_at: u64,
    ) -> Result<Bytes, PrivacyError> {
        if attributes.is_empty() {
            log!(&env, "ERROR: issue_private_credential - no attributes supplied");
            return Err(PrivacyError::InvalidInput);
        }
        if expires_at <= env.ledger().timestamp() {
            log!(&env, "ERROR: issue_private_credential - already expired on issue");
            return Err(PrivacyError::InvalidInput);
        }
        if schema_hash.len() != SHA256_DIGEST_LEN || holder_commitment.len() != SHA256_DIGEST_LEN {
            log!(&env, "ERROR: issue_private_credential - commitments must be SHA-256 digests");
            return Err(PrivacyError::InvalidCommitment);
        }

        let attributes_commitment = Self::seal_attributes(&env, &attributes);
        let nonce = Self::next_nonce(&env, "credential_nonce");
        let credential_id = Self::digest_fields(
            &env,
            CREDENTIAL_DOMAIN,
            &[schema_hash.clone(), Self::u64_bytes(&env, nonce)],
        );

        let credential = PrivateCredential {
            credential_id: credential_id.clone(),
            credential_commitment: Self::credential_commitment(
                &env,
                &credential_id,
                &attributes_commitment,
            ),
            schema_hash,
            attributes_commitment,
            holder_commitment,
            issued_at: env.ledger().timestamp(),
            expires_at,
            refresh_count: 0,
            refreshed_from: None,
            revoked: false,
        };

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, &Self::credential_key(&credential_id)), &credential);
        env.storage().persistent().set(
            &Symbol::new(&env, &Self::credential_index_key(&credential.credential_commitment)),
            &credential_id,
        );

        env.events().publish(
            (Symbol::new(&env, "PrivateCredentialIssued"), credential_id.clone()),
            (credential.credential_commitment, expires_at),
        );

        Ok(credential_id)
    }

    /// Re-issue an expiring credential from a proof of holding it.
    ///
    /// The successor carries the *same* `attributes_commitment`, which is how
    /// "attributes preserved without re-disclosure" is demonstrated: the value
    /// is provably unchanged because it was never opened. The new expiry is the
    /// only substantive difference.
    ///
    /// The predecessor is linked by `credential_commitment`, a per-credential
    /// digest. Linking by `attributes_commitment` would be useless here, because
    /// a refresh preserves attributes and the two would be indistinguishable.
    ///
    /// `ownership_proof` is checked for presence only: proving possession
    /// requires verifying a ZK proof, and this contract has no verifier. It is
    /// the nullifier, which is enforced strictly, that provides the replay
    /// guarantee.
    pub fn refresh_credential_privacy(
        env: Env,
        credential_id: Bytes,
        ownership_proof: Bytes,
        nullifier: Bytes,
        new_expires_at: u64,
    ) -> Result<Bytes, PrivacyError> {
        let current: PrivateCredential = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, &Self::credential_key(&credential_id)))
            .ok_or(PrivacyError::UnknownCredential)?;

        if current.revoked {
            log!(&env, "ERROR: refresh_credential_privacy - credential revoked");
            return Err(PrivacyError::RevokedCredential);
        }
        if ownership_proof.is_empty() {
            log!(&env, "ERROR: refresh_credential_privacy - missing ownership proof");
            return Err(PrivacyError::OwnershipProofFailed);
        }
        if new_expires_at <= env.ledger().timestamp() {
            log!(&env, "ERROR: refresh_credential_privacy - successor already expired");
            return Err(PrivacyError::InvalidInput);
        }

        // Single-use, which is what stops a captured ownership proof from being
        // replayed to mint a second successor.
        let nullifier_key = Symbol::new(&env, &Self::refresh_nullifier_key(&nullifier));
        if env.storage().persistent().has(&nullifier_key) {
            log!(&env, "ERROR: refresh_credential_privacy - nullifier replay");
            return Err(PrivacyError::InvalidNullifier);
        }

        let nonce = Self::next_nonce(&env, "credential_nonce");
        let new_id = Self::digest_fields(
            &env,
            CREDENTIAL_DOMAIN,
            &[current.schema_hash.clone(), Self::u64_bytes(&env, nonce)],
        );

        let successor = PrivateCredential {
            credential_id: new_id.clone(),
            credential_commitment: Self::credential_commitment(
                &env,
                &new_id,
                &current.attributes_commitment,
            ),
            schema_hash: current.schema_hash.clone(),
            // Carried forward untouched: no attribute is read, re-sent or
            // re-emitted anywhere in this path.
            attributes_commitment: current.attributes_commitment.clone(),
            holder_commitment: current.holder_commitment.clone(),
            issued_at: env.ledger().timestamp(),
            expires_at: new_expires_at,
            refresh_count: current.refresh_count.saturating_add(1),
            refreshed_from: Some(current.credential_commitment.clone()),
            revoked: false,
        };

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, &Self::credential_key(&new_id)), &successor);
        env.storage().persistent().set(
            &Symbol::new(&env, &Self::credential_index_key(&successor.credential_commitment)),
            &new_id,
        );
        env.storage().persistent().set(&nullifier_key, &new_id);
        env.storage().persistent().set(
            &Symbol::new(&env, &Self::refresh_link_key(&current.credential_commitment)),
            &CredentialRefreshLink {
                old_commitment: current.credential_commitment.clone(),
                new_credential_id: new_id.clone(),
                nullifier: nullifier.clone(),
                refreshed_at: env.ledger().timestamp(),
            },
        );

        // Commitments only. The event must not become the disclosure that the
        // whole scheme exists to avoid.
        env.events().publish(
            (Symbol::new(&env, "CredentialRefreshed"), new_id.clone()),
            (
                current.credential_commitment,
                successor.credential_commitment,
                successor.refresh_count,
            ),
        );

        Ok(new_id)
    }

    pub fn get_private_credential(
        env: Env,
        credential_id: Bytes,
    ) -> Result<PrivateCredential, PrivacyError> {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, &Self::credential_key(&credential_id)))
            .ok_or(PrivacyError::UnknownCredential)
    }

    pub fn get_refresh_link(
        env: Env,
        old_commitment: Bytes,
    ) -> Result<CredentialRefreshLink, PrivacyError> {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, &Self::refresh_link_key(&old_commitment)))
            .ok_or(PrivacyError::UnknownCredential)
    }

    /// Walk a credential's refresh history back to its root.
    ///
    /// Resolving a predecessor takes two steps: the refresh link keyed by the
    /// predecessor's commitment names the *successor*, while the commitment
    /// index resolves that same commitment to the predecessor's id. Following
    /// the link alone would just re-resolve the credential we came from, and
    /// every chain of length two or more would spin until it falsely reported
    /// `ChainTooDeep`.
    ///
    /// Returns false if any ancestor is missing, revoked, or reached through a
    /// record that disagrees with the credential being walked, so a chain rooted
    /// in a revoked credential cannot be laundered into a clean-looking
    /// successor.
    pub fn verify_credential_chain(env: Env, credential_id: Bytes) -> Result<bool, PrivacyError> {
        let mut entry_id = credential_id;
        let mut current = Self::get_private_credential(env.clone(), entry_id.clone())?;
        let mut depth: u32 = 0;

        while let Some(previous) = current.refreshed_from.clone() {
            depth = depth.saturating_add(1);
            if depth > MAX_REFRESH_DEPTH {
                log!(&env, "ERROR: verify_credential_chain - chain too deep");
                return Err(PrivacyError::ChainTooDeep);
            }

            let link: CredentialRefreshLink = env
                .storage()
                .persistent()
                .get(&Symbol::new(&env, &Self::refresh_link_key(&previous)))
                .ok_or(PrivacyError::UnknownCredential)?;

            if link.old_commitment != previous {
                log!(&env, "ERROR: verify_credential_chain - link mismatch");
                return Ok(false);
            }
            // The link must name the credential we are walking down from.
            if link.new_credential_id != entry_id {
                log!(&env, "ERROR: verify_credential_chain - link points elsewhere");
                return Ok(false);
            }

            let predecessor_id: Bytes = env
                .storage()
                .persistent()
                .get(&Symbol::new(&env, &Self::credential_index_key(&previous)))
                .ok_or(PrivacyError::UnknownCredential)?;

            current = Self::get_private_credential(env.clone(), predecessor_id.clone())?;
            // The index and the stored commitment have to agree.
            if current.credential_commitment != previous {
                log!(&env, "ERROR: verify_credential_chain - index disagrees with credential");
                return Ok(false);
            }
            if current.revoked {
                log!(&env, "ERROR: verify_credential_chain - ancestor revoked");
                return Ok(false);
            }

            entry_id = predecessor_id;
        }

        Ok(true)
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// Score from the declared tier and outcome, never from the amount.
    ///
    /// Withholding the amount costs nothing here: a successful transaction
    /// still scores, and the tier only adds a bounded bonus on top.
    fn confidential_score(tier_min: u64, was_successful: bool) -> u32 {
        if !was_successful {
            return 0;
        }
        let bonus = (tier_min / CONFIDENTIAL_SCORE_UNIT).min(MAX_CONFIDENTIAL_SCORE as u64) as u32;
        CONFIDENTIAL_BASE_SCORE + bonus
    }

    /// Feed a `Bytes` into a hasher without `Bytes::to_array`.
    ///
    /// `to_array` is only valid up to 32 bytes and panics beyond it, which any
    /// real attribute or user-supplied salt would exceed. Reading byte by byte
    /// is length-safe, and the length prefix keeps it unambiguous.
    fn update_with_bytes(hasher: &mut Sha256, data: &Bytes) {
        hasher.update(data.len().to_be_bytes());
        for index in 0..data.len() {
            if let Some(byte) = data.get(index) {
                hasher.update([byte]);
            }
        }
    }

    /// Length-prefixed SHA-256 over a domain and a list of fields.
    fn digest_fields(env: &Env, domain: &[u8], fields: &[Bytes]) -> Bytes {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update((fields.len() as u32).to_be_bytes());
        for field in fields.iter() {
            Self::update_with_bytes(&mut hasher, field);
        }
        Bytes::from_slice(env, &hasher.finalize())
    }

    /// Commit to an attribute set without retaining it.
    ///
    /// The count is hashed in, so `["ab", "c"]` and `["a", "bc"]` cannot seal to
    /// the same commitment.
    fn seal_attributes(env: &Env, attributes: &Vec<Bytes>) -> Bytes {
        let mut hasher = Sha256::new();
        hasher.update(ATTRIBUTES_DOMAIN);
        hasher.update((attributes.len() as u32).to_be_bytes());
        for attribute in attributes.iter() {
            Self::update_with_bytes(&mut hasher, attribute);
        }
        Bytes::from_slice(env, &hasher.finalize())
    }

    /// Per-credential identity digest, distinct from `attributes_commitment`,
    /// which two credentials sharing attributes would also share.
    fn credential_commitment(
        env: &Env,
        credential_id: &Bytes,
        attributes_commitment: &Bytes,
    ) -> Bytes {
        Self::digest_fields(
            env,
            CREDENTIAL_COMMITMENT_DOMAIN,
            &[credential_id.clone(), attributes_commitment.clone()],
        )
    }

    fn u64_bytes(env: &Env, value: u64) -> Bytes {
        Bytes::from_slice(env, &value.to_be_bytes())
    }

    /// Monotonic counter, so two issuances in the same ledger still differ.
    fn next_nonce(env: &Env, counter: &str) -> u64 {
        let key = Symbol::new(env, counter);
        let next: u64 = env.storage().persistent().get(&key).unwrap_or(0u64) + 1;
        env.storage().persistent().set(&key, &next);
        next
    }

    fn bump_u32(env: &Env, name: &str) {
        let value: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(env, name))
            .unwrap_or(0u32);
        env.storage()
            .persistent()
            .set(&Symbol::new(env, name), &value.saturating_add(1));
    }

    fn bump_u64(env: &Env, name: &str, delta: u64) {
        let value: u64 = env
            .storage()
            .persistent()
            .get(&Symbol::new(env, name))
            .unwrap_or(0u64);
        env.storage()
            .persistent()
            .set(&Symbol::new(env, name), &value.saturating_add(delta));
    }

    /// Subtract from a counter, flooring at zero rather than wrapping.
    fn drop_u64(env: &Env, name: &str, delta: u64) {
        let value: u64 = env
            .storage()
            .persistent()
            .get(&Symbol::new(env, name))
            .unwrap_or(0u64);
        env.storage()
            .persistent()
            .set(&Symbol::new(env, name), &value.saturating_sub(delta));
    }

    fn confidential_tx_key(proof_id: &Bytes) -> String {
        format!("confidential_tx:{}", proof_id.to_string())
    }

    fn credential_key(credential_id: &Bytes) -> String {
        format!("private_credential:{}", credential_id.to_string())
    }

    fn refresh_link_key(old_commitment: &Bytes) -> String {
        format!("refresh_link:{}", old_commitment.to_string())
    }

    /// Resolves a `credential_commitment` back to the credential holding it, so
    /// a refresh chain can be walked without either credential having to name
    /// its neighbour.
    fn credential_index_key(credential_commitment: &Bytes) -> String {
        format!("credential_index:{}", credential_commitment.to_string())
    }

    fn refresh_nullifier_key(nullifier: &Bytes) -> String {
        format!("refresh_nullifier:{}", nullifier.to_string())
    }
}
