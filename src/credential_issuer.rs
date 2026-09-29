use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::admin;
use crate::batch_optimizer::{IndexAppender, IndexKey};
use crate::contract_upgrade;
use crate::event_index::{self, EventFilter, EventRecord, EventStreamPage, IndexedEventType};
use crate::rate_limiter::{self, RateLimitConfig, RateLimitStatus};
use crate::reentrancy_guard::ReentrancyGuard;
use crate::validation::{self, ValidationError};
use crate::{clamp_page_size, PaginatedCredentials, VerifiableCredential};

// ---------------------------------------------------------------------------
// Delegated Credential Issuance Types (#92)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub struct DelegationAuthorization {
    pub id: Bytes,
    pub delegator: Address,
    pub delegate: Address,
    pub authorized_types: Vec<Bytes>,
    pub max_issuances: u32,
    pub issued_count: u32,
    pub expires_at: u64,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct DelegationChainEntry {
    pub delegator: Address,
    pub delegate: Address,
    pub authorized_types: Vec<Bytes>,
    pub timestamp: u64,
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// Revocation Registry Types (#91)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub struct RevocationRegistryEntry {
    pub id: Bytes,
    pub issuer: Address,
    pub credential_ids: Vec<Bytes>,
    pub nonce: Bytes,
    pub created: u64,
    pub revoked_count: u32,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RevocationProof {
    pub registry_id: Bytes,
    pub credential_id: Bytes,
    pub nonce: Bytes,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchRevocationRecord {
    pub batch_id: Bytes,
    pub issuer: Address,
    pub credential_ids: Vec<Bytes>,
    pub reason: Option<Bytes>,
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Batch Issuance Types (#81)
// ---------------------------------------------------------------------------

/// A single credential to issue in a batch.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchIssuanceItem {
    pub subject: Address,
    pub credential_type: Vec<Bytes>,
    pub credential_data: Bytes,
    pub expiration_date: Option<u64>,
    pub proof: Bytes,
}

// ---------------------------------------------------------------------------
// Namespaced storage keys (#58)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum CredKey {
    Credential(Bytes),
    Status(Bytes),
    Reason(Bytes),
    IssuerCreds(Address),
    SubjectCreds(Address),
    Schema(Bytes),
    Delegation(Bytes),
    DelegateAuths(Address),
    DelegatorAuths(Address),
    RevocationRegistry(Bytes),
    RevocationProof(Bytes),
    BatchRevocation(Bytes),
    AuthorizedIssuers,
    /// Monotonic issuance counter, used to build unique credential ids.
    IssuanceCounter,
}

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
    SchemaValidationFailed = 8,
    SchemaNotFound = 9,
    DelegationNotFound = 10,
    DelegationExpired = 11,
    DelegationLimitExceeded = 12,
    UnauthorizedCredentialType = 13,
    DelegationRevoked = 14,
    RegistryNotFound = 15,
    InvalidNonce = 16,
    /// Caller has exceeded the allowed request rate.
    RateLimitExceeded = 17,
    /// The entry already exists (authorization granted, contract initialized).
    AlreadyExists = 18,
    /// A required input was zero-length.
    EmptyField = 19,
    /// An input exceeded its maximum byte length.
    FieldTooLong = 20,
    /// An input was shorter than its minimum byte length.
    FieldTooShort = 21,
    /// A mandatory optional input was `None`.
    MissingField = 22,
    /// An address argument was the all-zero address.
    InvalidAddress = 23,
    /// Two addresses that must differ were equal.
    SameAddress = 24,
    /// A numeric argument fell outside its permitted range.
    OutOfRange = 25,
    /// A timestamp argument was outside the accepted window.
    InvalidTimestamp = 26,
    /// An input contained control / non-printable bytes.
    NonPrintableInput = 27,
    /// A tracked index vector is already at capacity.
    CollectionLimitExceeded = 28,
    /// Caller is not the contract admin.
    NotAdmin = 29,
}

impl From<ValidationError> for CredentialIssuerError {
    /// Map a shared validation failure onto the contract-specific error code
    /// so every rejection reason is distinguishable on-chain (#200).
    fn from(e: ValidationError) -> Self {
        match e {
            ValidationError::EmptyField => CredentialIssuerError::EmptyField,
            ValidationError::FieldTooLong => CredentialIssuerError::FieldTooLong,
            ValidationError::FieldTooShort => CredentialIssuerError::FieldTooShort,
            ValidationError::MissingField => CredentialIssuerError::MissingField,
            ValidationError::ZeroAddress => CredentialIssuerError::InvalidAddress,
            ValidationError::SameAddress => CredentialIssuerError::SameAddress,
            ValidationError::OutOfRange => CredentialIssuerError::OutOfRange,
            ValidationError::TimestampInPast | ValidationError::TimestampTooFarFuture => {
                CredentialIssuerError::InvalidTimestamp
            }
            ValidationError::BatchTooLarge => CredentialIssuerError::FieldTooLong,
            ValidationError::BatchEmpty => CredentialIssuerError::EmptyField,
            ValidationError::NonPrintableBytes => CredentialIssuerError::NonPrintableInput,
            ValidationError::CollectionLimitExceeded => {
                CredentialIssuerError::CollectionLimitExceeded
            }
        }
    }
}

impl From<rate_limiter::RateLimitError> for CredentialIssuerError {
    fn from(e: rate_limiter::RateLimitError) -> Self {
        match e {
            rate_limiter::RateLimitError::RateLimitExceeded => {
                CredentialIssuerError::RateLimitExceeded
            }
            rate_limiter::RateLimitError::NotAdmin => CredentialIssuerError::NotAdmin,
        }
    }
}

// ---------------------------------------------------------------------------
// Index vector access
//
// Shared by the single-item and batch paths. Free functions (rather than
// associated fns) so they can be handed to `IndexAppender` as closures.
// ---------------------------------------------------------------------------

fn read_index(env: &Env, key: &IndexKey) -> Vec<Bytes> {
    match key {
        IndexKey::Issuer(a) => env
            .storage()
            .persistent()
            .get(&CredKey::IssuerCreds(a.clone()))
            .unwrap_or_else(|| Vec::new(env)),
        IndexKey::Subject(a) => env
            .storage()
            .persistent()
            .get(&CredKey::SubjectCreds(a.clone()))
            .unwrap_or_else(|| Vec::new(env)),
        _ => Vec::new(env),
    }
}

fn write_index(env: &Env, key: &IndexKey, value: &Vec<Bytes>) {
    match key {
        IndexKey::Issuer(a) => {
            env.storage()
                .persistent()
                .set(&CredKey::IssuerCreds(a.clone()), value);
        }
        IndexKey::Subject(a) => {
            env.storage()
                .persistent()
                .set(&CredKey::SubjectCreds(a.clone()), value);
        }
        _ => {}
    }
}

#[contract]
pub struct CredentialIssuer;

#[contractimpl]
impl CredentialIssuer {
    const MAX_CREDENTIAL_TYPE_LENGTH: u32 = 128;
    const MAX_CREDENTIAL_DATA_LENGTH: u32 = 10240;
    /// Maximum number of credentials that can be issued in a single batch (#281).
    const MAX_BATCH_SIZE: u32 = 50;
    /// Maximum number of credentials an issuer may hold in its index vector.
    const MAX_ISSUER_CREDENTIALS: u32 = 100_000;
    /// Maximum number of credentials a subject may hold in its index vector.
    const MAX_SUBJECT_CREDENTIALS: u32 = 100_000;
    /// Maximum number of issuances a single delegation may authorise.
    const MAX_DELEGATION_ISSUANCES: u32 = 10_000;

    pub fn issue_credential(
        env: Env,
        issuer: Address,
        subject: Address,
        credential_type: Vec<Bytes>,
        credential_data: Bytes,
        expiration_date: Option<u64>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        // Per-issuer throttling with admin-configurable limits and trusted
        // issuer exemptions (#201).
        Self::enforce_rate_limit(
            &env,
            &issuer,
            &Symbol::new(&env, "issue_cred"),
            RateLimitConfig::new(
                rate_limiter::defaults::ISSUE_CREDENTIAL_WINDOW,
                rate_limiter::defaults::ISSUE_CREDENTIAL_MAX,
            ),
        )?;

        // Reentrancy guard: prevent callback loops via cross-contract calls
        ReentrancyGuard::acquire(&env, "issue_cred")
            .map_err(|_| CredentialIssuerError::Unauthorized)?;

        let result = Self::store_credential(
            &env,
            &issuer,
            &subject,
            &credential_type,
            &credential_data,
            expiration_date,
            &proof,
            None,
        );
        let credential_id = result?;

        env.events().publish(
            (Symbol::new(&env, "CredentialIssued"),),
            (credential_id.clone(), issuer.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::CredentialCreated,
            issuer,
            Some(subject),
            Some(credential_id.clone()),
            credential_data,
        );

        ReentrancyGuard::release(&env, "issue_cred");
        Ok(credential_id)
    }

    /// Validate and persist a credential, appending to the issuer / subject
    /// index vectors.
    ///
    /// When `batch` is supplied the index appends are staged so that
    /// `batch_issue_credentials` writes each vector once instead of once per
    /// credential (#197). `None` falls back to an immediate read-modify-write.
    #[allow(clippy::too_many_arguments)]
    fn store_credential(
        env: &Env,
        issuer: &Address,
        subject: &Address,
        credential_type: &Vec<Bytes>,
        credential_data: &Bytes,
        expiration_date: Option<u64>,
        proof: &Bytes,
        mut batch: Option<&mut IndexAppender>,
    ) -> Result<Bytes, CredentialIssuerError> {
        Self::validate_issuance(
            env,
            issuer,
            subject,
            credential_type,
            credential_data,
            expiration_date,
            proof,
        )?;

        let credential_id = Self::generate_credential_id(env, issuer, subject);
        let now = env.ledger().timestamp();

        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            type_: credential_type.clone(),
            credential_data: credential_data.clone(),
            issuance_date: now,
            expiration_date,
            schema_id: None,
            revocation: None,
            proof: Some(proof.clone()),
        };

        Self::validate_credential(env, &credential)?;

        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);
        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &0u32);

        Self::index_credential(env, batch.as_deref_mut(), issuer, subject, &credential_id);

        Ok(credential_id)
    }

    /// Append `credential_id` to the issuer and subject index vectors.
    ///
    /// Staged appends are flushed once by the batch caller; a direct issue
    /// (no batch) falls back to the naive read-modify-write.
    #[allow(clippy::too_many_arguments)]
    fn index_credential(
        env: &Env,
        mut batch: Option<&mut IndexAppender>,
        issuer: &Address,
        subject: &Address,
        credential_id: &Bytes,
    ) {
        let limits = [
            (
                IndexKey::Issuer(issuer.clone()),
                Self::MAX_ISSUER_CREDENTIALS,
            ),
            (
                IndexKey::Subject(subject.clone()),
                Self::MAX_SUBJECT_CREDENTIALS,
            ),
        ];

        for (key, cap) in limits {
            match batch.as_mut() {
                Some(appender) => {
                    let mut reader = |e: &Env, k: &IndexKey| read_index(e, k);
                    if appender.append(env, &key, credential_id, &mut reader) {
                        // Staged; the batch caller writes it once on flush.
                        continue;
                    }
                    // Tracking budget exhausted: fall through and write now so
                    // the credential is still indexed.
                }
                None => {
                    if validation::require_collection_room(read_index(env, &key).len(), cap)
                        .is_err()
                    {
                        // Index vector is full. The credential itself is still
                        // stored and reachable by id, so skip the index write
                        // rather than growing without bound.
                        continue;
                    }
                }
            }

            let mut current = read_index(env, &key);
            if !current.iter().any(|v| v == *credential_id) {
                current.push_back(credential_id.clone());
                write_index(env, &key, &current);
            }
        }
    }

    /// Full input validation for the issuance path (#200).
    ///
    /// Every rejection maps to a distinct `CredentialIssuerError` variant so
    /// callers can tell *why* an issuance was refused.
    #[allow(clippy::too_many_arguments)]
    fn validate_issuance(
        env: &Env,
        issuer: &Address,
        subject: &Address,
        credential_type: &Vec<Bytes>,
        credential_data: &Bytes,
        expiration_date: Option<u64>,
        proof: &Bytes,
    ) -> Result<(), CredentialIssuerError> {
        validation::require_non_zero_address(env, issuer)?;
        validation::require_non_zero_address(env, subject)?;

        if credential_type.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        for ct in credential_type.iter() {
            validation::require_non_empty(env, &ct)?;
            validation::require_max_len(env, &ct, Self::MAX_CREDENTIAL_TYPE_LENGTH)?;
        }

        validation::require_len_range(env, credential_data, 1, Self::MAX_CREDENTIAL_DATA_LENGTH)?;
        validation::require_non_empty(env, proof)?;

        // Back-dated expirations are allowed (administrative correction), but
        // an unbounded future date would pin storage forever, so cap it.
        if let Some(exp) = expiration_date {
            validation::require_timestamp_horizon(env, exp)?;
        }

        Ok(())
    }

    pub fn issue_credential_with_schema(
        env: Env,
        issuer: Address,
        subject: Address,
        credential_type: Vec<Bytes>,
        credential_data: Bytes,
        schema_id: Bytes,
        expiration_date: Option<u64>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        // Schema-bound issuance is throttled under the same issuance budget so
        // an issuer cannot bypass its limit by routing through a schema (#201).
        Self::enforce_rate_limit(
            &env,
            &issuer,
            &Symbol::new(&env, "issue_cred"),
            RateLimitConfig::new(
                rate_limiter::defaults::ISSUE_CREDENTIAL_WINDOW,
                rate_limiter::defaults::ISSUE_CREDENTIAL_MAX,
            ),
        )?;

        use crate::schema_registry::CredentialSchemaRegistry;
        let _schema = CredentialSchemaRegistry::get_schema(env.clone(), schema_id.clone(), None)
            .map_err(|_| CredentialIssuerError::SchemaNotFound)?;

        CredentialSchemaRegistry::validate_schema_exists(env.clone(), schema_id.clone())
            .map_err(|_| CredentialIssuerError::SchemaValidationFailed)?;

        validation::require_non_zero_address(&env, &issuer)?;
        validation::require_non_zero_address(&env, &subject)?;
        Self::validate_credential_type(&env, &credential_type)?;
        validation::require_len_range(&env, &credential_data, 1, Self::MAX_CREDENTIAL_DATA_LENGTH)?;
        validation::require_non_empty(&env, &proof)?;
        if let Some(exp) = expiration_date {
            validation::require_timestamp_horizon(&env, exp)?;
        }

        let credential_id = Self::generate_credential_id(&env, &issuer, &subject);
        let now = env.ledger().timestamp();

        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            type_: credential_type,
            credential_data,
            issuance_date: now,
            expiration_date,
            schema_id: Some(schema_id.clone()),
            revocation: None,
            proof: Some(proof),
        };

        Self::validate_credential(&env, &credential)?;

        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);
        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &0u32);

        Self::index_credential(&env, None, &issuer, &subject, &credential_id);

        env.events().publish(
            (Symbol::new(&env, "CredentialIssuedWithSchema"),),
            (credential_id.clone(), issuer.clone(), schema_id.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::CredentialCreated,
            issuer,
            Some(subject),
            Some(credential_id.clone()),
            Bytes::from_slice(&env, b"schema_bound"),
        );

        Ok(credential_id)
    }

    /// Verify a credential's status, expiry and proof.
    ///
    /// Throttled per caller: verification is the cheapest and most abusable
    /// entry point, and an unauthenticated read path is exactly what a spam /
    /// DoS vector looks like (#201).
    pub fn verify_credential(
        env: Env,
        caller: Address,
        credential_id: Bytes,
    ) -> Result<bool, CredentialIssuerError> {
        caller.require_auth();

        Self::enforce_rate_limit(
            &env,
            &caller,
            &Symbol::new(&env, "verify_cred"),
            RateLimitConfig::new(
                rate_limiter::defaults::VERIFY_CREDENTIAL_WINDOW,
                rate_limiter::defaults::VERIFY_CREDENTIAL_MAX,
            ),
        )?;

        validation::require_non_empty(&env, &credential_id)?;
        Self::verify_credential_unchecked(env.clone(), credential_id.clone())?;

        env.events().publish(
            (Symbol::new(&env, "CredentialVerified"),),
            (credential_id.clone(), caller.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::CredentialVerified,
            caller,
            None,
            Some(credential_id),
            Bytes::new(&env),
        );

        Ok(true)
    }

    /// Unthrottled verification core, shared with the batch path so a batch
    /// pays for one rate-limit check rather than one per credential.
    fn verify_credential_unchecked(
        env: Env,
        credential_id: Bytes,
    ) -> Result<bool, CredentialIssuerError> {
        let credential: VerifiableCredential = env
            .storage()
            .persistent()
            .get(&CredKey::Credential(credential_id.clone()))
            .ok_or(CredentialIssuerError::NotFound)?;

        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id))
            .unwrap_or(0);
        if status == 1 {
            return Ok(false);
        }

        if let Some(expiration) = credential.expiration_date {
            if env.ledger().timestamp() > expiration {
                return Ok(false);
            }
        }

        if let Some(ref proof) = credential.proof {
            Self::verify_proof(&env, proof, &credential)?;
        }

        Ok(true)
    }

    pub fn revoke_credential(
        env: Env,
        issuer: Address,
        credential_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<(), CredentialIssuerError> {
        issuer.require_auth();

        validation::require_non_zero_address(&env, &issuer)?;
        validation::require_non_empty(&env, &credential_id)?;
        if let Some(ref r) = reason {
            validation::require_non_empty(&env, r)?;
            validation::require_max_len(&env, r, validation::MAX_DETAIL_BYTES)?;
        }

        let mut credential: VerifiableCredential = env
            .storage()
            .persistent()
            .get(&CredKey::Credential(credential_id.clone()))
            .ok_or(CredentialIssuerError::NotFound)?;

        if credential.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id.clone()))
            .unwrap_or(0);
        if status == 1 {
            return Err(CredentialIssuerError::AlreadyRevoked);
        }

        credential.revocation = Some(Bytes::from_slice(
            &env,
            env.ledger().timestamp().to_string().as_bytes(),
        ));
        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);
        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &1u32);

        if let Some(ref reason_bytes) = reason {
            env.storage()
                .persistent()
                .set(&CredKey::Reason(credential_id.clone()), &reason_bytes);
        }

        env.events().publish(
            (Symbol::new(&env, "CredentialRevoked"),),
            (credential_id.clone(), issuer.clone(), reason.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::CredentialRevoked,
            issuer,
            Some(credential.subject),
            Some(credential_id),
            reason.unwrap_or(Bytes::from_slice(&env, b"unspecified")),
        );

        Ok(())
    }

    pub fn get_credential(
        env: Env,
        credential_id: Bytes,
    ) -> Result<VerifiableCredential, CredentialIssuerError> {
        validation::require_non_empty(&env, &credential_id)?;
        env.storage()
            .persistent()
            .get(&CredKey::Credential(credential_id))
            .ok_or(CredentialIssuerError::NotFound)
    }

    pub fn get_issuer_credentials(env: Env, issuer: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::IssuerCreds(issuer))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_subject_credentials(env: Env, subject: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::SubjectCreds(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_credentials_by_subject(
        env: Env,
        subject: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedCredentials {
        let all: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::SubjectCreds(subject))
            .unwrap_or_else(|| Vec::new(&env));
        Self::paginate_bytes(&env, &all, page, page_size)
    }

    pub fn get_credentials_by_issuer(
        env: Env,
        issuer: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedCredentials {
        let all: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::IssuerCreds(issuer))
            .unwrap_or_else(|| Vec::new(&env));
        Self::paginate_bytes(&env, &all, page, page_size)
    }

    pub fn get_credential_status(env: Env, credential_id: Bytes) -> Bytes {
        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id))
            .unwrap_or(255);
        match status {
            0 => Bytes::from_slice(&env, b"active"),
            1 => Bytes::from_slice(&env, b"revoked"),
            _ => Bytes::from_slice(&env, b"unknown"),
        }
    }

    /// Verify many credentials in one call.
    ///
    /// Two optimisations over calling `verify_credential` per id (#197):
    ///  - a single rate-limit check covers the whole batch, so a 50-item batch
    ///    costs one quota unit rather than 50;
    ///  - repeated ids are verified once and the result is memoised, so a
    ///    batch of duplicates performs a single storage read.
    ///
    /// The result vector is positionally aligned with the input: an unknown id
    /// yields `false` rather than aborting the whole batch.
    pub fn batch_verify_credentials(
        env: Env,
        caller: Address,
        credential_ids: Vec<Bytes>,
    ) -> Result<Vec<bool>, CredentialIssuerError> {
        caller.require_auth();

        Self::enforce_rate_limit(
            &env,
            &caller,
            &Symbol::new(&env, "batch_verify"),
            RateLimitConfig::new(
                rate_limiter::defaults::BATCH_VERIFY_WINDOW,
                rate_limiter::defaults::BATCH_VERIFY_MAX,
            ),
        )?;

        validation::require_batch_len(credential_ids.len(), Self::MAX_BATCH_SIZE)?;

        let mut results = Vec::new(&env);
        let mut memo: Vec<(Bytes, bool)> = Vec::new(&env);

        for credential_id in credential_ids.iter() {
            let cached = memo
                .iter()
                .find(|(id, _)| id == &credential_id)
                .map(|(_, v)| v);
            let is_valid = match cached {
                Some(v) => v,
                None => {
                    let v = Self::verify_credential_unchecked(env.clone(), credential_id.clone())
                        .unwrap_or(false);
                    memo.push_back((credential_id.clone(), v));
                    v
                }
            };
            results.push_back(is_valid);
        }

        env.events().publish(
            (Symbol::new(&env, "BatchCredentialsVerified"),),
            (caller, credential_ids.len()),
        );

        Ok(results)
    }

    /// Issue multiple credentials in a single transaction (#81, #197).
    ///
    /// Gas: the issuer and subject index vectors are staged and written once
    /// for the whole batch rather than once per credential, and the indexed
    /// event log is flushed once instead of once per credential. For a batch of
    /// `n` credentials against `k` distinct subjects that removes `2(n - k)`
    /// index storage operations and `3n` event-index operations.
    ///
    /// If any credential fails validation the entire batch reverts (atomic).
    /// Maximum batch size is enforced by `MAX_BATCH_SIZE` (default 50).
    pub fn batch_issue_credentials(
        env: Env,
        issuer: Address,
        items: Vec<BatchIssuanceItem>,
    ) -> Result<Vec<Bytes>, CredentialIssuerError> {
        issuer.require_auth();

        // One quota unit for the whole batch: a batch is a single user action.
        Self::enforce_rate_limit(
            &env,
            &issuer,
            &Symbol::new(&env, "batch_issue"),
            RateLimitConfig::new(
                rate_limiter::defaults::BATCH_ISSUE_WINDOW,
                rate_limiter::defaults::BATCH_ISSUE_MAX,
            ),
        )?;

        let batch_len = items.len();
        if batch_len == 0 {
            return Err(CredentialIssuerError::EmptyField);
        }
        if batch_len > Self::MAX_BATCH_SIZE {
            return Err(CredentialIssuerError::FieldTooLong);
        }

        let mut index_batch = IndexAppender::new(&env);
        let mut issued_ids = Vec::new(&env);
        let mut subject_for_id: Vec<(Bytes, Address)> = Vec::new(&env);

        for item in items.iter() {
            let credential_id = Self::store_credential(
                &env,
                &issuer,
                &item.subject,
                &item.credential_type,
                &item.credential_data,
                item.expiration_date,
                &item.proof,
                Some(&mut index_batch),
            )?;
            issued_ids.push_back(credential_id.clone());
            subject_for_id.push_back((credential_id, item.subject.clone()));
        }

        // Single write per tracked index vector.
        let mut writer = |e: &Env, k: &IndexKey, v: &Vec<Bytes>| write_index(e, k, v);
        index_batch.flush(&env, &mut writer);

        // Single flush for every indexed event in the batch (#195).
        let mut events = event_index::record_event_batch(&env);
        for (id, subject) in subject_for_id.iter() {
            events.push(
                &env,
                IndexedEventType::CredentialCreated,
                issuer.clone(),
                Some(subject.clone()),
                Some(id.clone()),
                Bytes::from_slice(&env, b"batch"),
            );
        }
        events.flush(&env);

        env.events().publish(
            (Symbol::new(&env, "BatchCredentialIssued"),),
            (issuer, issued_ids.len() as u32, issued_ids.clone()),
        );

        Ok(issued_ids)
    }

    pub fn get_revocation_reason(env: Env, credential_id: Bytes) -> Option<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::Reason(credential_id))
    }

    // -----------------------------------------------------------------------
    // Issuer Authorization (#41)
    // -----------------------------------------------------------------------

    /// Authorize an address to issue credentials. Emits IssuerAuthorized event.
    /// Only the contract admin may call this.
    pub fn authorize_issuer(
        env: Env,
        admin: Address,
        issuer: Address,
    ) -> Result<(), CredentialIssuerError> {
        admin.require_auth();
        admin::only_admin(&env, &admin).map_err(|_| CredentialIssuerError::Unauthorized)?;
        validation::require_non_zero_address(&env, &issuer)?;
        validation::require_distinct(&admin, &issuer)?;

        let mut issuers: Vec<Address> = env
            .storage()
            .persistent()
            .get(&CredKey::AuthorizedIssuers)
            .unwrap_or_else(|| Vec::new(&env));

        if issuers.iter().any(|i| i == issuer) {
            return Err(CredentialIssuerError::AlreadyExists);
        }

        issuers.push_back(issuer.clone());
        env.storage()
            .persistent()
            .set(&CredKey::AuthorizedIssuers, &issuers);

        env.events().publish(
            (Symbol::new(&env, "IssuerAuthorized"),),
            (issuer.clone(), admin.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::AdminOperation,
            admin,
            Some(issuer),
            None,
            Bytes::from_slice(&env, b"issuer_authorized"),
        );

        Ok(())
    }

    /// Revoke an address's authorization to issue credentials. Emits IssuerDeauthorized event.
    /// Only the contract admin may call this.
    pub fn deauthorize_issuer(
        env: Env,
        admin: Address,
        issuer: Address,
    ) -> Result<(), CredentialIssuerError> {
        admin.require_auth();
        admin::only_admin(&env, &admin).map_err(|_| CredentialIssuerError::Unauthorized)?;
        validation::require_non_zero_address(&env, &issuer)?;

        let issuers: Vec<Address> = env
            .storage()
            .persistent()
            .get(&CredKey::AuthorizedIssuers)
            .unwrap_or_else(|| Vec::new(&env));

        let mut found = false;
        let mut new_issuers: Vec<Address> = Vec::new(&env);
        for i in issuers.iter() {
            if i == issuer {
                found = true;
            } else {
                new_issuers.push_back(i);
            }
        }

        if !found {
            return Err(CredentialIssuerError::NotFound);
        }

        env.storage()
            .persistent()
            .set(&CredKey::AuthorizedIssuers, &new_issuers);

        env.events().publish(
            (Symbol::new(&env, "IssuerDeauthorized"),),
            (issuer.clone(), admin.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::AdminOperation,
            admin,
            Some(issuer),
            None,
            Bytes::from_slice(&env, b"issuer_deauthorized"),
        );

        Ok(())
    }

    /// Check whether an address is an authorized issuer.
    pub fn is_authorized_issuer(env: Env, issuer: Address) -> bool {
        let issuers: Vec<Address> = env
            .storage()
            .persistent()
            .get(&CredKey::AuthorizedIssuers)
            .unwrap_or_else(|| Vec::new(&env));
        issuers.iter().any(|i| i == issuer)
    }

    pub fn search_credentials_by_type(
        env: Env,
        _credential_type: Bytes,
        _max_results: u32,
    ) -> Vec<Bytes> {
        Vec::new(&env)
    }

    // -----------------------------------------------------------------------
    // Credential expiration & auto-revocation (#43)
    // -----------------------------------------------------------------------

    /// Batch-revoke all credentials whose `expiration_date` has passed.
    ///
    /// Walks through the issuer's credential list and revokes any expired
    /// credential.  Returns the number of credentials that were revoked.
    /// `batch_size` limits how many entries are processed in a single call
    /// (recommended: ≤ 50) to keep gas costs predictable.
    ///
    /// Gas (#197): the issuer index is read once, the shared `revocation_marker`
    /// is built once instead of per credential, and every indexed event for the
    /// batch is flushed in a single pass.
    pub fn revoke_expired_credentials(
        env: Env,
        admin: Address,
        batch_size: u32,
    ) -> Result<u32, CredentialIssuerError> {
        admin.require_auth();

        validation::require_non_zero_address(&env, &admin)?;
        validation::require_positive(&env, batch_size, Self::MAX_BATCH_SIZE)?;

        let now = env.ledger().timestamp();
        let mut revoked = 0u32;
        let expired_reason = Bytes::from_slice(&env, b"expired");
        let marker = Bytes::from_slice(&env, now.to_string().as_bytes());
        let mut revoked_subjects: Vec<Address> = Vec::new(&env);

        let creds: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::IssuerCreds(admin.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        for cred_id in creds.iter() {
            if revoked >= batch_size {
                break;
            }

            let credential: Option<VerifiableCredential> = env
                .storage()
                .persistent()
                .get(&CredKey::Credential(cred_id.clone()));

            if let Some(mut cred) = credential {
                let expired = cred.expiration_date.map(|exp| now > exp).unwrap_or(false);
                if !expired {
                    continue;
                }

                let status: u32 = env
                    .storage()
                    .persistent()
                    .get(&CredKey::Status(cred_id.clone()))
                    .unwrap_or(0);
                if status == 1 {
                    continue;
                }

                cred.revocation = Some(marker.clone());
                env.storage()
                    .persistent()
                    .set(&CredKey::Credential(cred_id.clone()), &cred);
                env.storage()
                    .persistent()
                    .set(&CredKey::Status(cred_id.clone()), &1u32);
                env.storage()
                    .persistent()
                    .set(&CredKey::Reason(cred_id.clone()), &expired_reason);

                revoked_subjects.push_back(cred.subject);
                revoked += 1;
            }
        }

        if revoked > 0 {
            env.events().publish(
                (Symbol::new(&env, "ExpiredCredentialsRevoked"),),
                (admin.clone(), revoked),
            );

            let mut events = event_index::record_event_batch(&env);
            for subject in revoked_subjects.iter() {
                events.push(
                    &env,
                    IndexedEventType::CredentialExpired,
                    admin.clone(),
                    Some(subject.clone()),
                    None,
                    expired_reason.clone(),
                );
            }
            events.flush(&env);
        }

        Ok(revoked)
    }

    /// Renew an existing credential by issuing a new one with an updated
    /// expiration date.  The original credential is NOT automatically
    /// revoked — the issuer must explicitly revoke it if desired.
    ///
    /// Returns the ID of the newly issued credential.
    ///
    /// Auth and rate limiting are applied once, here, and the write goes
    /// through the shared issuance path. Delegating to `issue_credential`
    /// would re-require auth for the same address inside a single frame (which
    /// Soroban rejects) and would charge the issuer's quota twice for one
    /// renewal.
    pub fn renew_credential(
        env: Env,
        issuer: Address,
        credential_id: Bytes,
        new_expiration_date: u64,
        new_proof: Bytes,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        Self::enforce_rate_limit(
            &env,
            &issuer,
            &Symbol::new(&env, "issue_cred"),
            RateLimitConfig::new(
                rate_limiter::defaults::ISSUE_CREDENTIAL_WINDOW,
                rate_limiter::defaults::ISSUE_CREDENTIAL_MAX,
            ),
        )?;

        validation::require_non_zero_address(&env, &issuer)?;
        validation::require_non_empty(&env, &credential_id)?;

        let credential: VerifiableCredential = env
            .storage()
            .persistent()
            .get(&CredKey::Credential(credential_id.clone()))
            .ok_or(CredentialIssuerError::NotFound)?;

        if credential.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        if new_expiration_date <= env.ledger().timestamp() {
            return Err(CredentialIssuerError::Expired);
        }
        validation::require_timestamp_horizon(&env, new_expiration_date)?;

        ReentrancyGuard::acquire(&env, "issue_cred")
            .map_err(|_| CredentialIssuerError::Unauthorized)?;

        let renewed_id = Self::store_credential(
            &env,
            &issuer,
            &credential.subject,
            &credential.type_,
            &credential.credential_data,
            Some(new_expiration_date),
            &new_proof,
            None,
        )?;

        env.events().publish(
            (Symbol::new(&env, "CredentialRenewed"),),
            (renewed_id.clone(), issuer.clone(), credential_id),
        );
        event_index::record_event(
            &env,
            IndexedEventType::CredentialUpdated,
            issuer,
            Some(credential.subject),
            Some(renewed_id.clone()),
            Bytes::from_slice(&env, b"renewed"),
        );

        ReentrancyGuard::release(&env, "issue_cred");
        Ok(renewed_id)
    }

    // -----------------------------------------------------------------------
    // Delegated Credential Issuance (#92)
    // -----------------------------------------------------------------------

    /// Authorize a delegate to issue credentials on the delegator's behalf.
    ///
    /// Validates both addresses, the authorized-type list, the issuance cap and
    /// the expiry horizon so a malformed delegation cannot be persisted (#200).
    pub fn authorize_delegation(
        env: Env,
        delegator: Address,
        delegate: Address,
        authorized_types: Vec<Bytes>,
        max_issuances: u32,
        expires_at: u64,
    ) -> Result<Bytes, CredentialIssuerError> {
        delegator.require_auth();

        validation::require_non_zero_address(&env, &delegator)?;
        validation::require_non_zero_address(&env, &delegate)?;
        validation::require_distinct(&delegator, &delegate)?;

        if authorized_types.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        for at in authorized_types.iter() {
            validation::require_non_empty(&env, &at)?;
            validation::require_max_len(&env, &at, Self::MAX_CREDENTIAL_TYPE_LENGTH)?;
        }
        validation::require_positive(&env, max_issuances, Self::MAX_DELEGATION_ISSUANCES)?;
        if expires_at <= env.ledger().timestamp() {
            return Err(CredentialIssuerError::DelegationExpired);
        }
        validation::require_future_within_horizon(&env, expires_at)?;

        let auth_id = Self::generate_delegation_id(&env, &delegator, &delegate);

        let auth = DelegationAuthorization {
            id: auth_id.clone(),
            delegator: delegator.clone(),
            delegate: delegate.clone(),
            authorized_types: authorized_types.clone(),
            max_issuances,
            issued_count: 0,
            expires_at,
            active: true,
        };

        env.storage()
            .persistent()
            .set(&CredKey::Delegation(auth_id.clone()), &auth);

        let mut delegate_auths: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::DelegateAuths(delegate.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        delegate_auths.push_back(auth_id.clone());
        env.storage()
            .persistent()
            .set(&CredKey::DelegateAuths(delegate.clone()), &delegate_auths);

        let mut delegator_auths: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&CredKey::DelegatorAuths(delegator.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        delegator_auths.push_back(auth_id.clone());
        env.storage().persistent().set(
            &CredKey::DelegatorAuths(delegator.clone()),
            &delegator_auths,
        );

        env.events().publish(
            (Symbol::new(&env, "DelegationAuthorized"),),
            (auth_id.clone(), delegator.clone(), delegate.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::DelegationGranted,
            delegator,
            Some(delegate),
            Some(auth_id.clone()),
            Bytes::from_slice(&env, b"granted"),
        );

        Ok(auth_id)
    }

    pub fn revoke_delegation(
        env: Env,
        delegator: Address,
        auth_id: Bytes,
    ) -> Result<(), CredentialIssuerError> {
        delegator.require_auth();

        validation::require_non_zero_address(&env, &delegator)?;
        validation::require_non_empty(&env, &auth_id)?;

        let mut auth: DelegationAuthorization = env
            .storage()
            .persistent()
            .get(&CredKey::Delegation(auth_id.clone()))
            .ok_or(CredentialIssuerError::DelegationNotFound)?;

        if auth.delegator != delegator {
            return Err(CredentialIssuerError::Unauthorized);
        }

        if !auth.active {
            return Err(CredentialIssuerError::DelegationRevoked);
        }

        auth.active = false;
        env.storage()
            .persistent()
            .set(&CredKey::Delegation(auth_id.clone()), &auth);

        env.events().publish(
            (Symbol::new(&env, "DelegationRevoked"),),
            (auth_id.clone(), delegator.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::DelegationRevoked,
            delegator,
            Some(auth.delegate),
            Some(auth_id),
            Bytes::from_slice(&env, b"revoked"),
        );

        Ok(())
    }

    pub fn issue_delegated_credential(
        env: Env,
        delegate: Address,
        auth_id: Bytes,
        subject: Address,
        credential_type: Vec<Bytes>,
        credential_data: Bytes,
        expiration_date: Option<u64>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialIssuerError> {
        delegate.require_auth();

        validation::require_non_zero_address(&env, &delegate)?;
        validation::require_non_zero_address(&env, &subject)?;
        validation::require_non_empty(&env, &auth_id)?;

        let mut auth: DelegationAuthorization = env
            .storage()
            .persistent()
            .get(&CredKey::Delegation(auth_id.clone()))
            .ok_or(CredentialIssuerError::DelegationNotFound)?;

        if !auth.active {
            return Err(CredentialIssuerError::DelegationRevoked);
        }

        if auth.delegate != delegate {
            return Err(CredentialIssuerError::Unauthorized);
        }

        if env.ledger().timestamp() > auth.expires_at {
            auth.active = false;
            env.storage()
                .persistent()
                .set(&CredKey::Delegation(auth_id), &auth);
            return Err(CredentialIssuerError::DelegationExpired);
        }

        if auth.issued_count >= auth.max_issuances {
            return Err(CredentialIssuerError::DelegationLimitExceeded);
        }

        for ct in credential_type.iter() {
            let mut authorized = false;
            for at in auth.authorized_types.iter() {
                if ct == at {
                    authorized = true;
                    break;
                }
            }
            if !authorized {
                return Err(CredentialIssuerError::UnauthorizedCredentialType);
            }
        }

        Self::validate_credential_type(&env, &credential_type)?;
        validation::require_len_range(&env, &credential_data, 1, Self::MAX_CREDENTIAL_DATA_LENGTH)?;
        validation::require_non_empty(&env, &proof)?;
        if let Some(exp) = expiration_date {
            validation::require_timestamp_horizon(&env, exp)?;
        }

        // Delegates share the delegator's issuance quota so a compromised
        // delegate cannot be used to sidestep the per-address limit (#201).
        Self::enforce_rate_limit(
            &env,
            &auth.delegator,
            &Symbol::new(&env, "issue_cred"),
            RateLimitConfig::new(
                rate_limiter::defaults::ISSUE_CREDENTIAL_WINDOW,
                rate_limiter::defaults::ISSUE_CREDENTIAL_MAX,
            ),
        )?;

        let credential_id = Self::generate_credential_id(&env, &auth.delegator, &subject);
        let now = env.ledger().timestamp();

        let credential = VerifiableCredential {
            id: credential_id.clone(),
            issuer: auth.delegator.clone(),
            subject: subject.clone(),
            type_: credential_type,
            credential_data,
            issuance_date: now,
            expiration_date,
            schema_id: None,
            revocation: None,
            proof: Some(proof),
        };

        Self::validate_credential(&env, &credential)?;

        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), &credential);
        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &0u32);

        Self::index_credential(&env, None, &auth.delegator, &subject, &credential_id);

        auth.issued_count += 1;
        env.storage()
            .persistent()
            .set(&CredKey::Delegation(auth_id.clone()), &auth);

        env.events().publish(
            (Symbol::new(&env, "DelegatedCredentialIssued"),),
            (credential_id.clone(), delegate.clone()),
        );
        event_index::record_event(
            &env,
            IndexedEventType::CredentialCreated,
            delegate,
            Some(subject),
            Some(credential_id.clone()),
            Bytes::from_slice(&env, b"delegated"),
        );

        Ok(credential_id)
    }

    pub fn get_delegation(env: Env, auth_id: Bytes) -> Option<DelegationAuthorization> {
        env.storage()
            .persistent()
            .get(&CredKey::Delegation(auth_id))
    }

    pub fn get_delegate_authorizations(env: Env, delegate: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::DelegateAuths(delegate))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_delegator_authorizations(env: Env, delegator: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&CredKey::DelegatorAuths(delegator))
            .unwrap_or_else(|| Vec::new(&env))
    }

    // -----------------------------------------------------------------------
    // Credential Revocation Registry (#91)
    // -----------------------------------------------------------------------

    pub fn create_revocation_registry(
        env: Env,
        issuer: Address,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        let registry_id = Self::generate_registry_id(&env, &issuer);
        let now = env.ledger().timestamp();

        let nonce = Bytes::from_slice(
            &env,
            env.crypto()
                .sha256(&Bytes::from_slice(&env, now.to_string().as_bytes()))
                .to_array()
                .as_slice(),
        );

        let registry = RevocationRegistryEntry {
            id: registry_id.clone(),
            issuer: issuer.clone(),
            credential_ids: Vec::new(&env),
            nonce,
            created: now,
            revoked_count: 0,
        };

        env.storage()
            .persistent()
            .set(&CredKey::RevocationRegistry(registry_id.clone()), &registry);

        env.events().publish(
            (Symbol::new(&env, "RevocationRegistryCreated"),),
            (registry_id.clone(), issuer),
        );

        Ok(registry_id)
    }

    pub fn revoke_credential_with_registry(
        env: Env,
        issuer: Address,
        credential_id: Bytes,
        registry_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<(), CredentialIssuerError> {
        Self::revoke_credential(
            env.clone(),
            issuer.clone(),
            credential_id.clone(),
            reason.clone(),
        )?;

        let mut registry: RevocationRegistryEntry = env
            .storage()
            .persistent()
            .get(&CredKey::RevocationRegistry(registry_id.clone()))
            .ok_or(CredentialIssuerError::RegistryNotFound)?;

        if registry.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        let nonce = Bytes::from_slice(
            &env,
            env.crypto()
                .sha256(&Bytes::from_slice(
                    &env,
                    env.ledger().timestamp().to_string().as_bytes(),
                ))
                .to_array()
                .as_slice(),
        );

        let proof = RevocationProof {
            registry_id: registry_id.clone(),
            credential_id: credential_id.clone(),
            nonce: nonce.clone(),
            timestamp: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&CredKey::RevocationProof(credential_id.clone()), &proof);

        registry.credential_ids.push_back(credential_id.clone());
        registry.revoked_count += 1;
        registry.nonce = nonce;
        env.storage()
            .persistent()
            .set(&CredKey::RevocationRegistry(registry_id), &registry);

        Ok(())
    }

    /// Revoke many credentials against a registry in one call.
    ///
    /// Gas notes (#197):
    ///  - each credential's status is read once and memoised, so a batch that
    ///    repeats an id costs a single read;
    ///  - the registry vector is accumulated in memory and written once (the
    ///    previous code re-serialised the whole registry per item);
    ///  - the revocation proof is derived from `sha256(now || id)` which is
    ///    computed once per distinct id, not once per occurrence;
    ///  - every indexed event in the batch is flushed in one pass (#195).
    pub fn batch_revoke_credentials(
        env: Env,
        issuer: Address,
        credential_ids: Vec<Bytes>,
        registry_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<Bytes, CredentialIssuerError> {
        issuer.require_auth();

        validation::require_non_zero_address(&env, &issuer)?;
        validation::require_non_empty(&env, &registry_id)?;
        validation::require_batch_len(credential_ids.len(), Self::MAX_BATCH_SIZE)?;
        if let Some(ref r) = reason {
            validation::require_max_len(&env, r, validation::MAX_DETAIL_BYTES)?;
        }

        let mut registry: RevocationRegistryEntry = env
            .storage()
            .persistent()
            .get(&CredKey::RevocationRegistry(registry_id.clone()))
            .ok_or(CredentialIssuerError::RegistryNotFound)?;

        if registry.issuer != issuer {
            return Err(CredentialIssuerError::Unauthorized);
        }

        let now = env.ledger().timestamp();
        let revocation_marker = Bytes::from_slice(&env, now.to_string().as_bytes());
        let mut seen: Vec<Bytes> = Vec::new(&env);
        let mut revoked_subjects: Vec<(Bytes, Address)> = Vec::new(&env);

        for credential_id in credential_ids.iter() {
            if seen.iter().any(|s| s == credential_id) {
                continue;
            }
            seen.push_back(credential_id.clone());

            let mut credential: VerifiableCredential = env
                .storage()
                .persistent()
                .get(&CredKey::Credential(credential_id.clone()))
                .ok_or(CredentialIssuerError::NotFound)?;

            if credential.issuer != issuer {
                return Err(CredentialIssuerError::Unauthorized);
            }

            let status: u32 = env
                .storage()
                .persistent()
                .get(&CredKey::Status(credential_id.clone()))
                .unwrap_or(0);

            if status == 0 {
                Self::revoke_one(
                    &env,
                    &mut credential,
                    &credential_id,
                    &registry_id,
                    &revocation_marker,
                    now,
                    reason.as_ref(),
                );
                revoked_subjects.push_back((credential_id.clone(), credential.subject));
                registry.credential_ids.push_back(credential_id.clone());
                registry.revoked_count += 1;
            }
        }

        registry.nonce = Bytes::from_slice(
            &env,
            env.crypto()
                .sha256(&Bytes::from_slice(&env, now.to_string().as_bytes()))
                .to_array()
                .as_slice(),
        );

        env.storage()
            .persistent()
            .set(&CredKey::RevocationRegistry(registry_id.clone()), &registry);

        let batch_id = Self::generate_batch_id(&env, &issuer);

        let batch_record = BatchRevocationRecord {
            batch_id: batch_id.clone(),
            issuer: issuer.clone(),
            credential_ids: credential_ids.clone(),
            reason: reason.clone(),
            timestamp: now,
        };

        env.storage()
            .persistent()
            .set(&CredKey::BatchRevocation(batch_id.clone()), &batch_record);

        let mut events = event_index::record_event_batch(&env);
        for (id, subject) in revoked_subjects.iter() {
            events.push(
                &env,
                IndexedEventType::CredentialRevoked,
                issuer.clone(),
                Some(subject.clone()),
                Some(id.clone()),
                reason.clone().unwrap_or(Bytes::new(&env)),
            );
        }
        events.flush(&env);

        env.events().publish(
            (Symbol::new(&env, "BatchRevocationExecuted"),),
            (batch_id.clone(), registry_id, issuer),
        );

        Ok(batch_id)
    }

    pub fn check_revocation_status(env: Env, credential_id: Bytes) -> bool {
        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id))
            .unwrap_or(0);
        status == 1
    }

    pub fn get_revocation_proof(env: Env, credential_id: Bytes) -> Option<RevocationProof> {
        env.storage()
            .persistent()
            .get(&CredKey::RevocationProof(credential_id))
    }

    pub fn verify_revocation_proof(
        env: Env,
        credential_id: Bytes,
        proof: RevocationProof,
    ) -> Result<bool, CredentialIssuerError> {
        let stored: RevocationProof = env
            .storage()
            .persistent()
            .get(&CredKey::RevocationProof(credential_id.clone()))
            .ok_or(CredentialIssuerError::RegistryNotFound)?;

        if stored.credential_id != proof.credential_id {
            return Ok(false);
        }
        if stored.registry_id != proof.registry_id {
            return Ok(false);
        }
        if stored.nonce != proof.nonce {
            return Ok(false);
        }

        let status: u32 = env
            .storage()
            .persistent()
            .get(&CredKey::Status(credential_id))
            .unwrap_or(0);

        Ok(status == 1)
    }

    pub fn get_revocation_registry(
        env: Env,
        registry_id: Bytes,
    ) -> Option<RevocationRegistryEntry> {
        env.storage()
            .persistent()
            .get(&CredKey::RevocationRegistry(registry_id))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Apply the revocation state for a single credential and persist it.
    ///
    /// Extracted from `batch_revoke_credentials` so the single and batch
    /// revocation paths cannot drift apart.
    #[allow(clippy::too_many_arguments)]
    fn revoke_one(
        env: &Env,
        credential: &mut VerifiableCredential,
        credential_id: &Bytes,
        registry_id: &Bytes,
        revocation_marker: &Bytes,
        now: u64,
        reason: Option<&Bytes>,
    ) {
        credential.revocation = Some(revocation_marker.clone());
        env.storage()
            .persistent()
            .set(&CredKey::Credential(credential_id.clone()), credential);
        env.storage()
            .persistent()
            .set(&CredKey::Status(credential_id.clone()), &1u32);

        if let Some(r) = reason {
            env.storage()
                .persistent()
                .set(&CredKey::Reason(credential_id.clone()), r);
        }

        let mut data = Bytes::from_slice(env, &now.to_be_bytes());
        data.append(credential_id);
        let hash = env.crypto().sha256(&data);
        let hash_bytes: BytesN<32> = hash.into();
        let proof = RevocationProof {
            registry_id: registry_id.clone(),
            credential_id: credential_id.clone(),
            nonce: Bytes::from_slice(env, hash_bytes.to_array().as_slice()),
            timestamp: now,
        };
        env.storage()
            .persistent()
            .set(&CredKey::RevocationProof(credential_id.clone()), &proof);
    }

    /// Validate the `credential_type` vector: non-empty, every entry
    /// non-empty and within the length cap.
    fn validate_credential_type(
        env: &Env,
        credential_type: &Vec<Bytes>,
    ) -> Result<(), CredentialIssuerError> {
        if credential_type.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        for ct in credential_type.iter() {
            validation::require_non_empty(env, &ct)?;
            validation::require_max_len(env, &ct, Self::MAX_CREDENTIAL_TYPE_LENGTH)?;
        }
        Ok(())
    }

    /// Apply the per-address rate limit for `operation` (#201).
    fn enforce_rate_limit(
        env: &Env,
        caller: &Address,
        operation: &Symbol,
        fallback: RateLimitConfig,
    ) -> Result<RateLimitStatus, CredentialIssuerError> {
        rate_limiter::check_operation(env, caller, operation, fallback).map_err(Into::into)
    }

    /// Build a unique credential id of the form `vc:<timestamp>:<counter>`.
    ///
    /// The ledger timestamp alone is not unique: two credentials issued in the
    /// same transaction (a batch, or a delegation) would collide and silently
    /// overwrite each other, so a monotonic counter is mixed in. Batch callers
    /// therefore get `n` distinct ids from a single transaction.
    fn generate_credential_id(env: &Env, _issuer: &Address, _subject: &Address) -> Bytes {
        let next: u64 = env
            .storage()
            .instance()
            .get(&CredKey::IssuanceCounter)
            .unwrap_or(0)
            + 1;
        env.storage()
            .instance()
            .set(&CredKey::IssuanceCounter, &next);

        let mut id = Bytes::from_slice(env, b"vc:");
        id.append(&Bytes::from_slice(
            env,
            env.ledger().timestamp().to_string().as_bytes(),
        ));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(env, &next.to_be_bytes()));
        id
    }

    fn generate_delegation_id(env: &Env, _delegator: &Address, _delegate: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"del:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }

    fn generate_registry_id(env: &Env, _issuer: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"reg:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }

    fn generate_batch_id(env: &Env, _issuer: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"batch:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }

    fn validate_credential(
        _env: &Env,
        credential: &VerifiableCredential,
    ) -> Result<(), CredentialIssuerError> {
        if credential.credential_data.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        if credential.type_.is_empty() {
            return Err(CredentialIssuerError::InvalidCredential);
        }
        if let Some(proof) = &credential.proof {
            if proof.is_empty() {
                return Err(CredentialIssuerError::InvalidSignature);
            }
        }
        Ok(())
    }

    fn verify_proof(
        _env: &Env,
        proof: &Bytes,
        _credential: &VerifiableCredential,
    ) -> Result<(), CredentialIssuerError> {
        if proof.is_empty() {
            return Err(CredentialIssuerError::InvalidSignature);
        }
        Ok(())
    }

    fn paginate_bytes(
        env: &Env,
        items: &Vec<Bytes>,
        page: u32,
        page_size: u32,
    ) -> PaginatedCredentials {
        let size = clamp_page_size(page_size);
        let total = items.len() as u32;
        let start = page * size;
        let mut data = Vec::new(env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(item) = items.get(i) {
                    data.push_back(item);
                }
            }
        }

        PaginatedCredentials {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }

    // ── Contract Upgrade (#275) ──────────────────────────────────────────────

    /// Initialize the upgrade module with an admin and initial WASM hash.
    /// Must be called once during contract deployment.
    pub fn init_upgrade(
        env: Env,
        admin: Address,
        initial_wasm_hash: BytesN<32>,
    ) -> Result<(), CredentialIssuerError> {
        admin.require_auth();
        if contract_upgrade::is_initialized(&env) {
            return Err(CredentialIssuerError::AlreadyExists);
        }
        contract_upgrade::init(&env, admin, initial_wasm_hash);
        Ok(())
    }

    /// Upgrade the contract to a new WASM hash.
    /// Only the registered admin can perform this operation.
    pub fn upgrade(
        env: Env,
        caller: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), CredentialIssuerError> {
        caller.require_auth();
        contract_upgrade::upgrade(&env, &caller, new_wasm_hash)
            .map_err(|_| CredentialIssuerError::Unauthorized)
    }

    /// Return the current contract version.
    pub fn get_contract_version(env: Env) -> u32 {
        contract_upgrade::get_contract_version(&env)
    }

    /// Return the current deployed WASM hash.
    pub fn get_wasm_hash(env: Env) -> Option<BytesN<32>> {
        contract_upgrade::get_wasm_hash(&env)
    }

    /// Return the full version history for audit purposes.
    pub fn get_version_history(env: Env) -> Vec<contract_upgrade::VersionRecord> {
        contract_upgrade::get_version_history(&env)
    }

    // -----------------------------------------------------------------------
    // Administration (#42, #201)
    // -----------------------------------------------------------------------

    /// Initialise the contract admin. Must be called exactly once.
    ///
    /// Every admin-only entry point below (`authorize_issuer`, the rate-limit
    /// setters, the exemption setters) is gated on this address.
    pub fn init_admin(env: Env, admin: Address) -> Result<(), CredentialIssuerError> {
        admin.require_auth();
        validation::require_non_zero_address(&env, &admin)?;
        admin::init(&env, admin).map_err(|_| CredentialIssuerError::AlreadyExists)
    }

    /// Return the current admin, if initialised.
    pub fn get_admin(env: Env) -> Option<Address> {
        admin::get_admin(&env)
    }

    /// Transfer the admin role. Admin only.
    pub fn transfer_admin(
        env: Env,
        caller: Address,
        new_admin: Address,
    ) -> Result<(), CredentialIssuerError> {
        caller.require_auth();
        validation::require_non_zero_address(&env, &new_admin)?;
        admin::transfer_admin(&env, &caller, new_admin)
            .map_err(|_| CredentialIssuerError::Unauthorized)
    }

    // -----------------------------------------------------------------------
    // Rate limit administration (#201)
    // -----------------------------------------------------------------------

    /// Override the rate limit for an operation. Admin only.
    ///
    /// `operation` is the short symbol used internally, e.g. `issue_cred`,
    /// `verify_cred`, `batch_issue`, `batch_verify`. Pass
    /// `RateLimitConfig::disabled()` to lift throttling entirely.
    pub fn set_rate_limit(
        env: Env,
        admin: Address,
        operation: Symbol,
        config: RateLimitConfig,
    ) -> Result<(), CredentialIssuerError> {
        admin.require_auth();
        rate_limiter::set_limit(&env, &admin, operation, config).map_err(Into::into)
    }

    /// Read the effective rate limit for an operation (override or default).
    pub fn get_rate_limit(env: Env, operation: Symbol) -> RateLimitConfig {
        rate_limiter::get_limit(
            &env,
            &operation,
            RateLimitConfig::new(
                rate_limiter::defaults::ISSUE_CREDENTIAL_WINDOW,
                rate_limiter::defaults::ISSUE_CREDENTIAL_MAX,
            ),
        )
    }

    /// Remove an override so the compiled-in default applies again. Admin only.
    pub fn clear_rate_limit(
        env: Env,
        admin: Address,
        operation: Symbol,
    ) -> Result<(), CredentialIssuerError> {
        admin.require_auth();
        rate_limiter::clear_limit(&env, &admin, operation).map_err(Into::into)
    }

    /// Exempt a trusted issuer from throttling. Admin only.
    pub fn set_rate_limit_exemption(
        env: Env,
        admin: Address,
        address: Address,
        exempt: bool,
    ) -> Result<(), CredentialIssuerError> {
        admin.require_auth();
        validation::require_non_zero_address(&env, &address)?;
        if exempt {
            rate_limiter::exempt_address(&env, &admin, address).map_err(Into::into)
        } else {
            rate_limiter::unexempt_address(&env, &admin, address).map_err(Into::into)
        }
    }

    /// Whether an address is currently exempt from throttling.
    pub fn is_rate_limit_exempt(env: Env, address: Address) -> bool {
        rate_limiter::is_exempt(&env, &address)
    }

    /// Remaining quota for `(address, operation)` without consuming any.
    ///
    /// Lets a client poll before submitting and schedule its next attempt from
    /// `retry_after_secs` instead of guessing.
    pub fn get_rate_limit_status(env: Env, address: Address, operation: Symbol) -> RateLimitStatus {
        rate_limiter::status(&env, &address, &operation)
    }

    // -----------------------------------------------------------------------
    // Indexed event log queries (#195)
    // -----------------------------------------------------------------------

    /// Query the indexed event log by type / actor / subject / time range with
    /// offset pagination. See [`crate::event_index`].
    pub fn query_events(
        env: Env,
        filter: EventFilter,
        page: u32,
        page_size: u32,
    ) -> event_index::PaginatedEvents {
        event_index::query_events(&env, filter, page, page_size)
    }

    /// Read events sequentially after `cursor` for real-time consumers.
    ///
    /// Poll with `next_cursor` until it is `None`, then poll again from the
    /// last sequence number received.
    pub fn stream_events(env: Env, cursor: Option<u64>, limit: u32) -> EventStreamPage {
        event_index::stream_events(&env, cursor, limit)
    }

    /// Read a single indexed event by sequence number.
    pub fn get_indexed_event(env: Env, seq: u64) -> Option<EventRecord> {
        event_index::get_event(&env, seq)
    }

    /// Sequence number of the newest indexed event.
    pub fn get_event_head(env: Env) -> u64 {
        event_index::event_head(&env)
    }

    /// Total number of indexed events recorded.
    pub fn get_event_count(env: Env) -> u64 {
        event_index::event_count(&env)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Events, Ledger, LedgerInfo};
    use soroban_sdk::{vec, Bytes, Env, Symbol, TryFromVal};

    /// Whether any event published in this transaction carried `name` as a
    /// topic symbol.
    ///
    /// Topics come back as opaque `Val`s (which are not `PartialEq`), so each
    /// candidate is converted back to a `Symbol` before comparing.
    fn has_topic(env: &Env, name: &str) -> bool {
        let symbol = Symbol::new(env, name);
        env.events().all().iter().any(|(_contract, topics, _data)| {
            topics.iter().any(|t| {
                Symbol::try_from_val(env, &t)
                    .map(|s| s == symbol)
                    .unwrap_or(false)
            })
        })
    }

    /// Build an environment plus a registered contract id.
    ///
    /// Tests drive the contract functions directly, so every call must run
    /// inside a contract frame: Soroban refuses to expose instance storage
    /// outside one, and rejects a second `require_auth` from the same address
    /// within a single frame. [`frame`] therefore gives each call its own.
    fn setup_env() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000,
            protocol_version: 22,
            sequence_number: 1000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });
        let host = env.register(CredentialIssuer, ());
        (env, host)
    }

    /// Run one contract call inside its own contract frame.
    fn frame<R>(env: &Env, host: &Address, call: impl FnOnce() -> R) -> R {
        env.as_contract(host, call)
    }

    /// Environment + contract id with `admin` already registered as admin.
    fn setup_env_with_admin() -> (Env, Address, Address) {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        (env, host, admin)
    }

    fn make_cred_type(env: &Env) -> Vec<Bytes> {
        vec![env, Bytes::from_slice(env, b"VerifiableCredential")]
    }

    /// Build a `Bytes` payload of exactly `len` bytes.
    ///
    /// Appending one byte at a time is quadratic in the SDK, so bulk payloads
    /// are sliced from a single buffer.
    fn oversized_bytes(env: &Env, len: u32) -> Bytes {
        let buf: alloc::vec::Vec<u8> = alloc::vec![0x41u8; len as usize];
        Bytes::from_slice(env, &buf)
    }

    // ── Event tests (#41) ─────────────────────────────────────────────────

    #[test]
    fn test_credential_issued_event_emitted() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let proof = Bytes::from_slice(&env, b"valid_proof");

        let result = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
                None,
                proof,
            )
        });
        assert!(result.is_ok());

        assert!(
            has_topic(&env, "CredentialIssued"),
            "expected event topic CredentialIssued"
        );
    }

    #[test]
    fn test_credential_verified_event_emitted() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let verifier = Address::generate(&env);
        let proof = Bytes::from_slice(&env, b"valid_proof");

        let cred_id = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
                None,
                proof,
            )
        })
        .unwrap();

        let result = frame(&env, &host, || {
            CredentialIssuer::verify_credential(env.clone(), verifier, cred_id)
        });
        assert!(result.is_ok());

        assert!(
            has_topic(&env, "CredentialVerified"),
            "expected event topic CredentialVerified"
        );
    }

    #[test]
    fn test_credential_revoked_event_emitted() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let proof = Bytes::from_slice(&env, b"valid_proof");

        let cred_id = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer.clone(),
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
                None,
                proof,
            )
        })
        .unwrap();

        frame(&env, &host, || {
            CredentialIssuer::revoke_credential(
                env.clone(),
                issuer,
                cred_id,
                Some(Bytes::from_slice(&env, b"reason")),
            )
        })
        .unwrap();

        assert!(
            has_topic(&env, "CredentialRevoked"),
            "expected event topic CredentialRevoked"
        );
    }

    #[test]
    fn test_issuer_authorized_event_emitted() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        let issuer = Address::generate(&env);

        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        frame(&env, &host, || {
            CredentialIssuer::authorize_issuer(env.clone(), admin, issuer)
        })
        .unwrap();

        assert!(
            has_topic(&env, "IssuerAuthorized"),
            "expected event topic IssuerAuthorized"
        );
    }

    #[test]
    fn test_issuer_deauthorized_event_emitted() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        let issuer = Address::generate(&env);

        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        frame(&env, &host, || {
            CredentialIssuer::authorize_issuer(env.clone(), admin.clone(), issuer.clone())
        })
        .unwrap();
        frame(&env, &host, || {
            CredentialIssuer::deauthorize_issuer(env.clone(), admin, issuer)
        })
        .unwrap();

        assert!(
            has_topic(&env, "IssuerDeauthorized"),
            "expected event topic IssuerDeauthorized"
        );
    }

    // ── Expiration & auto-revocation tests (#43) ───────────────────────────

    #[test]
    fn test_revoke_expired_credentials_works() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let proof = Bytes::from_slice(&env, b"valid_proof");

        // Issue credential with expiration in the past
        let past = env.ledger().timestamp() - 1000;
        let cred_id = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer.clone(),
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{\"name\":\"Alice\"}"),
                Some(past),
                proof,
            )
        })
        .unwrap();

        let revoked = frame(&env, &host, || {
            CredentialIssuer::revoke_expired_credentials(env.clone(), issuer, 10)
        })
        .unwrap();
        assert_eq!(revoked, 1);

        let status = frame(&env, &host, || {
            CredentialIssuer::get_credential_status(env.clone(), cred_id)
        });
        assert_eq!(status, Bytes::from_slice(&env, b"revoked"));
    }

    #[test]
    fn test_revoke_expired_credentials_skips_active() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let proof = Bytes::from_slice(&env, b"valid_proof");

        // Issue credential with expiration far in the future
        let future = env.ledger().timestamp() + 1_000_000;
        frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer.clone(),
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{\"name\":\"Bob\"}"),
                Some(future),
                proof,
            )
        })
        .unwrap();

        let revoked = frame(&env, &host, || {
            CredentialIssuer::revoke_expired_credentials(env.clone(), issuer, 10)
        })
        .unwrap();
        assert_eq!(revoked, 0);
    }

    #[test]
    fn test_renew_credential_creates_new_one() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let proof = Bytes::from_slice(&env, b"valid_proof");
        let new_proof = Bytes::from_slice(&env, b"renewed_proof");

        let future = env.ledger().timestamp() + 10_000;
        let cred_id = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer.clone(),
                subject.clone(),
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{\"name\":\"Charlie\"}"),
                Some(future),
                proof,
            )
        })
        .unwrap();

        let new_expiration = env.ledger().timestamp() + 1_000_000;
        let renewed_id = frame(&env, &host, || {
            CredentialIssuer::renew_credential(
                env.clone(),
                issuer,
                cred_id,
                new_expiration,
                new_proof,
            )
        })
        .unwrap();

        // New credential should exist and have the new expiration
        let renewed = frame(&env, &host, || {
            CredentialIssuer::get_credential(env.clone(), renewed_id)
        })
        .unwrap();
        assert_eq!(renewed.subject, subject);
        assert_eq!(renewed.expiration_date, Some(new_expiration));
    }

    #[test]
    fn test_is_authorized_issuer() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        let issuer = Address::generate(&env);
        let other = Address::generate(&env);

        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        frame(&env, &host, || {
            CredentialIssuer::authorize_issuer(env.clone(), admin, issuer.clone())
        })
        .unwrap();

        assert!(frame(&env, &host, || {
            CredentialIssuer::is_authorized_issuer(env.clone(), issuer)
        }));
        assert!(!frame(&env, &host, || {
            CredentialIssuer::is_authorized_issuer(env.clone(), other)
        }));
    }

    // ── Admin initialisation (#42) ─────────────────────────────────────

    #[test]
    fn test_init_admin_sets_admin() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::get_admin(env.clone())),
            Some(admin)
        );
    }

    #[test]
    fn test_init_admin_is_single_shot() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        let other = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin)
        })
        .unwrap();
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::init_admin(
                env.clone(),
                other
            ))
            .unwrap_err(),
            CredentialIssuerError::AlreadyExists
        );
    }

    #[test]
    fn test_transfer_admin_moves_authority() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let issuer = Address::generate(&env);
        let intruder = Address::generate(&env);

        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        frame(&env, &host, || {
            CredentialIssuer::transfer_admin(env.clone(), admin.clone(), new_admin.clone())
        })
        .unwrap();

        // Old admin loses authority.
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::authorize_issuer(
                env.clone(),
                admin,
                issuer.clone()
            ))
            .unwrap_err(),
            CredentialIssuerError::Unauthorized
        );
        // New admin gains it.
        frame(&env, &host, || {
            CredentialIssuer::authorize_issuer(env.clone(), new_admin, issuer)
        })
        .unwrap();
        // Intruders never had it.
        let _ = intruder;
    }

    #[test]
    fn test_authorize_issuer_rejects_admin_self_authorization() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::authorize_issuer(
                env.clone(),
                admin.clone(),
                admin
            ))
            .unwrap_err(),
            CredentialIssuerError::SameAddress
        );
    }

    // ── Input validation (#200) ────────────────────────────────────────

    fn issue_env() -> (Env, Address, Address, Address) {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        (env, host, issuer, subject)
    }

    #[test]
    fn test_empty_credential_type_rejected() {
        let (env, host, issuer, subject) = issue_env();
        let err = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                Vec::new(&env),
                Bytes::from_slice(&env, b"{}"),
                None,
                Bytes::from_slice(&env, b"p"),
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::InvalidCredential);
    }

    #[test]
    fn test_empty_credential_data_rejected_with_specific_code() {
        let (env, host, issuer, subject) = issue_env();
        let err = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                make_cred_type(&env),
                Bytes::new(&env),
                None,
                Bytes::from_slice(&env, b"p"),
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::EmptyField);
    }

    #[test]
    fn test_oversized_credential_type_rejected() {
        let (env, host, issuer, subject) = issue_env();
        let mut long = Bytes::new(&env);
        for _ in 0..200 {
            long.push_back(0x41u8);
        }
        let err = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                vec![&env, long],
                Bytes::from_slice(&env, b"{}"),
                None,
                Bytes::from_slice(&env, b"p"),
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::FieldTooLong);
    }

    #[test]
    fn test_oversized_credential_data_rejected() {
        let (env, host, issuer, subject) = issue_env();
        let big = oversized_bytes(&env, CredentialIssuer::MAX_CREDENTIAL_DATA_LENGTH + 1);
        let err = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                make_cred_type(&env),
                big,
                None,
                Bytes::from_slice(&env, b"p"),
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::FieldTooLong);
    }

    #[test]
    fn test_empty_proof_rejected() {
        let (env, host, issuer, subject) = issue_env();
        let err = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{}"),
                None,
                Bytes::new(&env),
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::EmptyField);
    }

    #[test]
    fn test_immortal_expiration_rejected() {
        let (env, host, issuer, subject) = issue_env();
        let err = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{}"),
                Some(u64::MAX),
                Bytes::from_slice(&env, b"p"),
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::InvalidTimestamp);
    }

    #[test]
    fn test_zero_expiration_rejected() {
        let (env, host, issuer, subject) = issue_env();
        let err = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{}"),
                Some(0),
                Bytes::from_slice(&env, b"p"),
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::InvalidTimestamp);
    }

    #[test]
    fn test_backdated_expiration_is_allowed() {
        let (env, host, issuer, subject) = issue_env();
        let past = env.ledger().timestamp() - 100;
        let id = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer,
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{}"),
                Some(past),
                Bytes::from_slice(&env, b"p"),
            )
        })
        .expect("back-dated expiry is a legitimate correction path");
        assert!(frame(&env, &host, || CredentialIssuer::get_credential(
            env.clone(),
            id
        ))
        .is_ok());
    }

    #[test]
    fn test_get_credential_rejects_empty_id() {
        let (env, host, _, _) = issue_env();
        let empty = Bytes::new(&env);
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::get_credential(
                env.clone(),
                empty
            ))
            .err()
            .unwrap(),
            CredentialIssuerError::EmptyField
        );
    }

    #[test]
    fn test_verify_rejects_empty_credential_id() {
        let (env, host, _, _) = issue_env();
        let verifier = Address::generate(&env);
        let empty = Bytes::new(&env);
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::verify_credential(
                env.clone(),
                verifier,
                empty
            ))
            .err()
            .unwrap(),
            CredentialIssuerError::EmptyField
        );
    }

    #[test]
    fn test_revocation_reason_length_is_capped() {
        let (env, host, issuer, subject) = issue_env();
        let id = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer.clone(),
                subject,
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{}"),
                None,
                Bytes::from_slice(&env, b"p"),
            )
        })
        .unwrap();

        let mut huge = Bytes::new(&env);
        for _ in 0..300 {
            huge.push_back(0x41u8);
        }
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::revoke_credential(
                env.clone(),
                issuer,
                id,
                Some(huge)
            ))
            .unwrap_err(),
            CredentialIssuerError::FieldTooLong
        );
    }

    #[test]
    fn test_delegation_rejects_self_delegation() {
        let (env, host, delegator, _) = issue_env();
        let err = frame(&env, &host, || {
            CredentialIssuer::authorize_delegation(
                env.clone(),
                delegator.clone(),
                delegator,
                make_cred_type(&env),
                5,
                env.ledger().timestamp() + 1000,
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::SameAddress);
    }

    #[test]
    fn test_delegation_rejects_zero_cap() {
        let (env, host, delegator, _) = issue_env();
        let delegate = Address::generate(&env);
        let err = frame(&env, &host, || {
            CredentialIssuer::authorize_delegation(
                env.clone(),
                delegator,
                delegate,
                make_cred_type(&env),
                0,
                env.ledger().timestamp() + 1000,
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::OutOfRange);
    }

    #[test]
    fn test_delegation_rejects_far_future_expiry() {
        let (env, host, delegator, _) = issue_env();
        let delegate = Address::generate(&env);
        let err = frame(&env, &host, || {
            CredentialIssuer::authorize_delegation(
                env.clone(),
                delegator,
                delegate,
                make_cred_type(&env),
                5,
                u64::MAX,
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::InvalidTimestamp);
    }

    // ── Rate limiting (#201) ───────────────────────────────────────────

    fn issue_one(env: &Env, host: &Address, issuer: &Address, subject: &Address) -> Bytes {
        frame(env, host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer.clone(),
                subject.clone(),
                make_cred_type(env),
                Bytes::from_slice(env, b"{}"),
                None,
                Bytes::from_slice(env, b"p"),
            )
        })
        .expect("issuance must succeed")
    }

    #[test]
    fn test_issuance_is_rate_limited_per_address() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        frame(&env, &host, || {
            CredentialIssuer::set_rate_limit(
                env.clone(),
                admin,
                Symbol::new(&env, "issue_cred"),
                RateLimitConfig::new(60, 2),
            )
        })
        .unwrap();

        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        issue_one(&env, &host, &issuer, &subject);
        issue_one(&env, &host, &issuer, &subject);
        let err = frame(&env, &host, || {
            CredentialIssuer::issue_credential(
                env.clone(),
                issuer.clone(),
                subject.clone(),
                make_cred_type(&env),
                Bytes::from_slice(&env, b"{}"),
                None,
                Bytes::from_slice(&env, b"p"),
            )
        })
        .unwrap_err();
        assert_eq!(err, CredentialIssuerError::RateLimitExceeded);
    }

    #[test]
    fn test_rate_limit_does_not_leak_across_addresses() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        frame(&env, &host, || {
            CredentialIssuer::set_rate_limit(
                env.clone(),
                admin,
                Symbol::new(&env, "issue_cred"),
                RateLimitConfig::new(60, 1),
            )
        })
        .unwrap();

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let subject = Address::generate(&env);

        issue_one(&env, &host, &alice, &subject);
        // Bob is unaffected by Alice's exhausted quota.
        issue_one(&env, &host, &bob, &subject);
    }

    #[test]
    fn test_exempt_issuer_bypasses_the_issuance_limit() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        frame(&env, &host, || {
            CredentialIssuer::set_rate_limit(
                env.clone(),
                admin.clone(),
                Symbol::new(&env, "issue_cred"),
                RateLimitConfig::new(60, 1),
            )
        })
        .unwrap();

        let trusted = Address::generate(&env);
        let subject = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::set_rate_limit_exemption(env.clone(), admin, trusted.clone(), true)
        })
        .unwrap();
        assert!(frame(&env, &host, || {
            CredentialIssuer::is_rate_limit_exempt(env.clone(), trusted.clone())
        }));

        for _ in 0..5 {
            issue_one(&env, &host, &trusted, &subject);
        }
    }

    #[test]
    fn test_set_rate_limit_requires_admin() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        let intruder = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin)
        })
        .unwrap();

        assert_eq!(
            frame(&env, &host, || CredentialIssuer::set_rate_limit(
                env.clone(),
                intruder,
                Symbol::new(&env, "issue_cred"),
                RateLimitConfig::new(60, 1),
            ))
            .unwrap_err(),
            CredentialIssuerError::NotAdmin
        );
    }

    #[test]
    fn test_get_rate_limit_reflects_override() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        let op = Symbol::new(&env, "issue_cred");
        frame(&env, &host, || {
            CredentialIssuer::set_rate_limit(
                env.clone(),
                admin.clone(),
                op.clone(),
                RateLimitConfig::new(120, 3),
            )
        })
        .unwrap();

        let cfg = frame(&env, &host, || {
            CredentialIssuer::get_rate_limit(env.clone(), op.clone())
        });
        assert_eq!(cfg.max_calls, 3);
        assert_eq!(cfg.window_secs, 120);

        frame(&env, &host, || {
            CredentialIssuer::clear_rate_limit(env.clone(), admin, op.clone())
        })
        .unwrap();
        let cfg = frame(&env, &host, || {
            CredentialIssuer::get_rate_limit(env.clone(), op)
        });
        assert_eq!(cfg.max_calls, rate_limiter::defaults::ISSUE_CREDENTIAL_MAX);
    }

    #[test]
    fn test_rate_limit_status_reports_remaining_quota() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin.clone())
        })
        .unwrap();
        let op = Symbol::new(&env, "issue_cred");
        frame(&env, &host, || {
            CredentialIssuer::set_rate_limit(
                env.clone(),
                admin,
                op.clone(),
                RateLimitConfig::new(60, 4),
            )
        })
        .unwrap();

        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        issue_one(&env, &host, &issuer, &subject);

        let status = frame(&env, &host, || {
            CredentialIssuer::get_rate_limit_status(env.clone(), issuer, op)
        });
        assert_eq!(status.count, 1);
        assert_eq!(status.remaining, 3);
    }

    // ── Indexed event log (#195) ───────────────────────────────────────

    fn any_event() -> EventFilter {
        EventFilter {
            event_type: None,
            actor: None,
            subject: None,
            from_timestamp: None,
            to_timestamp: None,
        }
    }

    #[test]
    fn test_single_issuance_is_indexed_for_issuer_and_subject() {
        // Regression: the direct (non-batch) index path must actually write the
        // issuer and subject index vectors, otherwise a credential is stored
        // but invisible to `get_issuer_credentials` / `revoke_expired_credentials`.
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let id = issue_one(&env, &host, &issuer, &subject);

        let by_issuer = frame(&env, &host, || {
            CredentialIssuer::get_issuer_credentials(env.clone(), issuer.clone())
        });
        let by_subject = frame(&env, &host, || {
            CredentialIssuer::get_subject_credentials(env.clone(), subject.clone())
        });
        assert_eq!(by_issuer.len(), 1);
        assert_eq!(by_subject.len(), 1);
        assert_eq!(by_issuer.get(0).unwrap(), id);
        assert_eq!(by_subject.get(0).unwrap(), id);
    }

    #[test]
    fn test_credential_ids_are_unique_within_one_transaction() {
        // Regression: the ledger timestamp alone is not unique, so two
        // credentials issued in one batch used to collide and overwrite
        // each other.
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin)
        })
        .unwrap();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let mut items: Vec<BatchIssuanceItem> = Vec::new(&env);
        for n in 0..3u32 {
            items.push_back(BatchIssuanceItem {
                subject: subject.clone(),
                credential_type: make_cred_type(&env),
                credential_data: Bytes::from_slice(&env, &format!("{{\"n\":{}}}", n).as_bytes()),
                expiration_date: None,
                proof: Bytes::from_slice(&env, b"p"),
            });
        }

        let ids = frame(&env, &host, || {
            CredentialIssuer::batch_issue_credentials(env.clone(), issuer.clone(), items)
        })
        .unwrap();

        assert_eq!(ids.len(), 3);
        assert_ne!(ids.get(0).unwrap(), ids.get(1).unwrap());
        assert_ne!(ids.get(1).unwrap(), ids.get(2).unwrap());
        assert_ne!(ids.get(0).unwrap(), ids.get(2).unwrap());
        for i in 0..3u32 {
            assert!(frame(&env, &host, || CredentialIssuer::get_credential(
                env.clone(),
                ids.get(i).unwrap()
            ))
            .is_ok());
        }
    }

    #[test]
    fn test_issuance_is_recorded_in_the_event_log() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        issue_one(&env, &host, &issuer, &subject);

        assert_eq!(
            frame(&env, &host, || CredentialIssuer::get_event_count(
                env.clone()
            )),
            1
        );
        let rec = frame(&env, &host, || {
            CredentialIssuer::get_indexed_event(env.clone(), 1)
        })
        .unwrap();
        assert_eq!(rec.event_type, IndexedEventType::CredentialCreated);
        assert_eq!(rec.actor, issuer);
        assert_eq!(rec.subject, Some(subject));
    }

    #[test]
    fn test_revocation_is_recorded_in_the_event_log() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let id = issue_one(&env, &host, &issuer, &subject);
        frame(&env, &host, || {
            CredentialIssuer::revoke_credential(
                env.clone(),
                issuer,
                id,
                Some(Bytes::from_slice(&env, b"compromised")),
            )
        })
        .unwrap();

        let mut filter = any_event();
        filter.event_type = Some(event_index::type_symbol(
            &env,
            &IndexedEventType::CredentialRevoked,
        ));
        let page = frame(&env, &host, || {
            CredentialIssuer::query_events(env.clone(), filter, 0, 10)
        });
        assert_eq!(page.total, 1);
        assert_eq!(
            page.data.get(0).unwrap().event_type,
            IndexedEventType::CredentialRevoked
        );
    }

    #[test]
    fn test_event_log_can_be_queried_by_actor() {
        let (env, host) = setup_env();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let subject = Address::generate(&env);
        issue_one(&env, &host, &alice, &subject);
        issue_one(&env, &host, &bob, &subject);
        issue_one(&env, &host, &alice, &subject);

        let mut filter = any_event();
        filter.actor = Some(alice);
        let page = frame(&env, &host, || {
            CredentialIssuer::query_events(env.clone(), filter, 0, 10)
        });
        assert_eq!(page.total, 2);
    }

    #[test]
    fn test_event_stream_returns_events_in_order() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        issue_one(&env, &host, &issuer, &subject);
        issue_one(&env, &host, &issuer, &subject);

        let page = frame(&env, &host, || {
            CredentialIssuer::stream_events(env.clone(), None, 10)
        });
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.events.get(0).unwrap().seq, 1);
        assert_eq!(page.events.get(1).unwrap().seq, 2);
        assert!(page.caught_up);
        assert_eq!(page.head, 2);
    }

    #[test]
    fn test_batch_issuance_records_one_event_per_credential() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin)
        })
        .unwrap();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let items: Vec<BatchIssuanceItem> = vec![
            &env,
            BatchIssuanceItem {
                subject: subject.clone(),
                credential_type: make_cred_type(&env),
                credential_data: Bytes::from_slice(&env, b"{\"a\":1}"),
                expiration_date: None,
                proof: Bytes::from_slice(&env, b"p"),
            },
            BatchIssuanceItem {
                subject: subject.clone(),
                credential_type: make_cred_type(&env),
                credential_data: Bytes::from_slice(&env, b"{\"a\":2}"),
                expiration_date: None,
                proof: Bytes::from_slice(&env, b"p"),
            },
        ];

        let ids = frame(&env, &host, || {
            CredentialIssuer::batch_issue_credentials(env.clone(), issuer.clone(), items)
        })
        .unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::get_event_count(
                env.clone()
            )),
            2
        );
    }

    #[test]
    fn test_batch_issuance_indexes_both_credentials_for_the_subject() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin)
        })
        .unwrap();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let items: Vec<BatchIssuanceItem> = vec![
            &env,
            BatchIssuanceItem {
                subject: subject.clone(),
                credential_type: make_cred_type(&env),
                credential_data: Bytes::from_slice(&env, b"{\"a\":1}"),
                expiration_date: None,
                proof: Bytes::from_slice(&env, b"p"),
            },
            BatchIssuanceItem {
                subject: subject.clone(),
                credential_type: make_cred_type(&env),
                credential_data: Bytes::from_slice(&env, b"{\"a\":2}"),
                expiration_date: None,
                proof: Bytes::from_slice(&env, b"p"),
            },
        ];

        frame(&env, &host, || {
            CredentialIssuer::batch_issue_credentials(env.clone(), issuer.clone(), items)
        })
        .unwrap();

        // The staged index appends must be flushed exactly once and contain
        // both credentials.
        let by_issuer = frame(&env, &host, || {
            CredentialIssuer::get_issuer_credentials(env.clone(), issuer)
        });
        let by_subject = frame(&env, &host, || {
            CredentialIssuer::get_subject_credentials(env.clone(), subject)
        });
        assert_eq!(by_issuer.len(), 2);
        assert_eq!(by_subject.len(), 2);
    }

    // ── Batch verification (#197, #201) ────────────────────────────────

    #[test]
    fn test_batch_verify_returns_positional_results() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let verifier = Address::generate(&env);
        let valid = issue_one(&env, &host, &issuer, &subject);
        let revoked = issue_one(&env, &host, &issuer, &subject);
        frame(&env, &host, || {
            CredentialIssuer::revoke_credential(env.clone(), issuer.clone(), revoked.clone(), None)
        })
        .unwrap();

        let results = frame(&env, &host, || {
            CredentialIssuer::batch_verify_credentials(
                env.clone(),
                verifier,
                vec![
                    &env,
                    valid.clone(),
                    revoked.clone(),
                    Bytes::from_slice(&env, b"does-not-exist"),
                ],
            )
        })
        .unwrap();

        assert_eq!(results.len(), 3);
        assert!(results.get(0).unwrap(), "live credential must verify");
        assert!(
            !results.get(1).unwrap(),
            "revoked credential must not verify"
        );
        assert!(
            !results.get(2).unwrap(),
            "unknown ids must not abort the batch"
        );
    }

    #[test]
    fn test_batch_verify_deduplicates_repeated_ids() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let verifier = Address::generate(&env);
        let id = issue_one(&env, &host, &issuer, &subject);

        let results = frame(&env, &host, || {
            CredentialIssuer::batch_verify_credentials(
                env.clone(),
                verifier,
                vec![&env, id.clone(), id.clone(), id.clone()],
            )
        })
        .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r));
    }

    #[test]
    fn test_batch_verify_rejects_empty_batch() {
        let (env, host) = setup_env();
        let verifier = Address::generate(&env);
        let empty = Vec::new(&env);
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::batch_verify_credentials(
                env.clone(),
                verifier,
                empty
            ))
            .err()
            .unwrap(),
            CredentialIssuerError::EmptyField
        );
    }

    #[test]
    fn test_batch_issue_rejects_empty_batch() {
        let (env, host) = setup_env();
        let issuer = Address::generate(&env);
        let empty = Vec::new(&env);
        assert_eq!(
            frame(&env, &host, || CredentialIssuer::batch_issue_credentials(
                env.clone(),
                issuer,
                empty
            ))
            .err()
            .unwrap(),
            CredentialIssuerError::EmptyField
        );
    }

    #[test]
    fn test_batch_issue_rejects_oversized_batch() {
        let (env, host) = setup_env();
        let admin = Address::generate(&env);
        frame(&env, &host, || {
            CredentialIssuer::init_admin(env.clone(), admin)
        })
        .unwrap();
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);

        let mut items: Vec<BatchIssuanceItem> = Vec::new(&env);
        for _ in 0..=CredentialIssuer::MAX_BATCH_SIZE {
            items.push_back(BatchIssuanceItem {
                subject: subject.clone(),
                credential_type: make_cred_type(&env),
                credential_data: Bytes::from_slice(&env, b"{}"),
                expiration_date: None,
                proof: Bytes::from_slice(&env, b"p"),
            });
        }

        assert_eq!(
            frame(&env, &host, || CredentialIssuer::batch_issue_credentials(
                env.clone(),
                issuer,
                items
            ))
            .err()
            .unwrap(),
            CredentialIssuerError::FieldTooLong
        );
    }
}
