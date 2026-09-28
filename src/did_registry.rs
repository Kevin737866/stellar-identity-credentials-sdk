use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Symbol, Vec,
};

use crate::{DIDDocument, Service, VerificationMethod};
use crate::rate_limiter::{check_rate_limit, defaults};

// ---------------------------------------------------------------------------
// Multi-Signature Types (#93)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub struct Signer {
    pub address: Address,
    pub weight: u32,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MultiSigConfig {
    pub signers: Vec<Signer>,
    pub threshold: u32,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingMultiSigOperation {
    pub id: Bytes,
    pub did: Bytes,
    pub operation_data: Bytes,
    pub approvals: Vec<Address>,
    pub executed: bool,
}

// ---------------------------------------------------------------------------
// DID document cache (#265)
// ---------------------------------------------------------------------------

/// Snapshot of a DID document held in temporary storage (#265).
///
/// Expiry is tracked explicitly so correctness never depends on the host's own
/// temporary-entry TTL: the host may evict an entry earlier under storage
/// pressure (which just produces a miss), but never later than `expires_at`.
#[contracttype]
#[derive(Clone)]
pub struct CachedDIDDocument {
    /// Document snapshot, identical to the one in persistent storage.
    pub doc: DIDDocument,
    /// Ledger sequence at which the snapshot was taken.
    pub cached_at: u32,
    /// Ledger sequence at which the snapshot becomes stale (`cached_at + ttl`).
    pub expires_at: u32,
}

// ---------------------------------------------------------------------------
// Namespaced storage keys (#58)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DidKey {
    Doc(Bytes),
    Controller(Address),
    MultiSig(Bytes),
    Operation(Bytes),
    /// Cached DID document (#265), stored in temporary storage.
    Cache(Bytes),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DIDRegistryError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidFormat = 4,
    Deactivated = 5,
    InvalidSignature = 6,
    AlreadyDeactivated = 7,
    /// Caller has exceeded the allowed request rate.
    RateLimitExceeded = 8,
    /// Registry admin has not been configured yet (see [`DIDRegistry::initialize`]).
    AdminNotSet = 9,
    /// Registry admin has already been configured.
    AlreadyInitialized = 10,
    /// Requested cache TTL is outside the supported range.
    InvalidCacheTtl = 11,
}

#[contract]
pub struct DIDRegistry;

#[contractimpl]
impl DIDRegistry {
    const MAX_DID_LENGTH: u32 = 256;
    const MAX_VM_ID_LENGTH: u32 = 128;
    const MAX_SERVICE_ID_LENGTH: u32 = 128;
    const MAX_SERVICE_ENDPOINT_LENGTH: u32 = 512;
    /// Default DID document cache lifetime, in ledgers (#265).
    const DEFAULT_CACHE_TTL_LEDGERS: u32 = 100;
    /// Upper bound accepted by [`DIDRegistry::set_cache_ttl`].
    const MAX_CACHE_TTL_LEDGERS: u32 = 100_000;

    /// Create a new DID on-chain.
    ///
    /// # Security assumptions
    /// - Only the `controller` (authenticated via `require_auth`) may create their DID.
    /// - `did_id` must start with `"did:stellar:"` and be ≤ 256 bytes.
    /// - Duplicate registrations are rejected with [`DIDRegistryError::AlreadyExists`].
    /// - Verification method IDs are capped at 128 bytes; service IDs/endpoints at 128/512 bytes.
    ///
    /// # Emits
    /// `DIDCreated` event with `(did_id, controller)`.
    pub fn create_did(
        env: Env,
        controller: Address,
        did_id: Bytes,
        verification_methods: Vec<VerificationMethod>,
        services: Vec<Service>,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        // Rate limit: max 5 DID creations per controller per 300 seconds
        check_rate_limit(
            &env,
            &controller,
            Symbol::new(&env, "create_did"),
            defaults::CREATE_DID_MAX,
            defaults::CREATE_DID_WINDOW,
        )
        .map_err(|_| DIDRegistryError::RateLimitExceeded)?;

        if !Self::check_did_prefix(&env, &did_id) {
            return Err(DIDRegistryError::InvalidFormat);
        }
        if did_id.len() > Self::MAX_DID_LENGTH {
            return Err(DIDRegistryError::InvalidFormat);
        }
        for vm in verification_methods.iter() {
            if vm.id.len() > Self::MAX_VM_ID_LENGTH {
                return Err(DIDRegistryError::InvalidFormat);
            }
        }
        for svc in services.iter() {
            if svc.id.len() > Self::MAX_SERVICE_ID_LENGTH
                || svc.endpoint.len() > Self::MAX_SERVICE_ENDPOINT_LENGTH
            {
                return Err(DIDRegistryError::InvalidFormat);
            }
        }

        if env.storage().persistent().has(&DidKey::Doc(did_id.clone())) {
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

        env.storage()
            .persistent()
            .set(&DidKey::Doc(did_id.clone()), &doc);
        env.storage()
            .persistent()
            .set(&DidKey::Controller(controller.clone()), &did_id);

        env.events()
            .publish((Symbol::new(&env, "DIDCreated"),), (did_id, controller));

        Ok(())
    }

    /// Resolve a DID document by its DID string.
    ///
    /// Serves the cached snapshot when one is present and unexpired (#265),
    /// otherwise reads persistent storage. A miss never writes, so this stays a
    /// purely read-only call and is still usable inside simulations; populate
    /// the cache with [`DIDRegistry::cache_did_doc`].
    ///
    /// Returns [`DIDRegistryError::NotFound`] if the DID does not exist.
    pub fn resolve_did(env: Env, did: Bytes) -> Result<DIDDocument, DIDRegistryError> {
        if let Some(doc) = Self::read_cached_doc(&env, &did) {
            return Ok(doc);
        }

        env.storage()
            .persistent()
            .get(&DidKey::Doc(did))
            .ok_or(DIDRegistryError::NotFound)
    }

    /// Update verification methods and/or services for the caller's DID.
    ///
    /// Fails if the DID has been deactivated or if the caller is not the controller.
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
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
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
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did.clone()), &doc);

        // Any cached snapshot is now stale (#265).
        Self::purge_cached_doc(&env, &did);

        env.events()
            .publish((Symbol::new(&env, "DIDUpdated"),), (did, controller));

        Ok(())
    }

    /// Permanently deactivate the caller's DID. This action is irreversible.
    ///
    /// # Security note
    /// Only the controller can deactivate. An already-deactivated DID returns
    /// [`DIDRegistryError::AlreadyDeactivated`].
    pub fn deactivate_did(env: Env, controller: Address) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::AlreadyDeactivated);
        }

        doc.deactivated = true;
        doc.updated = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did.clone()), &doc);

        // A deactivated document must never be served from cache (#265).
        Self::purge_cached_doc(&env, &did);

        env.events()
            .publish((Symbol::new(&env, "DIDDeactivated"),), (did, controller));

        Ok(())
    }

    pub fn add_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        doc.authentication.push_back(authentication_method.clone());
        doc.updated = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did.clone()), &doc);

        // The snapshot no longer matches the stored document (#265).
        Self::purge_cached_doc(&env, &did);

        Ok(())
    }

    pub fn remove_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
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
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did.clone()), &doc);

        // The snapshot no longer matches the stored document (#265).
        Self::purge_cached_doc(&env, &did);

        Ok(())
    }

    pub fn verify_signature(
        env: Env,
        did: Bytes,
        message: Bytes,
        signature: BytesN<64>,
    ) -> Result<bool, DIDRegistryError> {
        let doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let vm = doc
            .verification_method
            .get(0)
            .ok_or(DIDRegistryError::NotFound)?;

        env.crypto()
            .ed25519_verify(&vm.public_key, &message, &signature);

        Ok(true)
    }

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
            .get(&DidKey::Doc(did))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let vm = doc
            .verification_method
            .get(method_index)
            .ok_or(DIDRegistryError::NotFound)?;

        env.crypto()
            .ed25519_verify(&vm.public_key, &message, &signature);

        Ok(true)
    }

    pub fn did_exists(env: Env, did: Bytes) -> bool {
        env.storage().persistent().has(&DidKey::Doc(did))
    }

    pub fn get_controller_did(env: Env, controller: Address) -> Option<Bytes> {
        env.storage()
            .persistent()
            .get(&DidKey::Controller(controller))
    }

    // -----------------------------------------------------------------------
    // DID document cache (#265)
    // -----------------------------------------------------------------------

    /// Configure the registry admin.
    ///
    /// The admin is the only account allowed to tune the DID document cache via
    /// [`DIDRegistry::set_cache_ttl`]. This can only be called once; later calls
    /// fail with [`DIDRegistryError::AlreadyInitialized`].
    ///
    /// # Emits
    /// `RegistryInitialized` with the admin address.
    pub fn initialize(env: Env, admin: Address) -> Result<(), DIDRegistryError> {
        let key = Self::admin_key(&env);
        if env.storage().instance().has(&key) {
            return Err(DIDRegistryError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().instance().set(&key, &admin);

        env.events()
            .publish((Symbol::new(&env, "RegistryInitialized"),), admin);

        Ok(())
    }

    /// Return the configured admin, or `None` when the registry was never
    /// initialised.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&Self::admin_key(&env))
    }

    /// Set how many ledgers a cached DID document stays valid (#265).
    ///
    /// A TTL of `0` disables caching: [`DIDRegistry::cache_did_doc`] becomes a
    /// no-op and [`DIDRegistry::get_cached_doc`] always returns `None`. The new
    /// value applies to entries written after this call; already-cached entries
    /// keep the expiry they were written with.
    ///
    /// # Emits
    /// `CacheTtlUpdated` with the new TTL.
    pub fn set_cache_ttl(
        env: Env,
        admin: Address,
        ttl_ledgers: u32,
    ) -> Result<(), DIDRegistryError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if ttl_ledgers > Self::MAX_CACHE_TTL_LEDGERS {
            return Err(DIDRegistryError::InvalidCacheTtl);
        }

        env.storage()
            .instance()
            .set(&Self::cache_ttl_key(&env), &ttl_ledgers);

        env.events()
            .publish((Symbol::new(&env, "CacheTtlUpdated"),), ttl_ledgers);

        Ok(())
    }

    /// Current cache TTL in ledgers, defaulting to
    /// [`DIDRegistry::DEFAULT_CACHE_TTL_LEDGERS`] when never configured.
    pub fn get_cache_ttl(env: Env) -> u32 {
        Self::configured_cache_ttl(&env)
    }

    /// Snapshot the stored DID document into temporary storage (#265).
    ///
    /// The snapshot expires `ttl` ledgers after the current ledger sequence, so
    /// repeated lookups of a hot DID avoid the persistent read. Caching an
    /// unknown DID fails with [`DIDRegistryError::NotFound`] and caching a
    /// deactivated DID fails with [`DIDRegistryError::Deactivated`]; re-caching a
    /// DID that is already cached simply refreshes the entry.
    ///
    /// Permissionless: the document is already public through
    /// [`DIDRegistry::resolve_did`], and the caller pays for the write.
    ///
    /// # Emits
    /// `DIDDocumentCached` with `(did, expires_at)` when an entry is written.
    pub fn cache_did_doc(env: Env, did: Bytes) -> Result<(), DIDRegistryError> {
        let doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let ttl = Self::configured_cache_ttl(&env);
        if ttl == 0 {
            // Caching is disabled by the admin: nothing to store.
            return Ok(());
        }

        let cached_at = env.ledger().sequence();
        let expires_at = cached_at.saturating_add(ttl);

        env.storage().temporary().set(
            &DidKey::Cache(did.clone()),
            &CachedDIDDocument {
                doc,
                cached_at,
                expires_at,
            },
        );

        env.events().publish(
            (Symbol::new(&env, "DIDDocumentCached"),),
            (did, expires_at),
        );

        Ok(())
    }

    /// Read the cached DID document for `did` (#265).
    ///
    /// Returns `None` when nothing is cached, when the entry has expired, or
    /// when the DID has no cacheable document. Expired entries are dropped on
    /// read.
    pub fn get_cached_doc(env: Env, did: Bytes) -> Option<DIDDocument> {
        Self::read_cached_doc(&env, &did)
    }

    /// Drop the cached DID document for `did` (#265).
    ///
    /// Returns `true` when an entry was actually removed, `false` when there was
    /// nothing to clear. Permissionless for the same reason as
    /// [`DIDRegistry::cache_did_doc`]: clearing the cache can only force a
    /// re-read of public data.
    ///
    /// # Emits
    /// `CacheCleared` with `did`, only when an entry was removed.
    pub fn invalidate_cache(env: Env, did: Bytes) -> bool {
        Self::purge_cached_doc(&env, &did)
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

    fn admin_key(env: &Env) -> Symbol {
        Symbol::new(env, "did_admin")
    }

    fn cache_ttl_key(env: &Env) -> Symbol {
        Symbol::new(env, "did_cache_ttl")
    }

    fn assert_admin(env: &Env, caller: &Address) -> Result<(), DIDRegistryError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&Self::admin_key(env))
            .ok_or(DIDRegistryError::AdminNotSet)?;

        if *caller != admin {
            return Err(DIDRegistryError::Unauthorized);
        }

        Ok(())
    }

    fn configured_cache_ttl(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&Self::cache_ttl_key(env))
            .unwrap_or(Self::DEFAULT_CACHE_TTL_LEDGERS)
    }

    fn read_cached_doc(env: &Env, did: &Bytes) -> Option<DIDDocument> {
        let key = DidKey::Cache(did.clone());
        let entry: CachedDIDDocument = env.storage().temporary().get(&key)?;

        if env.ledger().sequence() >= entry.expires_at {
            env.storage().temporary().remove(&key);
            return None;
        }

        Some(entry.doc)
    }

    /// Remove a cached snapshot, emitting `CacheCleared` when one existed.
    fn purge_cached_doc(env: &Env, did: &Bytes) -> bool {
        let key = DidKey::Cache(did.clone());
        if !env.storage().temporary().has(&key) {
            return false;
        }

        env.storage().temporary().remove(&key);
        env.events()
            .publish((Symbol::new(env, "CacheCleared"),), did.clone());

        true
    }

    // -----------------------------------------------------------------------
    // Multi-Signature DID Operations (#93)
    // -----------------------------------------------------------------------

    pub fn configure_multisig(
        env: Env,
        controller: Address,
        signers: Vec<Signer>,
        threshold: u32,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        if signers.is_empty() {
            return Err(DIDRegistryError::InvalidFormat);
        }
        if threshold == 0 || threshold > signers.len() as u32 {
            return Err(DIDRegistryError::InvalidFormat);
        }

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let config = MultiSigConfig {
            signers: signers.clone(),
            threshold,
        };

        env.storage()
            .persistent()
            .set(&DidKey::MultiSig(did.clone()), &config);

        doc.updated = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did.clone()), &doc);

        // `updated` changed, so any cached snapshot is stale (#265).
        Self::purge_cached_doc(&env, &did);

        env.events().publish(
            (Symbol::new(&env, "MultiSigConfigured"),),
            (did, controller, threshold),
        );

        Ok(())
    }

    pub fn get_multisig_config(env: Env, did: Bytes) -> Option<MultiSigConfig> {
        env.storage().persistent().get(&DidKey::MultiSig(did))
    }

    pub fn add_multisig_signer(
        env: Env,
        controller: Address,
        signer: Signer,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut config: MultiSigConfig = env
            .storage()
            .persistent()
            .get(&DidKey::MultiSig(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        for existing in config.signers.iter() {
            if existing.address == signer.address {
                return Err(DIDRegistryError::AlreadyExists);
            }
        }

        config.signers.push_back(signer);
        env.storage()
            .persistent()
            .set(&DidKey::MultiSig(did.clone()), &config);

        Ok(())
    }

    pub fn remove_multisig_signer(
        env: Env,
        controller: Address,
        signer_address: Address,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut config: MultiSigConfig = env
            .storage()
            .persistent()
            .get(&DidKey::MultiSig(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut found = false;
        let mut new_signers: Vec<Signer> = Vec::new(&env);
        for s in config.signers.iter() {
            if s.address == signer_address {
                found = true;
            } else {
                new_signers.push_back(s);
            }
        }

        if !found {
            return Err(DIDRegistryError::NotFound);
        }

        if config.threshold > new_signers.len() as u32 {
            config.threshold = new_signers.len() as u32;
        }

        config.signers = new_signers;
        env.storage()
            .persistent()
            .set(&DidKey::MultiSig(did), &config);

        Ok(())
    }

    pub fn update_multisig_threshold(
        env: Env,
        controller: Address,
        new_threshold: u32,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut config: MultiSigConfig = env
            .storage()
            .persistent()
            .get(&DidKey::MultiSig(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if new_threshold == 0 || new_threshold > config.signers.len() as u32 {
            return Err(DIDRegistryError::InvalidFormat);
        }

        config.threshold = new_threshold;
        env.storage()
            .persistent()
            .set(&DidKey::MultiSig(did), &config);

        Ok(())
    }

    pub fn create_multisig_operation(
        env: Env,
        creator: Address,
        did: Bytes,
        operation_data: Bytes,
    ) -> Result<Bytes, DIDRegistryError> {
        creator.require_auth();

        let config: MultiSigConfig = env
            .storage()
            .persistent()
            .get(&DidKey::MultiSig(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut is_authorized = false;
        for signer in config.signers.iter() {
            if signer.address == creator {
                is_authorized = true;
                break;
            }
        }
        if !is_authorized {
            return Err(DIDRegistryError::Unauthorized);
        }

        let operation_id = Self::generate_operation_id(&env, &did);
        let operation = PendingMultiSigOperation {
            id: operation_id.clone(),
            did,
            operation_data,
            approvals: Vec::new(&env),
            executed: false,
        };

        env.storage()
            .persistent()
            .set(&DidKey::Operation(operation_id.clone()), &operation);

        env.events().publish(
            (Symbol::new(&env, "MultiSigOperationCreated"),),
            (operation_id.clone(), creator),
        );

        Ok(operation_id)
    }

    pub fn sign_multisig_operation(
        env: Env,
        signer: Address,
        operation_id: Bytes,
    ) -> Result<(), DIDRegistryError> {
        signer.require_auth();

        let mut operation: PendingMultiSigOperation = env
            .storage()
            .persistent()
            .get(&DidKey::Operation(operation_id.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if operation.executed {
            return Err(DIDRegistryError::AlreadyExists);
        }

        let config: MultiSigConfig = env
            .storage()
            .persistent()
            .get(&DidKey::MultiSig(operation.did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut is_valid_signer = false;
        for s in config.signers.iter() {
            if s.address == signer {
                is_valid_signer = true;
                break;
            }
        }
        if !is_valid_signer {
            return Err(DIDRegistryError::Unauthorized);
        }

        for approval in operation.approvals.iter() {
            if approval == signer {
                return Err(DIDRegistryError::AlreadyExists);
            }
        }

        operation.approvals.push_back(signer.clone());
        env.storage()
            .persistent()
            .set(&DidKey::Operation(operation_id.clone()), &operation);

        env.events().publish(
            (Symbol::new(&env, "MultiSigOperationSigned"),),
            (operation_id, signer),
        );

        Ok(())
    }

    pub fn execute_multisig_operation(
        env: Env,
        executor: Address,
        operation_id: Bytes,
    ) -> Result<Bytes, DIDRegistryError> {
        executor.require_auth();

        let mut operation: PendingMultiSigOperation = env
            .storage()
            .persistent()
            .get(&DidKey::Operation(operation_id.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if operation.executed {
            return Err(DIDRegistryError::AlreadyExists);
        }

        let config: MultiSigConfig = env
            .storage()
            .persistent()
            .get(&DidKey::MultiSig(operation.did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if (operation.approvals.len() as u32) < config.threshold {
            return Err(DIDRegistryError::Unauthorized);
        }

        operation.executed = true;
        env.storage()
            .persistent()
            .set(&DidKey::Operation(operation_id.clone()), &operation);

        env.events().publish(
            (Symbol::new(&env, "MultiSigOperationExecuted"),),
            (
                operation_id.clone(),
                executor,
                operation.operation_data.clone(),
            ),
        );

        Ok(operation.operation_data)
    }

    pub fn get_pending_multisig_operation(
        env: Env,
        operation_id: Bytes,
    ) -> Option<PendingMultiSigOperation> {
        env.storage()
            .persistent()
            .get(&DidKey::Operation(operation_id))
    }

    fn generate_operation_id(env: &Env, _did: &Bytes) -> Bytes {
        let mut id = Bytes::from_slice(env, b"op:");
        id.append(&Bytes::from_slice(
            env,
            env.ledger().timestamp().to_string().as_bytes(),
        ));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events, Ledger, LedgerInfo},
        vec, BytesN, Env, TryFromVal,
    };

    fn setup_env() -> Env {
        let env = Env::default();
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000,
            protocol_version: 22,
            sequence_number: 1000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50000,
            min_persistent_entry_ttl: 50000,
            max_entry_ttl: 50000,
        });
        env
    }

    fn make_did_bytes(env: &Env, addr: &Address) -> Bytes {
        let s = alloc::format!("did:stellar:{}", "<bytes>");
        Bytes::from_slice(env, s.as_bytes())
    }

    fn make_vm(env: &Env, id: &str, key: &[u8; 32]) -> VerificationMethod {
        VerificationMethod {
            id: Bytes::from_slice(env, id.as_bytes()),
            type_: Bytes::from_slice(env, b"Ed25519VerificationKey2018"),
            controller: Address::generate(env),
            public_key: BytesN::from_array(env, key),
        }
    }

    /// True when the most recent invocation emitted an event carrying `topic`.
    ///
    /// Topics are compared as `Symbol`s: `Vec<Val>::contains` compares object
    /// values by handle, so two Vals for the same topic are never equal.
    fn emitted(env: &Env, topic: &str) -> bool {
        let expected = Symbol::new(env, topic);
        env.events().all().iter().any(|e| {
            e.1.iter().any(|t| {
                Symbol::try_from_val(env, &t)
                    .map(|s| s == expected)
                    .unwrap_or(false)
            })
        })
    }

    fn make_services(env: &Env) -> Vec<Service> {
        vec![
            env,
            Service {
                id: Bytes::from_slice(env, b"#hub"),
                type_: Bytes::from_slice(env, b"IdentityHub"),
                endpoint: Bytes::from_slice(env, b"https://hub.example.com"),
            },
        ]
    }

    // ── Issue #11: create_did tests ──

    #[test]
    fn test_create_did_success() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        let result = DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        );
        assert!(result.is_ok());

        // DID was stored and resolves correctly
        let doc = DIDRegistry::resolve_did(env.clone(), did.clone()).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.controller, controller);
        assert!(!doc.deactivated);
    }

    #[test]
    fn test_create_did_returns_did_string_format() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        // DID must start with "did:stellar:"
        let prefix = Bytes::from_slice(&env, b"did:stellar:");
        for i in 0..prefix.len() {
            assert_eq!(did.get(i), prefix.get(i));
        }
    }

    #[test]
    fn test_create_did_duplicate_returns_already_exists() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm1 = make_vm(&env, "#key-1", &[1u8; 32]);
        let vm2 = make_vm(&env, "#key-2", &[2u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm1],
            make_services(&env),
        )
        .unwrap();

        let result = DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm2],
            make_services(&env),
        );
        assert_eq!(result.err().unwrap(), DIDRegistryError::AlreadyExists);
    }

    #[test]
    fn test_create_did_invalid_format_rejected() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        // Missing "did:stellar:" prefix
        let bad_did = Bytes::from_slice(&env, b"stellar:GD5DJQDKEJXGYQT");

        let result = DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            bad_did,
            Vec::new(&env),
            Vec::new(&env),
        );
        assert_eq!(result.err().unwrap(), DIDRegistryError::InvalidFormat);
    }

    #[test]
    fn test_create_did_stores_verification_methods_and_services() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);
        let services = make_services(&env);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm.clone()],
            services,
        )
        .unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did).unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.verification_method.get(0).unwrap().id, vm.id);
    }

    #[test]
    fn test_create_did_access_control_requires_controller_auth() {
        let env = setup_env();
        // Do NOT mock auths — auth should fail
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);

        // This should panic because require_auth() is not satisfied
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            DIDRegistry::create_did(
                env.clone(),
                controller.clone(),
                did.clone(),
                Vec::new(&env),
                Vec::new(&env),
            )
        }));
        assert!(result.is_err(), "Expected auth panic when controller auth not provided");
    }

    // ── Issue #12: resolve_did tests ──

    #[test]
    fn test_resolve_did_success() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did.clone()).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.controller, controller);
        assert!(!doc.deactivated);
        assert_eq!(doc.created, 1_700_000_000);
        assert_eq!(doc.updated, 1_700_000_000);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.service.len(), 1);
    }

    #[test]
    fn test_resolve_did_not_found() {
        let env = setup_env();
        let fake_did = Bytes::from_slice(&env, b"did:stellar:NONEXISTENT");
        let result = DIDRegistry::resolve_did(env.clone(), fake_did);
        assert_eq!(result.err().unwrap(), DIDRegistryError::NotFound);
    }

    // ── Issue #13: update_did tests ──

    #[test]
    fn test_update_did_verification_methods() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        let new_vm = make_vm(&env, "#key-2", &[2u8; 32]);
        DIDRegistry::update_did(
            env.clone(),
            controller.clone(),
            Some(vec![&env, new_vm]),
            None,
        )
        .unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did).unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method.get(0).unwrap().id,
            Bytes::from_slice(&env, b"#key-2")
        );
    }

    #[test]
    fn test_update_did_services() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        let new_services: Vec<Service> = Vec::new(&env);
        DIDRegistry::update_did(env.clone(), controller.clone(), None, Some(new_services)).unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did).unwrap();
        assert_eq!(doc.service.len(), 0);
    }

    #[test]
    fn test_update_deactivated_did_fails() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::deactivate_did(env.clone(), controller.clone()).unwrap();

        let result = DIDRegistry::update_did(env.clone(), controller, None, None);
        assert_eq!(result.err().unwrap(), DIDRegistryError::Deactivated);
    }

    // ── Issue #13: deactivate_did tests ──

    #[test]
    fn test_deactivate_did_success() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::deactivate_did(env.clone(), controller).unwrap();

        let doc = DIDRegistry::resolve_did(env.clone(), did).unwrap();
        assert!(doc.deactivated);
    }

    #[test]
    fn test_deactivate_already_deactivated_did_fails() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::deactivate_did(env.clone(), controller.clone()).unwrap();

        let result = DIDRegistry::deactivate_did(env.clone(), controller);
        assert_eq!(result.err().unwrap(), DIDRegistryError::AlreadyDeactivated);
    }

    #[test]
    fn test_deactivate_nonexistent_did_fails() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);

        let result = DIDRegistry::deactivate_did(env.clone(), controller);
        assert_eq!(result.err().unwrap(), DIDRegistryError::NotFound);
    }

    // ── Issue #41: Event emission tests ──

    #[test]
    fn test_did_created_event_emitted() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller,
            did.clone(),
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        assert!(emitted(&env, "DIDCreated"));
    }

    #[test]
    fn test_authentication_added_event_emitted() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);
        let auth_method = Bytes::from_slice(&env, b"auth-key-1");

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did,
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::add_authentication(env.clone(), controller, auth_method).unwrap();

        assert!(emitted(&env, "AuthenticationAdded"));
    }

    #[test]
    fn test_authentication_removed_event_emitted() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);
        let auth_method = Bytes::from_slice(&env, b"auth-key-1");

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did,
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::add_authentication(env.clone(), controller.clone(), auth_method.clone()).unwrap();
        DIDRegistry::remove_authentication(env.clone(), controller, auth_method).unwrap();

        assert!(emitted(&env, "AuthenticationRemoved"));
    }

    #[test]
    fn test_did_updated_event_emitted() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did,
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::update_did(env.clone(), controller, None, None).unwrap();

        assert!(emitted(&env, "DIDUpdated"));
    }

    #[test]
    fn test_did_deactivated_event_emitted() {
        let env = setup_env();
        env.mock_all_auths();
        let controller = Address::generate(&env);
        let did = make_did_bytes(&env, &controller);
        let vm = make_vm(&env, "#key-1", &[1u8; 32]);

        DIDRegistry::create_did(
            env.clone(),
            controller.clone(),
            did,
            vec![&env, vm],
            make_services(&env),
        )
        .unwrap();

        DIDRegistry::deactivate_did(env.clone(), controller).unwrap();

        assert!(emitted(&env, "DIDDeactivated"));
    }

    // ── Issue #265: DID document caching ──

    /// Register the registry and create a DID owned by a fresh controller.
    ///
    /// The contract must be registered and driven through its client: a direct
    /// call to the generated functions has no contract frame to begin with, so
    /// any storage access traps with "no contract running".
    fn setup_cached<'a>(env: &'a Env) -> (DIDRegistryClient<'a>, Address, Bytes) {
        let client = DIDRegistryClient::new(env, &env.register(DIDRegistry, ()));
        let controller = Address::generate(env);
        let did = make_did_bytes(env, &controller);

        client.create_did(
            &controller,
            &did,
            &vec![env, make_vm(env, "#key-1", &[1u8; 32])],
            &make_services(env),
        );

        (client, controller, did)
    }

    fn bootstrap_admin(env: &Env, client: &DIDRegistryClient) -> Address {
        let admin = Address::generate(env);
        client.initialize(&admin);
        admin
    }

    /// Count `CacheCleared` events in the most recent invocation.
    fn cache_cleared_event_count(env: &Env) -> usize {
        let expected = Symbol::new(env, "CacheCleared");
        env.events()
            .all()
            .iter()
            .filter(|e| {
                e.1.iter().any(|t| {
                    Symbol::try_from_val(env, &t)
                        .map(|s| s == expected)
                        .unwrap_or(false)
                })
            })
            .count()
    }

    #[test]
    fn test_get_cached_doc_misses_before_caching() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, did) = setup_cached(&env);

        assert!(client.get_cached_doc(&did).is_none());
    }

    #[test]
    fn test_cache_did_doc_then_get_cached_doc_hits() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, did) = setup_cached(&env);

        client.cache_did_doc(&did);

        let cached = client.get_cached_doc(&did).unwrap();
        assert_eq!(cached.id, did);
        assert_eq!(cached.verification_method.len(), 1);

        // resolve_did serves the snapshot as well.
        let resolved = client.resolve_did(&did);
        assert_eq!(resolved.controller, cached.controller);
    }

    #[test]
    fn test_cache_did_doc_rejects_unknown_did() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, _) = setup_cached(&env);
        let missing = Bytes::from_slice(&env, b"did:stellar:MISSING");

        assert_eq!(
            client.try_cache_did_doc(&missing).unwrap_err().unwrap(),
            DIDRegistryError::NotFound
        );
    }

    #[test]
    fn test_cache_did_doc_rejects_deactivated_did() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, controller, did) = setup_cached(&env);

        client.deactivate_did(&controller);

        assert_eq!(
            client.try_cache_did_doc(&did).unwrap_err().unwrap(),
            DIDRegistryError::Deactivated
        );
    }

    #[test]
    fn test_default_cache_ttl_is_100_ledgers() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, did) = setup_cached(&env);

        assert_eq!(client.get_cache_ttl(), 100);

        client.cache_did_doc(&did);

        env.ledger().set_sequence_number(1099);
        assert!(client.get_cached_doc(&did).is_some());

        env.ledger().set_sequence_number(1100);
        assert!(client.get_cached_doc(&did).is_none());
    }

    #[test]
    fn test_cache_expires_after_configured_ttl() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, did) = setup_cached(&env);
        let admin = bootstrap_admin(&env, &client);

        client.set_cache_ttl(&admin, &10);
        assert_eq!(client.get_cache_ttl(), 10);

        client.cache_did_doc(&did);

        // One ledger short of the TTL: still a hit.
        env.ledger().set_sequence_number(1009);
        assert!(client.get_cached_doc(&did).is_some());

        // At the boundary the entry is stale...
        env.ledger().set_sequence_number(1010);
        assert!(client.get_cached_doc(&did).is_none());

        // ...and it was dropped, not merely hidden.
        env.ledger().set_sequence_number(1000);
        assert!(client.get_cached_doc(&did).is_none());
    }

    #[test]
    fn test_cache_invalidated_on_update() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, controller, did) = setup_cached(&env);

        client.cache_did_doc(&did);
        assert!(client.get_cached_doc(&did).is_some());

        let new_vm = make_vm(&env, "#key-2", &[2u8; 32]);
        client.update_did(&controller, &Some(vec![&env, new_vm]), &None);

        assert!(client.get_cached_doc(&did).is_none());

        // A fresh resolve returns the updated document, never a stale snapshot.
        let doc = client.resolve_did(&did);
        assert_eq!(
            doc.verification_method.get(0).unwrap().id,
            Bytes::from_slice(&env, b"#key-2")
        );
    }

    #[test]
    fn test_cache_invalidated_on_deactivate() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, controller, did) = setup_cached(&env);

        client.cache_did_doc(&did);
        client.deactivate_did(&controller);

        assert!(client.get_cached_doc(&did).is_none());
    }

    #[test]
    fn test_cache_invalidated_on_authentication_change() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, controller, did) = setup_cached(&env);
        let auth_method = Bytes::from_slice(&env, b"auth-key-1");

        client.cache_did_doc(&did);
        client.add_authentication(&controller, &auth_method);
        assert!(client.get_cached_doc(&did).is_none());

        client.cache_did_doc(&did);
        client.remove_authentication(&controller, &auth_method);
        assert!(client.get_cached_doc(&did).is_none());
    }

    #[test]
    fn test_invalidate_cache_reports_entry_and_emits_event() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, did) = setup_cached(&env);

        client.cache_did_doc(&did);

        assert!(client.invalidate_cache(&did));
        assert_eq!(cache_cleared_event_count(&env), 1);
        assert!(client.get_cached_doc(&did).is_none());

        // Nothing left to clear, so nothing is emitted.
        assert!(!client.invalidate_cache(&did));
        assert_eq!(cache_cleared_event_count(&env), 0);
    }

    #[test]
    fn test_set_cache_ttl_requires_admin() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, _) = setup_cached(&env);
        let admin = bootstrap_admin(&env, &client);
        let stranger = Address::generate(&env);

        assert!(client.try_set_cache_ttl(&admin, &50).is_ok());

        assert_eq!(
            client.try_set_cache_ttl(&stranger, &50).unwrap_err().unwrap(),
            DIDRegistryError::Unauthorized
        );
    }

    #[test]
    fn test_set_cache_ttl_without_admin_config() {
        let env = setup_env();
        env.mock_all_auths();
        let client = DIDRegistryClient::new(&env, &env.register(DIDRegistry, ()));
        let caller = Address::generate(&env);

        assert_eq!(
            client.try_set_cache_ttl(&caller, &50).unwrap_err().unwrap(),
            DIDRegistryError::AdminNotSet
        );
    }

    #[test]
    fn test_set_cache_ttl_rejects_out_of_range() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, _) = setup_cached(&env);
        let admin = bootstrap_admin(&env, &client);

        assert_eq!(
            client
                .try_set_cache_ttl(&admin, &(DIDRegistry::MAX_CACHE_TTL_LEDGERS + 1))
                .unwrap_err()
                .unwrap(),
            DIDRegistryError::InvalidCacheTtl
        );
    }

    #[test]
    fn test_zero_ttl_disables_caching() {
        let env = setup_env();
        env.mock_all_auths();
        let (client, _, did) = setup_cached(&env);
        let admin = bootstrap_admin(&env, &client);

        client.set_cache_ttl(&admin, &0);
        client.cache_did_doc(&did);

        assert!(client.get_cached_doc(&did).is_none());
    }

    #[test]
    fn test_initialize_sets_admin_only_once() {
        let env = setup_env();
        env.mock_all_auths();
        let client = DIDRegistryClient::new(&env, &env.register(DIDRegistry, ()));
        let admin = Address::generate(&env);

        assert!(client.get_admin().is_none());

        client.initialize(&admin);
        assert_eq!(client.get_admin().unwrap(), admin);

        assert_eq!(
            client
                .try_initialize(&Address::generate(&env))
                .unwrap_err()
                .unwrap(),
            DIDRegistryError::AlreadyInitialized
        );
    }
}
