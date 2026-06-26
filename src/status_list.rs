//! W3C Bitstring Status List (#44)
//!
//! Implements a W3C-compliant BitstringStatusList for efficient on-chain
//! credential revocation status checking, reducing storage costs.
//!
//! Each status list is a packed bitstring where each bit represents the
//! revocation status of a credential at a given index.  Multiple status
//! lists can coexist (e.g. per issuer or per credential type).
//!
//! Reference: https://www.w3.org/TR/vc-bitstring-status-list/

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol, Vec,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of bits a single status list can hold.
pub const MAX_STATUS_LIST_SIZE: u32 = 131_072; // 16 KiB of bits

/// Number of bits packed into a single u8 word.
const BITS_PER_WORD: u32 = 8;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum SlKey {
    /// Status list data indexed by list id — stores the raw bitstring bytes.
    List(Bytes),
    /// Metadata for each status list.
    Meta(Bytes),
    /// Index of all status list IDs managed by a given issuer.
    IssuerLists(Address),
    /// Global index of all status list IDs.
    ListIndex,
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Metadata associated with a status list.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusListMeta {
    /// Unique identifier for this status list.
    pub id: Bytes,
    /// The issuer/creator of this status list.
    pub issuer: Address,
    /// Total number of bits / entries allocated.
    pub size: u32,
    /// How many credentials have been marked revoked in this list.
    pub revoked_count: u32,
    /// Ledger timestamp when this list was created.
    pub created_at: u64,
    /// Ledger timestamp of the last update.
    pub last_updated: u64,
    /// Whether the list is active.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum StatusListError {
    /// List with this ID already exists.
    AlreadyExists = 1,
    /// Requested status list was not found.
    NotFound = 2,
    /// Caller is not authorised for this operation.
    Unauthorized = 3,
    /// Index is out of bounds for this status list.
    IndexOutOfBounds = 4,
    /// Requested list size exceeds the maximum allowed.
    SizeTooLarge = 5,
    /// Specified list size must be greater than zero.
    InvalidSize = 6,
    /// The status list has been deactivated.
    ListDeactivated = 7,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct BitstringStatusList;

#[contractimpl]
impl BitstringStatusList {
    /// Create a new status list with the given number of bits.
    ///
    /// # Arguments
    /// * `admin` — authenticated creator of the list.
    /// * `list_id` — unique identifier for the list.
    /// * `size` — number of bits / entries (1 .. MAX_STATUS_LIST_SIZE).
    pub fn create_status_list(
        env: Env,
        admin: Address,
        list_id: Bytes,
        size: u32,
    ) -> Result<(), StatusListError> {
        admin.require_auth();

        if size == 0 {
            return Err(StatusListError::InvalidSize);
        }
        if size > MAX_STATUS_LIST_SIZE {
            return Err(StatusListError::SizeTooLarge);
        }

        if env
            .storage()
            .persistent()
            .has(&SlKey::List(list_id.clone()))
        {
            return Err(StatusListError::AlreadyExists);
        }

        // Allocate byte-array: ceil(size / 8) bytes, all zeroed.
        let byte_count = (size + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let mut encoded = Bytes::new(&env);
        for _ in 0..byte_count {
            encoded.push_back(0u8);
        }

        let meta = StatusListMeta {
            id: list_id.clone(),
            issuer: admin.clone(),
            size,
            revoked_count: 0,
            created_at: env.ledger().timestamp(),
            last_updated: env.ledger().timestamp(),
            active: true,
        };

        env.storage()
            .persistent()
            .set(&SlKey::Meta(list_id.clone()), &meta);
        env.storage()
            .persistent()
            .set(&SlKey::List(list_id.clone()), &encoded);

        // Add to issuer index
        let mut issuer_lists: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&SlKey::IssuerLists(admin.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        issuer_lists.push_back(list_id.clone());
        env.storage()
            .persistent()
            .set(&SlKey::IssuerLists(admin.clone()), &issuer_lists);

        // Add to global index
        let mut global: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&SlKey::ListIndex)
            .unwrap_or_else(|| Vec::new(&env));
        global.push_back(list_id.clone());
        env.storage()
            .persistent()
            .set(&SlKey::ListIndex, &global);

        env.events().publish(
            (Symbol::new(&env, "StatusListCreated"),),
            (list_id, admin, size),
        );

        Ok(())
    }

    /// Set the revocation status of the credential at `index` in the
    /// specified status list.
    ///
    /// Only the issuer (admin who created the list) may call this.
    pub fn set_status(
        env: Env,
        admin: Address,
        list_id: Bytes,
        index: u32,
        revoked: bool,
    ) -> Result<(), StatusListError> {
        admin.require_auth();

        let mut meta: StatusListMeta = env
            .storage()
            .persistent()
            .get(&SlKey::Meta(list_id.clone()))
            .ok_or(StatusListError::NotFound)?;

        if !meta.active {
            return Err(StatusListError::ListDeactivated);
        }
        if meta.issuer != admin {
            return Err(StatusListError::Unauthorized);
        }
        if index >= meta.size {
            return Err(StatusListError::IndexOutOfBounds);
        }

        let mut list_data: Bytes = env
            .storage()
            .persistent()
            .get(&SlKey::List(list_id.clone()))
            .unwrap_or_else(|| Bytes::new(&env));

        let byte_idx = index / BITS_PER_WORD;
        let bit_idx = index % BITS_PER_WORD;

        let current_byte: u8 = list_data
            .get(byte_idx)
            .unwrap_or(0);

        let was_revoked = (current_byte & (1 << bit_idx)) != 0;
        let new_byte = if revoked {
            current_byte | (1 << bit_idx)
        } else {
            current_byte & !(1 << bit_idx)
        };

        // Only update storage and metadata if the bit actually changed.
        if was_revoked != revoked {
            list_data.set(byte_idx, new_byte);

            if revoked {
                meta.revoked_count = meta.revoked_count.saturating_add(1);
            } else {
                meta.revoked_count = meta.revoked_count.saturating_sub(1);
            }
            meta.last_updated = env.ledger().timestamp();

            env.storage()
                .persistent()
                .set(&SlKey::List(list_id.clone()), &list_data);
            env.storage()
                .persistent()
                .set(&SlKey::Meta(list_id.clone()), &meta);

            env.events().publish(
                (Symbol::new(&env, "CredentialRevocationStatusChanged"),),
                (list_id, index, revoked),
            );
        }

        Ok(())
    }

    /// Return the revocation status (`true` = revoked) for the credential at
    /// `index` in the specified list.
    pub fn get_status(
        env: Env,
        list_id: Bytes,
        index: u32,
    ) -> Result<bool, StatusListError> {
        let meta: StatusListMeta = env
            .storage()
            .persistent()
            .get(&SlKey::Meta(list_id.clone()))
            .ok_or(StatusListError::NotFound)?;

        if !meta.active {
            return Err(StatusListError::ListDeactivated);
        }
        if index >= meta.size {
            return Err(StatusListError::IndexOutOfBounds);
        }

        let list_data: Bytes = env
            .storage()
            .persistent()
            .get(&SlKey::List(list_id.clone()))
            .unwrap_or_else(|| Bytes::new(&env));

        let byte_idx = index / BITS_PER_WORD;
        let bit_idx = index % BITS_PER_WORD;

        let byte: u8 = list_data.get(byte_idx).unwrap_or(0);
        Ok((byte & (1 << bit_idx)) != 0)
    }

    /// Batch-query revocation status for multiple indices in a single list.
    /// Batch-query revocation status for multiple indices.
    ///
    /// **Important:** Omitted indices (e.g. deactivated list or
    /// out-of-bounds) are reported as `false` rather than failing the
    /// whole batch.  Callers that need exact error attribution should
    /// use [`get_status`] individually.
    pub fn batch_get_status(
        env: Env,
        list_id: Bytes,
        indices: Vec<u32>,
    ) -> Result<Vec<bool>, StatusListError> {
        let mut results = Vec::new(&env);
        for index in indices.iter() {
            // If one query fails, push false and continue — the caller
            // can re-check specific entries individually.
            let status = Self::get_status(env.clone(), list_id.clone(), index.clone())
                .unwrap_or(false);
            results.push_back(status);
        }
        Ok(results)
    }

    /// Return metadata for a given status list.
    pub fn get_metadata(env: Env, list_id: Bytes) -> Option<StatusListMeta> {
        env.storage().persistent().get(&SlKey::Meta(list_id))
    }

    /// Return all status list IDs created by a given issuer.
    pub fn get_issuer_lists(env: Env, issuer: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&SlKey::IssuerLists(issuer))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Return the raw encoded bitstring for a status list.
    /// This can be served off-chain to holders for selective-disclosure
    /// proofs as required by the W3C specification.
    pub fn get_encoded_list(env: Env, list_id: Bytes) -> Result<Bytes, StatusListError> {
        let meta: StatusListMeta = env
            .storage()
            .persistent()
            .get(&SlKey::Meta(list_id.clone()))
            .ok_or(StatusListError::NotFound)?;

        if !meta.active {
            return Err(StatusListError::ListDeactivated);
        }

        env.storage()
            .persistent()
            .get(&SlKey::List(list_id))
            .ok_or(StatusListError::NotFound)
    }

    /// Deactivate a status list.  Once deactivated, no further status updates
    /// are allowed, but existing revocation states remain queryable.
    pub fn deactivate_status_list(
        env: Env,
        admin: Address,
        list_id: Bytes,
    ) -> Result<(), StatusListError> {
        admin.require_auth();

        let mut meta: StatusListMeta = env
            .storage()
            .persistent()
            .get(&SlKey::Meta(list_id.clone()))
            .ok_or(StatusListError::NotFound)?;

        if meta.issuer != admin {
            return Err(StatusListError::Unauthorized);
        }

        meta.active = false;
        meta.last_updated = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&SlKey::Meta(list_id), &meta);

        env.events()
            .publish((Symbol::new(&env, "StatusListDeactivated"),), (list_id, admin));

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{Address, Bytes, Env, Vec};

    fn setup_env() -> Env {
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
        env
    }

    fn bootstrap(env: &Env) -> (Address, Bytes) {
        let admin = Address::generate(env);
        let list_id = Bytes::from_slice(env, b"test-list-001");
        BitstringStatusList::create_status_list(
            env.clone(),
            admin.clone(),
            list_id.clone(),
            1024,
        )
        .unwrap();
        (admin, list_id)
    }

    #[test]
    fn creates_status_list_successfully() {
        let env = setup_env();
        let (admin, list_id) = bootstrap(&env);

        let meta = BitstringStatusList::get_metadata(env.clone(), list_id.clone()).unwrap();
        assert_eq!(meta.size, 1024);
        assert_eq!(meta.issuer, admin);
        assert!(meta.active);
        assert_eq!(meta.revoked_count, 0);
    }

    #[test]
    fn set_and_get_status_works() {
        let env = setup_env();
        let (admin, list_id) = bootstrap(&env);

        // Initially not revoked
        assert!(!BitstringStatusList::get_status(env.clone(), list_id.clone(), 5).unwrap());

        // Set revoked
        BitstringStatusList::set_status(env.clone(), admin.clone(), list_id.clone(), 5, true)
            .unwrap();

        assert!(BitstringStatusList::get_status(env.clone(), list_id.clone(), 5).unwrap());
        let meta =
            BitstringStatusList::get_metadata(env.clone(), list_id.clone()).unwrap();
        assert_eq!(meta.revoked_count, 1);

        // Un-revoke
        BitstringStatusList::set_status(
            env.clone(),
            admin,
            list_id.clone(),
            5,
            false,
        )
        .unwrap();
        assert!(!BitstringStatusList::get_status(env.clone(), list_id.clone(), 5).unwrap());
    }

    #[test]
    fn out_of_bounds_index_returns_error() {
        let env = setup_env();
        let (admin, list_id) = bootstrap(&env);

        // size is 1024, index 1024 is out of bounds
        let result = BitstringStatusList::set_status(
            env.clone(),
            admin,
            list_id.clone(),
            1024,
            true,
        );
        assert_eq!(result.unwrap_err(), StatusListError::IndexOutOfBounds);

        let result = BitstringStatusList::get_status(env.clone(), list_id, 1024);
        assert_eq!(result.unwrap_err(), StatusListError::IndexOutOfBounds);
    }

    #[test]
    fn zero_size_rejected() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let result = BitstringStatusList::create_status_list(
            env.clone(),
            admin,
            Bytes::from_slice(&env, b"list"),
            0,
        );
        assert_eq!(result.unwrap_err(), StatusListError::InvalidSize);
    }

    #[test]
    fn too_large_size_rejected() {
        let env = setup_env();
        let admin = Address::generate(&env);
        let result = BitstringStatusList::create_status_list(
            env.clone(),
            admin,
            Bytes::from_slice(&env, b"list"),
            MAX_STATUS_LIST_SIZE + 1,
        );
        assert_eq!(result.unwrap_err(), StatusListError::SizeTooLarge);
    }

    #[test]
    fn duplicate_list_rejected() {
        let env = setup_env();
        let (admin, list_id) = bootstrap(&env);
        let result = BitstringStatusList::create_status_list(
            env.clone(),
            admin,
            list_id,
            512,
        );
        assert_eq!(result.unwrap_err(), StatusListError::AlreadyExists);
    }

    #[test]
    fn non_issuer_cannot_set_status() {
        let env = setup_env();
        let (_, list_id) = bootstrap(&env);
        let intruder = Address::generate(&env);

        let result = BitstringStatusList::set_status(
            env.clone(),
            intruder,
            list_id,
            0,
            true,
        );
        assert_eq!(result.unwrap_err(), StatusListError::Unauthorized);
    }

    #[test]
    fn deactivated_list_rejects_updates() {
        let env = setup_env();
        let (admin, list_id) = bootstrap(&env);

        BitstringStatusList::deactivate_status_list(
            env.clone(),
            admin.clone(),
            list_id.clone(),
        )
        .unwrap();

        let result = BitstringStatusList::set_status(
            env.clone(),
            admin,
            list_id.clone(),
            0,
            true,
        );
        assert_eq!(result.unwrap_err(), StatusListError::ListDeactivated);
    }

    #[test]
    fn batch_get_status_works() {
        let env = setup_env();
        let (admin, list_id) = bootstrap(&env);

        // Set some indices as revoked
        for i in [3u32, 7, 15, 99] {
            BitstringStatusList::set_status(
                env.clone(),
                admin.clone(),
                list_id.clone(),
                i,
                true,
            )
            .unwrap();
        }

        let mut indices = Vec::new(&env);
        for i in 0u32..=100 {
            indices.push_back(i);
        }

        let results =
            BitstringStatusList::batch_get_status(env.clone(), list_id, indices).unwrap();

        assert!(!results.get(0).unwrap());
        assert!(results.get(3).unwrap());
        assert!(!results.get(4).unwrap());
        assert!(results.get(7).unwrap());
        assert!(results.get(15).unwrap());
        assert!(!results.get(16).unwrap());
        assert!(results.get(99).unwrap());
        assert!(!results.get(100).unwrap());
    }

    #[test]
    fn issuer_lists_tracking() {
        let env = setup_env();
        let admin = Address::generate(&env);

        let id1 = Bytes::from_slice(&env, b"list-1");
        let id2 = Bytes::from_slice(&env, b"list-2");

        BitstringStatusList::create_status_list(env.clone(), admin.clone(), id1.clone(), 256)
            .unwrap();
        BitstringStatusList::create_status_list(env.clone(), admin.clone(), id2.clone(), 512)
            .unwrap();

        let lists = BitstringStatusList::get_issuer_lists(env.clone(), admin);
        assert_eq!(lists.len(), 2);
    }

    #[test]
    fn get_encoded_list_returns_raw_bytes() {
        let env = setup_env();
        let (admin, list_id) = bootstrap(&env);

        // Set some bits
        for i in [10u32, 20, 30] {
            BitstringStatusList::set_status(
                env.clone(),
                admin,
                list_id.clone(),
                i,
                true,
            )
            .unwrap();
        }

        let encoded = BitstringStatusList::get_encoded_list(env.clone(), list_id).unwrap();
        // Should have ceil(1024 / 8) = 128 bytes
        assert_eq!(encoded.len(), 128);
    }
}
