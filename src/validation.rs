//! Shared input validation primitives (#200).
//!
//! Every public contract entry point funnels its untrusted arguments through
//! the helpers in this module before touching storage. The helpers are
//! deliberately cheap (no allocation, no hashing) so that validation does not
//! erode the gas savings delivered by [`crate::batch_optimizer`].
//!
//! Design notes:
//! - Each helper returns a *specific* [`ValidationError`] variant so callers
//!   can map it onto their own `#[contracterror]` enum and surface a precise
//!   error code to callers instead of a generic "invalid input".
//! - No helper ever panics. All arithmetic uses saturating operations and all
//!   indexing is bounds-checked, so malformed input can only produce an `Err`.
//! - Length limits are expressed in bytes (`Bytes::len()`), matching the unit
//!   used by the Soroban XDR encoding.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, Env};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Specific reasons an input can be rejected.
///
/// Contracts map these onto their own error enums so the discriminant exposed
/// on-chain is unique per contract (Soroban requires that).
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ValidationError {
    /// A required field was empty (zero-length `Bytes`).
    EmptyField = 1,
    /// A field exceeded its maximum byte length.
    FieldTooLong = 2,
    /// A field was shorter than its minimum byte length.
    FieldTooShort = 3,
    /// A required field was `None` when a value was mandatory.
    MissingField = 4,
    /// An address argument was the all-zero address.
    ZeroAddress = 5,
    /// Two addresses that must differ were equal (e.g. issuer == subject).
    SameAddress = 6,
    /// A numeric argument fell outside its permitted inclusive range.
    OutOfRange = 7,
    /// A timestamp argument was in the past when it had to be in the future.
    TimestampInPast = 8,
    /// A timestamp was further in the future than the protocol allows.
    TimestampTooFarFuture = 9,
    /// A batch argument exceeded the maximum permitted item count.
    BatchTooLarge = 10,
    /// A batch argument contained zero items.
    BatchEmpty = 11,
    /// A byte field contained control characters / non-printable bytes.
    NonPrintableBytes = 12,
    /// A collection exceeded the maximum number of tracked elements.
    CollectionLimitExceeded = 13,
}

// ---------------------------------------------------------------------------
// Scalar limits
// ---------------------------------------------------------------------------

/// Upper bound for a "human readable" label (DID method, credential type,
/// jurisdiction code, ...).
pub const MAX_LABEL_BYTES: u32 = 128;

/// Upper bound for a free-form payload (credential data, schema definition).
pub const MAX_PAYLOAD_BYTES: u32 = 10_240;

/// Upper bound for a reason / detail string.
pub const MAX_DETAIL_BYTES: u32 = 256;

/// Upper bound for a batch of items processed in a single call.
pub const MAX_BATCH_ITEMS: u32 = 50;

/// Maximum horizon for a future timestamp (10 years), guarding against
/// accidental `u64::MAX` style values that would make entries immortal.
pub const MAX_TIMESTAMP_HORIZON_SECS: u64 = 315_360_000;

// ---------------------------------------------------------------------------
// Bytes validation
// ---------------------------------------------------------------------------

/// Require `value` to contain at least one byte.
pub fn require_non_empty(_env: &Env, value: &Bytes) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyField);
    }
    Ok(())
}

/// Require `value.len() <= max`.
pub fn require_max_len(_env: &Env, value: &Bytes, max: u32) -> Result<(), ValidationError> {
    if value.len() > max {
        return Err(ValidationError::FieldTooLong);
    }
    Ok(())
}

/// Require `min <= value.len() <= max`.
pub fn require_len_range(
    env: &Env,
    value: &Bytes,
    min: u32,
    max: u32,
) -> Result<(), ValidationError> {
    require_non_empty(env, value)?;
    let len = value.len();
    if len < min {
        return Err(ValidationError::FieldTooShort);
    }
    if len > max {
        return Err(ValidationError::FieldTooLong);
    }
    Ok(())
}

/// Reject control characters so untrusted input cannot corrupt diagnostics or
/// indexer text. Only bytes in `0x20..=0x7E` (printable ASCII) are allowed,
/// plus `\t`, `\n` and `\r` for legitimately multi-line payloads.
pub fn require_printable(value: &Bytes) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyField);
    }
    let mut i = 0u32;
    while i < value.len() {
        let byte = value.get(i).unwrap_or(0);
        let allowed = (0x20..=0x7E).contains(&byte) || byte == 0x09 || byte == 0x0A || byte == 0x0D;
        if !allowed {
            return Err(ValidationError::NonPrintableBytes);
        }
        i += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Address validation
// ---------------------------------------------------------------------------

/// Byte offset at which the account-id / contract-hash payload begins inside
/// the XDR encoding of an `Address` (4-byte `ScVal` tag + 4-byte `ScAddress`
/// discriminant).
pub const ADDRESS_PAYLOAD_OFFSET: u32 = 8;

/// Reject degenerate (all-zero) addresses.
///
/// Soroban `Address` is a tagged union (account / contract / muxed) with no
/// `is_zero()` helper, and the host happily materialises the all-zero account
/// address, so callers must guard against it explicitly: an all-zero issuer or
/// subject would otherwise silently pool every such user's credentials under
/// one identity.
///
/// The XDR encoding of an address is `ScVal` (4-byte type tag) wrapping
/// `ScAddress` (4-byte discriminant) followed by the account id or contract
/// hash, so the payload begins at [`ADDRESS_PAYLOAD_OFFSET`]. Requiring at least
/// one non-zero payload byte rejects the degenerate encodings while accepting
/// every legitimate address.
pub fn require_non_zero_address(env: &Env, address: &Address) -> Result<(), ValidationError> {
    let xdr = address.clone().to_xdr(env);
    if xdr.len() <= ADDRESS_PAYLOAD_OFFSET {
        return Err(ValidationError::ZeroAddress);
    }
    let mut i = ADDRESS_PAYLOAD_OFFSET;
    while i < xdr.len() {
        if xdr.get(i).unwrap_or(0) != 0 {
            return Ok(());
        }
        i += 1;
    }
    Err(ValidationError::ZeroAddress)
}

/// Require that two addresses are distinct. Used wherever a self-referential
/// call would be nonsensical (issuer issuing to itself, trustee attesting to
/// itself, ...).
pub fn require_distinct(a: &Address, b: &Address) -> Result<(), ValidationError> {
    if a == b {
        return Err(ValidationError::SameAddress);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Numeric / range validation
// ---------------------------------------------------------------------------

/// Require `min <= value <= max`.
pub fn require_range<T: PartialOrd + Copy>(
    _env: &Env,
    value: T,
    min: T,
    max: T,
) -> Result<(), ValidationError> {
    if value < min || value > max {
        return Err(ValidationError::OutOfRange);
    }
    Ok(())
}

/// Require a percentage in `0..=100`.
pub fn require_percentage(env: &Env, value: u32) -> Result<(), ValidationError> {
    require_range(env, value, 0u32, 100u32)
}

/// Require a value in `1..=max` (excludes zero, guards division by zero).
pub fn require_positive(_env: &Env, value: u32, max: u32) -> Result<(), ValidationError> {
    if value == 0 || value > max {
        return Err(ValidationError::OutOfRange);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Timestamp validation
// ---------------------------------------------------------------------------

/// Require `ts` to be strictly in the future.
pub fn require_future(env: &Env, ts: u64) -> Result<(), ValidationError> {
    if ts <= env.ledger().timestamp() {
        return Err(ValidationError::TimestampInPast);
    }
    Ok(())
}

/// Require `ts` to be in the future and no further out than
/// [`MAX_TIMESTAMP_HORIZON_SECS`]. Used for TTLs, expirations and leases so a
/// single bad input cannot pin storage entries forever.
pub fn require_future_within_horizon(env: &Env, ts: u64) -> Result<(), ValidationError> {
    let now = env.ledger().timestamp();
    if ts <= now {
        return Err(ValidationError::TimestampInPast);
    }
    if ts.saturating_sub(now) > MAX_TIMESTAMP_HORIZON_SECS {
        return Err(ValidationError::TimestampTooFarFuture);
    }
    Ok(())
}

/// Require `ts` to be non-zero and no further out than
/// [`MAX_TIMESTAMP_HORIZON_SECS`].
///
/// Unlike [`require_future_within_horizon`] this deliberately places no lower
/// bound relative to "now", because back-dated expirations are legitimate:
/// an issuer correcting a mistyped expiry, or a verifier testing the
/// auto-revocation path for an already-expired credential. The upper bound is
/// what matters for storage safety — a `u64::MAX` expiry would make the entry
/// immortal and exempt it from garbage collection forever.
pub fn require_timestamp_horizon(env: &Env, ts: u64) -> Result<(), ValidationError> {
    if ts == 0 {
        return Err(ValidationError::TimestampInPast);
    }
    let now = env.ledger().timestamp();
    if ts.saturating_sub(now) > MAX_TIMESTAMP_HORIZON_SECS {
        return Err(ValidationError::TimestampTooFarFuture);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Collection validation
// ---------------------------------------------------------------------------

/// Require `len` to be within `1..=max`.
pub fn require_batch_len(len: u32, max: u32) -> Result<(), ValidationError> {
    if len == 0 {
        return Err(ValidationError::BatchEmpty);
    }
    if len > max {
        return Err(ValidationError::BatchTooLarge);
    }
    Ok(())
}

/// Require a tracked collection to still have room for one more element.
///
/// Guards unbounded growth of per-address index vectors (issuer credential
/// lists, DID populations, sanctions lists) which are the main source of
/// storage bloat in this contract suite.
pub fn require_collection_room(current: u32, max: u32) -> Result<(), ValidationError> {
    if current >= max {
        return Err(ValidationError::CollectionLimitExceeded);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger, testutils::LedgerInfo, Env};

    fn setup() -> Env {
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

    fn bytes(env: &Env, n: usize) -> Bytes {
        let mut v = Bytes::new(env);
        for _ in 0..n {
            v.push_back(0x41u8);
        }
        v
    }

    // ── Bytes ────────────────────────────────────────────────────────────

    #[test]
    fn non_empty_rejects_zero_length() {
        let env = setup();
        assert_eq!(
            require_non_empty(&env, &Bytes::new(&env)),
            Err(ValidationError::EmptyField)
        );
        assert!(require_non_empty(&env, &bytes(&env, 1)).is_ok());
    }

    #[test]
    fn max_len_boundary_is_inclusive() {
        let env = setup();
        assert!(require_max_len(&env, &bytes(&env, 10), 10).is_ok());
        assert_eq!(
            require_max_len(&env, &bytes(&env, 11), 10),
            Err(ValidationError::FieldTooLong)
        );
    }

    #[test]
    fn len_range_checks_both_bounds() {
        let env = setup();
        assert_eq!(
            require_len_range(&env, &bytes(&env, 3), 4, 10),
            Err(ValidationError::FieldTooShort)
        );
        assert_eq!(
            require_len_range(&env, &bytes(&env, 11), 4, 10),
            Err(ValidationError::FieldTooLong)
        );
        assert!(require_len_range(&env, &bytes(&env, 5), 4, 10).is_ok());
    }

    #[test]
    fn printable_rejects_control_bytes() {
        let env = setup();
        let mut nul = Bytes::new(&env);
        nul.push_back(0x00u8);
        assert_eq!(
            require_printable(&nul),
            Err(ValidationError::NonPrintableBytes)
        );

        // DEL (0x7F) is a control character and must be rejected.
        let mut del = Bytes::new(&env);
        del.push_back(0x7Fu8);
        assert_eq!(
            require_printable(&del),
            Err(ValidationError::NonPrintableBytes)
        );

        let mut good = Bytes::new(&env);
        good.push_back(b'A');
        good.push_back(b'\n');
        good.push_back(0x7Eu8);
        assert!(require_printable(&good).is_ok());
    }

    #[test]
    fn printable_accepts_every_byte_of_payload() {
        // Boundary fuzz: the whole printable range must be accepted.
        for b in 0x20u8..=0x7E {
            let env = setup();
            let mut v = Bytes::new(&env);
            v.push_back(b);
            assert!(require_printable(&v).is_ok(), "byte {:#x} rejected", b);
        }
    }

    // ── Addresses ────────────────────────────────────────────────────────

    #[test]
    fn non_zero_address_accepts_generated() {
        let env = setup();
        let a = Address::generate(&env);
        assert!(require_non_zero_address(&env, &a).is_ok());
    }

    #[test]
    fn non_zero_address_rejects_the_all_zero_account_address() {
        let env = setup();
        // The canonical all-zero Stellar account address.
        let zero = Address::from_str(
            &env,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        );
        assert_eq!(
            require_non_zero_address(&env, &zero),
            Err(ValidationError::ZeroAddress)
        );
    }

    #[test]
    fn distinct_rejects_equal_addresses() {
        let env = setup();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        assert!(require_distinct(&a, &b).is_ok());
        assert_eq!(require_distinct(&a, &a), Err(ValidationError::SameAddress));
    }

    // ── Numeric ──────────────────────────────────────────────────────────

    #[test]
    fn range_boundaries() {
        let env = setup();
        assert!(require_range(&env, 0u32, 0u32, 100u32).is_ok());
        assert!(require_range(&env, 100u32, 0u32, 100u32).is_ok());
        assert_eq!(
            require_range(&env, 101u32, 0u32, 100u32),
            Err(ValidationError::OutOfRange)
        );
        assert!(require_percentage(&env, 0).is_ok());
        assert!(require_percentage(&env, 100).is_ok());
    }

    #[test]
    fn positive_excludes_zero() {
        let env = setup();
        assert_eq!(
            require_positive(&env, 0, 10),
            Err(ValidationError::OutOfRange)
        );
        assert_eq!(
            require_positive(&env, 11, 10),
            Err(ValidationError::OutOfRange)
        );
        assert!(require_positive(&env, 1, 10).is_ok());
    }

    // ── Timestamps ───────────────────────────────────────────────────────

    #[test]
    fn future_rejects_now_and_past() {
        let env = setup();
        let now = env.ledger().timestamp();
        assert_eq!(
            require_future(&env, now),
            Err(ValidationError::TimestampInPast)
        );
        assert!(require_future(&env, now + 1).is_ok());
    }

    #[test]
    fn horizon_rejects_far_future() {
        let env = setup();
        let now = env.ledger().timestamp();
        assert!(require_future_within_horizon(&env, now + 60).is_ok());
        assert_eq!(
            require_future_within_horizon(&env, now + MAX_TIMESTAMP_HORIZON_SECS + 1),
            Err(ValidationError::TimestampTooFarFuture)
        );
        assert_eq!(
            require_future_within_horizon(&env, u64::MAX),
            Err(ValidationError::TimestampTooFarFuture)
        );
    }

    #[test]
    fn timestamp_horizon_allows_backdating_but_rejects_zero_and_far_future() {
        let env = setup();
        let now = env.ledger().timestamp();
        // Back-dating is allowed (issuer correcting a mistyped expiry).
        assert!(require_timestamp_horizon(&env, now - 1_000).is_ok());
        // Zero is a sentinel, not a real timestamp.
        assert_eq!(
            require_timestamp_horizon(&env, 0),
            Err(ValidationError::TimestampInPast)
        );
        // Immortal entries are rejected.
        assert_eq!(
            require_timestamp_horizon(&env, u64::MAX),
            Err(ValidationError::TimestampTooFarFuture)
        );
        assert!(require_timestamp_horizon(&env, now + MAX_TIMESTAMP_HORIZON_SECS).is_ok());
    }

    // ── Collections ──────────────────────────────────────────────────────

    #[test]
    fn batch_len_boundaries() {
        assert_eq!(require_batch_len(0, 50), Err(ValidationError::BatchEmpty));
        assert_eq!(
            require_batch_len(51, 50),
            Err(ValidationError::BatchTooLarge)
        );
        assert!(require_batch_len(50, 50).is_ok());
    }

    #[test]
    fn collection_room_boundary() {
        assert!(require_collection_room(0, 2).is_ok());
        assert!(require_collection_room(1, 2).is_ok());
        assert_eq!(
            require_collection_room(2, 2),
            Err(ValidationError::CollectionLimitExceeded)
        );
    }
}
