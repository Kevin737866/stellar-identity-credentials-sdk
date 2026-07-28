//! Credential Data Encryption at Rest (#73)
//!
//! Provides XOR-based symmetric encryption for credential PII stored on-chain,
//! keyed by the holder's public key material.  The scheme is intentionally
//! simple so it compiles inside the Soroban `no_std` environment without
//! pulling in additional crates.
//!
//! # Encryption scheme
//! `ciphertext[i] = plaintext[i] XOR key[i % key.len()]`
//!
//! A real production deployment should replace this with an authenticated
//! encryption scheme (e.g. AES-256-GCM) once an appropriate `no_std` crate
//! is available for Soroban.

use soroban_sdk::{contracttype, Address, Bytes, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Storage key
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum EncKey {
    /// Encrypted credential blob keyed by credential_id.
    Encrypted(Bytes),
    /// Key-handle record keyed by holder address.
    KeyHandle(Address),
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Metadata stored alongside the encrypted blob.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EncryptedCredential {
    /// Identifier of the credential this blob belongs to.
    pub credential_id: Bytes,
    /// The holder whose public key was used to derive the encryption key.
    pub holder: Address,
    /// The encrypted payload (XOR of plaintext and key-stream).
    pub ciphertext: Bytes,
    /// A short tag that can be used to verify key ownership before decryption.
    pub key_tag: Bytes,
    /// Ledger timestamp at encryption time.
    pub created_at: u64,
}

/// A lightweight key-handle stored per holder so the SDK can locate which
/// key material to use when decrypting.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EncryptionKeyHandle {
    pub holder: Address,
    /// First 8 bytes of the raw key — used as a tag / hint.
    pub key_hint: Bytes,
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Core helpers (pure, no storage I/O)
// ---------------------------------------------------------------------------

/// Derive a deterministic key-stream of length `length` from `raw_key`.
///
/// The key is repeated cyclically (standard stream-cipher expansion).
fn derive_key_stream(env: &Env, raw_key: &Bytes, length: u32) -> Bytes {
    let key_len = raw_key.len();
    if key_len == 0 || length == 0 {
        return Bytes::new(env);
    }

    let mut stream = Bytes::new(env);
    let mut written: u32 = 0;
    while written < length {
        let pos = written % key_len;
        stream.push_back(raw_key.get(pos).unwrap_or(0));
        written += 1;
    }
    stream
}

/// XOR `data` with the first `data.len()` bytes of `key_stream`.
fn xor_bytes(env: &Env, data: &Bytes, key_stream: &Bytes) -> Bytes {
    let len = data.len();
    let mut out = Bytes::new(env);
    for i in 0..len {
        let d = data.get(i).unwrap_or(0);
        let k = key_stream.get(i).unwrap_or(0);
        out.push_back(d ^ k);
    }
    out
}

/// Compute an 8-byte tag from `raw_key` by XOR-folding all bytes.
fn compute_key_tag(env: &Env, raw_key: &Bytes) -> Bytes {
    let mut tag = [0u8; 8];
    for (i, byte) in raw_key.iter().enumerate() {
        tag[i % 8] ^= byte;
    }
    Bytes::from_slice(env, &tag)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` using `holder_key` as the encryption key.
///
/// Returns the [`EncryptedCredential`] record; callers are responsible for
/// persisting it via [`store_encrypted_credential`].
pub fn encrypt_credential(
    env: &Env,
    credential_id: Bytes,
    holder: Address,
    plaintext: Bytes,
    holder_key: Bytes,
) -> EncryptedCredential {
    let key_stream = derive_key_stream(env, &holder_key, plaintext.len());
    let ciphertext = xor_bytes(env, &plaintext, &key_stream);
    let key_tag = compute_key_tag(env, &holder_key);

    EncryptedCredential {
        credential_id,
        holder,
        ciphertext,
        key_tag,
        created_at: env.ledger().timestamp(),
    }
}

/// Decrypt a previously encrypted credential.
///
/// Returns `None` if the key tag does not match (wrong key supplied).
pub fn decrypt_credential(
    env: &Env,
    encrypted: &EncryptedCredential,
    holder_key: &Bytes,
) -> Option<Bytes> {
    let expected_tag = compute_key_tag(env, holder_key);
    if expected_tag != encrypted.key_tag {
        return None;
    }
    let key_stream = derive_key_stream(env, holder_key, encrypted.ciphertext.len());
    Some(xor_bytes(env, &encrypted.ciphertext, &key_stream))
}

/// Persist an [`EncryptedCredential`] in contract storage.
pub fn store_encrypted_credential(env: &Env, record: &EncryptedCredential) {
    env.storage()
        .persistent()
        .set(&EncKey::Encrypted(record.credential_id.clone()), record);
}

/// Retrieve an [`EncryptedCredential`] by `credential_id`.
pub fn get_encrypted_credential(env: &Env, credential_id: Bytes) -> Option<EncryptedCredential> {
    env.storage()
        .persistent()
        .get(&EncKey::Encrypted(credential_id))
}

/// Register a key-handle for `holder`.
pub fn register_key_handle(env: &Env, holder: Address, raw_key: &Bytes) {
    let hint_len = raw_key.len().min(8);
    let mut hint_bytes = Bytes::new(env);
    for i in 0..hint_len {
        hint_bytes.push_back(raw_key.get(i).unwrap_or(0));
    }

    let handle = EncryptionKeyHandle {
        holder: holder.clone(),
        key_hint: hint_bytes,
        created_at: env.ledger().timestamp(),
    };
    env.storage()
        .persistent()
        .set(&EncKey::KeyHandle(holder), &handle);
}

/// Retrieve the key-handle for `holder`.
pub fn get_key_handle(env: &Env, holder: Address) -> Option<EncryptionKeyHandle> {
    env.storage()
        .persistent()
        .get(&EncKey::KeyHandle(holder))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Env,
    };

    fn setup() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000,
            protocol_version: 22,
            sequence_number: 1,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });
        env
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let env = setup();
        let holder = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-001");
        let plaintext = Bytes::from_slice(&env, b"sensitive PII data: John Doe, DOB 1990-01-15");
        let key = Bytes::from_slice(&env, b"32-byte-encryption-key-for-test!");

        let encrypted = encrypt_credential(&env, cred_id, holder, plaintext.clone(), key.clone());
        assert_ne!(encrypted.ciphertext, plaintext, "ciphertext must differ from plaintext");

        let decrypted = decrypt_credential(&env, &encrypted, &key);
        assert!(decrypted.is_some(), "decryption must succeed with correct key");
        assert_eq!(decrypted.unwrap(), plaintext, "decrypted must match original");
    }

    #[test]
    fn wrong_key_returns_none() {
        let env = setup();
        let holder = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-002");
        let plaintext = Bytes::from_slice(&env, b"secret data");
        let key = Bytes::from_slice(&env, b"correct-key");
        let wrong_key = Bytes::from_slice(&env, b"wrong---key");

        let encrypted = encrypt_credential(&env, cred_id, holder, plaintext, key);
        let result = decrypt_credential(&env, &encrypted, &wrong_key);
        assert!(result.is_none(), "wrong key must return None");
    }

    #[test]
    fn store_and_retrieve_encrypted_credential() {
        let env = setup();
        let holder = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-003");
        let plaintext = Bytes::from_slice(&env, b"stored data");
        let key = Bytes::from_slice(&env, b"test-key");

        let encrypted = encrypt_credential(&env, cred_id.clone(), holder, plaintext.clone(), key.clone());
        store_encrypted_credential(&env, &encrypted);

        let retrieved = get_encrypted_credential(&env, cred_id);
        assert!(retrieved.is_some());
        let decrypted = decrypt_credential(&env, &retrieved.unwrap(), &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn key_handle_registration_and_retrieval() {
        let env = setup();
        let holder = Address::generate(&env);
        let key = Bytes::from_slice(&env, b"holder-public-key-material");

        register_key_handle(&env, holder.clone(), &key);

        let handle = get_key_handle(&env, holder.clone());
        assert!(handle.is_some());
        let handle = handle.unwrap();
        assert_eq!(handle.holder, holder);
        assert_eq!(handle.key_hint.len(), 8);
    }

    #[test]
    fn empty_plaintext_encrypts_to_empty() {
        let env = setup();
        let holder = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-empty");
        let plaintext = Bytes::new(&env);
        let key = Bytes::from_slice(&env, b"any-key");

        let encrypted = encrypt_credential(&env, cred_id, holder, plaintext.clone(), key.clone());
        assert!(encrypted.ciphertext.is_empty());
        let decrypted = decrypt_credential(&env, &encrypted, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn different_keys_produce_different_ciphertexts() {
        let env = setup();
        let holder = Address::generate(&env);
        let plaintext = Bytes::from_slice(&env, b"same plaintext");
        let key_a = Bytes::from_slice(&env, b"key-aaaaaaa");
        let key_b = Bytes::from_slice(&env, b"key-bbbbbbb");

        let enc_a = encrypt_credential(&env, Bytes::from_slice(&env, b"id-a"), holder.clone(), plaintext.clone(), key_a);
        let enc_b = encrypt_credential(&env, Bytes::from_slice(&env, b"id-b"), holder, plaintext, key_b);

        assert_ne!(enc_a.ciphertext, enc_b.ciphertext);
    }
}
