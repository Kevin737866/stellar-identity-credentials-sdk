//! Credential Offer and Acceptance Flow (#94)
//!
//! Enables push-based credential issuance where issuers can offer credentials
//! to holders, and holders can accept or reject them. Supports offer expiration
//! and full status tracking.
//!
//! ## Storage Schema
//!
//! | Variant                | Value type              | Storage tier |
//! |------------------------|------------------------|-------------|
//! | `Offer(Bytes)`         | `CredentialOffer`      | Persistent  |
//! | `Status(Bytes)`        | `OfferStatus`          | Persistent  |
//! | `IssuerOffers(Address)`| `Vec<Bytes>`           | Persistent  |
//! | `HolderOffers(Address)`| `Vec<Bytes>`           | Persistent  |
//! | `OfferIndex`           | `Vec<Bytes>`           | Persistent  |

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol, Vec,
};

use crate::{clamp_page_size, VerifiableCredential};

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum OfferKey {
    Offer(Bytes),
    Status(Bytes),
    IssuerOffers(Address),
    HolderOffers(Address),
    OfferIndex,
    IssuedCred(Bytes),
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum CredentialOfferError {
    Unauthorized = 1,
    NotFound = 2,
    AlreadyAccepted = 3,
    AlreadyRejected = 4,
    Expired = 5,
    InvalidOffer = 6,
    NotExpired = 7,
    AlreadyCancelled = 8,
    InvalidCredentialType = 9,
    OfferExpired = 10,
}

// ---------------------------------------------------------------------------
// Offer status enum
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfferStatusCode {
    Pending,
    Accepted,
    Rejected,
    Expired,
    Cancelled,
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialOffer {
    pub id: Bytes,
    pub issuer: Address,
    pub holder: Address,
    pub credential_type: Vec<Bytes>,
    pub credential_data: Bytes,
    pub schema_id: Option<Bytes>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub status: OfferStatusCode,
    pub rejection_reason: Option<Bytes>,
    pub accepted_at: Option<u64>,
    pub resulting_credential_id: Option<Bytes>,
    pub proof: Option<Bytes>,
    pub metadata: Option<Bytes>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferStatus {
    pub offer_id: Bytes,
    pub status: OfferStatusCode,
    pub updated_at: u64,
    pub detail: Option<Bytes>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaginatedOffers {
    pub data: Vec<Bytes>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct CredentialOfferContract;

#[contractimpl]
impl CredentialOfferContract {
    const MAX_CREDENTIAL_TYPE_LENGTH: u32 = 128;
    const MAX_CREDENTIAL_DATA_LENGTH: u32 = 10240;

    /// Create a credential offer from an issuer to a holder.
    ///
    /// The issuer must authorize the transaction. The offer will be stored
    /// and the holder can later accept or reject it.
    pub fn create_offer(
        env: Env,
        issuer: Address,
        holder: Address,
        credential_type: Vec<Bytes>,
        credential_data: Bytes,
        schema_id: Option<Bytes>,
        expires_at: Option<u64>,
        metadata: Option<Bytes>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialOfferError> {
        issuer.require_auth();

        // Validate credential type
        if credential_type.is_empty() {
            return Err(CredentialOfferError::InvalidCredentialType);
        }
        for ct in credential_type.iter() {
            if ct.len() > Self::MAX_CREDENTIAL_TYPE_LENGTH {
                return Err(CredentialOfferError::InvalidCredentialType);
            }
        }

        // Validate credential data
        if credential_data.is_empty() || credential_data.len() > Self::MAX_CREDENTIAL_DATA_LENGTH {
            return Err(CredentialOfferError::InvalidOffer);
        }

        // Validate expiration is in the future
        if let Some(exp) = expires_at {
            if exp <= env.ledger().timestamp() {
                return Err(CredentialOfferError::Expired);
            }
        }

        let now = env.ledger().timestamp();
        let offer_id = Self::generate_offer_id(&env, &issuer, &holder);

        let offer = CredentialOffer {
            id: offer_id.clone(),
            issuer: issuer.clone(),
            holder: holder.clone(),
            credential_type,
            credential_data,
            schema_id,
            created_at: now,
            expires_at,
            status: OfferStatusCode::Pending,
            rejection_reason: None,
            accepted_at: None,
            resulting_credential_id: None,
            proof: Some(proof),
            metadata,
        };

        // Store the offer
        env.storage()
            .persistent()
            .set(&OfferKey::Offer(offer_id.clone()), &offer);

        // Store status
        let status = OfferStatus {
            offer_id: offer_id.clone(),
            status: OfferStatusCode::Pending,
            updated_at: now,
            detail: None,
        };
        env.storage()
            .persistent()
            .set(&OfferKey::Status(offer_id.clone()), &status);

        // Add to issuer's offers
        let mut issuer_offers: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OfferKey::IssuerOffers(issuer.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        issuer_offers.push_back(offer_id.clone());
        env.storage()
            .persistent()
            .set(&OfferKey::IssuerOffers(issuer.clone()), &issuer_offers);

        // Add to holder's offers
        let mut holder_offers: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OfferKey::HolderOffers(holder.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        holder_offers.push_back(offer_id.clone());
        env.storage()
            .persistent()
            .set(&OfferKey::HolderOffers(holder.clone()), &holder_offers);

        // Add to global offer index
        let mut index: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OfferKey::OfferIndex)
            .unwrap_or_else(|| Vec::new(&env));
        index.push_back(offer_id.clone());
        env.storage()
            .persistent()
            .set(&OfferKey::OfferIndex, &index);

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "CredentialOfferCreated"),),
            (offer_id.clone(), issuer.clone(), holder.clone()),
        );

        Ok(offer_id)
    }

    /// Accept a credential offer.
    ///
    /// The holder must authorize. On successful acceptance, the credential
    /// is issued via the CredentialIssuer contract and the resulting credential
    /// ID is stored in the offer.
    pub fn accept_offer(
        env: Env,
        holder: Address,
        offer_id: Bytes,
    ) -> Result<Bytes, CredentialOfferError> {
        holder.require_auth();

        let mut offer: CredentialOffer = env
            .storage()
            .persistent()
            .get(&OfferKey::Offer(offer_id.clone()))
            .ok_or(CredentialOfferError::NotFound)?;

        // Verify holder matches
        if offer.holder != holder {
            return Err(CredentialOfferError::Unauthorized);
        }

        // Check current status
        match offer.status {
            OfferStatusCode::Accepted => return Err(CredentialOfferError::AlreadyAccepted),
            OfferStatusCode::Rejected => return Err(CredentialOfferError::AlreadyRejected),
            OfferStatusCode::Cancelled => return Err(CredentialOfferError::AlreadyCancelled),
            OfferStatusCode::Expired => return Err(CredentialOfferError::OfferExpired),
            OfferStatusCode::Pending => {}
        }

        // Check expiration
        if let Some(exp) = offer.expires_at {
            if env.ledger().timestamp() > exp {
                offer.status = OfferStatusCode::Expired;
                env.storage()
                    .persistent()
                    .set(&OfferKey::Offer(offer_id.clone()), &offer);
                Self::update_offer_status(&env, &offer_id, OfferStatusCode::Expired, None);
                return Err(CredentialOfferError::OfferExpired);
            }
        }

        let now = env.ledger().timestamp();

        // Issue the credential via the credential issuer
        let credential_id = Self::issue_credential_from_offer(
            &env,
            &offer.issuer,
            &offer.holder,
            &offer.credential_type,
            &offer.credential_data,
            offer.schema_id.clone(),
            None, // No additional expiration beyond what's in the offer
            offer
                .proof
                .clone()
                .unwrap_or_else(|| Bytes::from_slice(&env, b"offer_acceptance")),
        )?;

        // Update offer status
        offer.status = OfferStatusCode::Accepted;
        offer.accepted_at = Some(now);
        offer.resulting_credential_id = Some(credential_id.clone());

        env.storage()
            .persistent()
            .set(&OfferKey::Offer(offer_id.clone()), &offer);

        Self::update_offer_status(
            &env,
            &offer_id,
            OfferStatusCode::Accepted,
            Some(credential_id.clone()),
        );

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "CredentialOfferAccepted"),),
            (offer_id.clone(), holder, credential_id.clone()),
        );

        Ok(credential_id)
    }

    /// Reject a credential offer with an optional reason.
    ///
    /// The holder must authorize. Offers that have already been accepted,
    /// rejected, cancelled, or expired cannot be rejected again.
    pub fn reject_offer(
        env: Env,
        holder: Address,
        offer_id: Bytes,
        reason: Option<Bytes>,
    ) -> Result<(), CredentialOfferError> {
        holder.require_auth();

        let mut offer: CredentialOffer = env
            .storage()
            .persistent()
            .get(&OfferKey::Offer(offer_id.clone()))
            .ok_or(CredentialOfferError::NotFound)?;

        // Verify holder matches
        if offer.holder != holder {
            return Err(CredentialOfferError::Unauthorized);
        }

        // Check current status
        match offer.status {
            OfferStatusCode::Accepted => return Err(CredentialOfferError::AlreadyAccepted),
            OfferStatusCode::Rejected => return Err(CredentialOfferError::AlreadyRejected),
            OfferStatusCode::Cancelled => return Err(CredentialOfferError::AlreadyCancelled),
            OfferStatusCode::Expired => return Err(CredentialOfferError::OfferExpired),
            OfferStatusCode::Pending => {}
        }

        offer.status = OfferStatusCode::Rejected;
        offer.rejection_reason = reason.clone();

        env.storage()
            .persistent()
            .set(&OfferKey::Offer(offer_id.clone()), &offer);

        Self::update_offer_status(&env, &offer_id, OfferStatusCode::Rejected, reason);

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "CredentialOfferRejected"),),
            (offer_id, holder),
        );

        Ok(())
    }

    /// Cancel a credential offer (issuer only).
    ///
    /// Only the original issuer can cancel an offer. Once cancelled, it
    /// cannot be accepted or rejected.
    pub fn cancel_offer(
        env: Env,
        issuer: Address,
        offer_id: Bytes,
    ) -> Result<(), CredentialOfferError> {
        issuer.require_auth();

        let mut offer: CredentialOffer = env
            .storage()
            .persistent()
            .get(&OfferKey::Offer(offer_id.clone()))
            .ok_or(CredentialOfferError::NotFound)?;

        // Verify issuer matches
        if offer.issuer != issuer {
            return Err(CredentialOfferError::Unauthorized);
        }

        // Check current status
        match offer.status {
            OfferStatusCode::Accepted => return Err(CredentialOfferError::AlreadyAccepted),
            OfferStatusCode::Rejected => return Err(CredentialOfferError::AlreadyRejected),
            OfferStatusCode::Cancelled => return Err(CredentialOfferError::AlreadyCancelled),
            OfferStatusCode::Expired => return Err(CredentialOfferError::OfferExpired),
            OfferStatusCode::Pending => {}
        }

        offer.status = OfferStatusCode::Cancelled;

        env.storage()
            .persistent()
            .set(&OfferKey::Offer(offer_id.clone()), &offer);

        Self::update_offer_status(&env, &offer_id, OfferStatusCode::Cancelled, None);

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "CredentialOfferCancelled"),),
            (offer_id, issuer),
        );

        Ok(())
    }

    /// Get the current status of a credential offer.
    pub fn get_offer_status(
        env: Env,
        offer_id: Bytes,
    ) -> Result<OfferStatus, CredentialOfferError> {
        // First check if the offer has expired
        let offer: CredentialOffer = env
            .storage()
            .persistent()
            .get(&OfferKey::Offer(offer_id.clone()))
            .ok_or(CredentialOfferError::NotFound)?;

        // Auto-expire if past expiration and still pending
        if offer.status == OfferStatusCode::Pending {
            if let Some(exp) = offer.expires_at {
                if env.ledger().timestamp() > exp {
                    let mut expired_offer = offer;
                    expired_offer.status = OfferStatusCode::Expired;
                    env.storage()
                        .persistent()
                        .set(&OfferKey::Offer(offer_id.clone()), &expired_offer);

                    let expired_status = OfferStatus {
                        offer_id: offer_id.clone(),
                        status: OfferStatusCode::Expired,
                        updated_at: env.ledger().timestamp(),
                        detail: Some(Bytes::from_slice(&env, b"Auto-expired")),
                    };
                    env.storage()
                        .persistent()
                        .set(&OfferKey::Status(offer_id.clone()), &expired_status);

                    return Ok(expired_status);
                }
            }
        }

        env.storage()
            .persistent()
            .get(&OfferKey::Status(offer_id))
            .ok_or(CredentialOfferError::NotFound)
    }

    /// Get the full credential offer by ID.
    pub fn get_offer(env: Env, offer_id: Bytes) -> Result<CredentialOffer, CredentialOfferError> {
        let mut offer: CredentialOffer = env
            .storage()
            .persistent()
            .get(&OfferKey::Offer(offer_id))
            .ok_or(CredentialOfferError::NotFound)?;

        // Auto-expire if past expiration and still pending
        if offer.status == OfferStatusCode::Pending {
            if let Some(exp) = offer.expires_at {
                if env.ledger().timestamp() > exp {
                    offer.status = OfferStatusCode::Expired;
                    env.storage()
                        .persistent()
                        .set(&OfferKey::Offer(offer.id.clone()), &offer);
                }
            }
        }

        Ok(offer)
    }

    /// Get all offers for a given holder.
    pub fn get_holder_offers(env: Env, holder: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&OfferKey::HolderOffers(holder))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get all offers from a given issuer.
    pub fn get_issuer_offers(env: Env, issuer: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&OfferKey::IssuerOffers(issuer.clone()))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get paginated offers for a holder.
    pub fn get_holder_offers_paginated(
        env: Env,
        holder: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedOffers {
        let all: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OfferKey::HolderOffers(holder))
            .unwrap_or_else(|| Vec::new(&env));
        Self::paginate(&env, &all, page, page_size)
    }

    /// Get paginated offers for an issuer.
    pub fn get_issuer_offers_paginated(
        env: Env,
        issuer: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedOffers {
        let all: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OfferKey::IssuerOffers(issuer.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        Self::paginate(&env, &all, page, page_size)
    }

    /// Get all pending offers for a holder.
    pub fn get_pending_offers(env: Env, holder: Address) -> Vec<Bytes> {
        let all: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&OfferKey::HolderOffers(holder))
            .unwrap_or_else(|| Vec::new(&env));

        let mut pending: Vec<Bytes> = Vec::new(&env);
        for offer_id in all.iter() {
            if let Some(offer) = env
                .storage()
                .persistent()
                .get::<OfferKey, CredentialOffer>(&OfferKey::Offer(offer_id.clone()))
            {
                if offer.status == OfferStatusCode::Pending {
                    // Also check that it hasn't expired
                    let expired = offer
                        .expires_at
                        .map(|exp| env.ledger().timestamp() > exp)
                        .unwrap_or(false);
                    if !expired {
                        pending.push_back(offer_id);
                    }
                }
            }
        }

        pending
    }

    /// Check if an offer has expired.
    pub fn is_offer_expired(env: Env, offer_id: Bytes) -> Result<bool, CredentialOfferError> {
        let offer: CredentialOffer = env
            .storage()
            .persistent()
            .get(&OfferKey::Offer(offer_id))
            .ok_or(CredentialOfferError::NotFound)?;

        if offer.status == OfferStatusCode::Expired {
            return Ok(true);
        }

        if let Some(exp) = offer.expires_at {
            if env.ledger().timestamp() > exp {
                return Ok(true);
            }
        }

        Ok(false)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn generate_offer_id(env: &Env, _issuer: &Address, _holder: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let mut id = Bytes::from_slice(env, b"offer:");
        id.append(&Bytes::from_slice(env, timestamp.to_string().as_bytes()));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(
            env,
            env.ledger().sequence().to_string().as_bytes(),
        ));
        id
    }

    fn update_offer_status(
        env: &Env,
        offer_id: &Bytes,
        status: OfferStatusCode,
        detail: Option<Bytes>,
    ) {
        let status_record = OfferStatus {
            offer_id: offer_id.clone(),
            status,
            updated_at: env.ledger().timestamp(),
            detail,
        };
        env.storage()
            .persistent()
            .set(&OfferKey::Status(offer_id.clone()), &status_record);
    }

    fn issue_credential_from_offer(
        env: &Env,
        issuer: &Address,
        subject: &Address,
        credential_type: &Vec<Bytes>,
        credential_data: &Bytes,
        _schema_id: Option<Bytes>,
        _expiration_date: Option<u64>,
        proof: Bytes,
    ) -> Result<Bytes, CredentialOfferError> {
        // Generate a unique credential ID
        let timestamp = env.ledger().timestamp();
        let mut cred_id_bytes: alloc::vec::Vec<u8> =
            alloc::vec![b'v', b'c', b':', b'o', b'f', b'f', b'e', b'r', b':'];
        let ts_str = alloc::format!("{}", timestamp);
        let seq_str = alloc::format!("{}", env.ledger().sequence());
        cred_id_bytes.extend_from_slice(ts_str.as_bytes());
        cred_id_bytes.push(b':');
        cred_id_bytes.extend_from_slice(seq_str.as_bytes());
        let cred_id = Bytes::from_slice(env, &cred_id_bytes);

        // Store the issued credential from offer acceptance
        let credential = VerifiableCredential {
            id: cred_id.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            type_: credential_type.clone(),
            credential_data: credential_data.clone(),
            issuance_date: timestamp,
            expiration_date: None,
            schema_id: None,
            revocation: None,
            proof: Some(proof),
        };

        env.storage()
            .persistent()
            .set(&OfferKey::IssuedCred(cred_id.clone()), &credential);

        Ok(cred_id)
    }

    fn paginate(env: &Env, items: &Vec<Bytes>, page: u32, page_size: u32) -> PaginatedOffers {
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

        PaginatedOffers {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        vec, Address, Bytes, Env,
    };

    fn setup_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
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

    #[test]
    fn test_create_offer_success() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let cred_type = vec![&env, Bytes::from_slice(&env, b"KYCCredential")];
        let cred_data = Bytes::from_slice(&env, b"{\"name\":\"Alice\"}");
        let proof = Bytes::from_slice(&env, b"issuer_proof");

        let result = CredentialOfferContract::create_offer(
            env.clone(),
            issuer.clone(),
            holder.clone(),
            cred_type,
            cred_data,
            None,
            Some(1_700_500_000),
            None,
            proof,
        );
        assert!(result.is_ok());
        let offer_id = result.unwrap();

        let offer = CredentialOfferContract::get_offer(env.clone(), offer_id.clone()).unwrap();
        assert_eq!(offer.issuer, issuer);
        assert_eq!(offer.holder, holder);
        assert_eq!(offer.status, OfferStatusCode::Pending);
    }

    #[test]
    fn test_create_offer_expired_fails() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let result = CredentialOfferContract::create_offer(
            env.clone(),
            issuer,
            holder,
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_000_000_000), // Already expired
            None,
            Bytes::from_slice(&env, b"proof"),
        );
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), CredentialOfferError::Expired);
    }

    #[test]
    fn test_accept_offer() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer.clone(),
            holder.clone(),
            vec![&env, Bytes::from_slice(&env, b"KYCCredential")],
            Bytes::from_slice(&env, b"{\"name\":\"Bob\"}"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        let credential_id =
            CredentialOfferContract::accept_offer(env.clone(), holder.clone(), offer_id.clone())
                .unwrap();

        assert!(!credential_id.is_empty());

        let offer = CredentialOfferContract::get_offer(env.clone(), offer_id.clone()).unwrap();
        assert_eq!(offer.status, OfferStatusCode::Accepted);
        assert!(offer.accepted_at.is_some());
        assert_eq!(offer.resulting_credential_id.unwrap(), credential_id);
    }

    #[test]
    fn test_accept_already_accepted_fails() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer,
            holder.clone(),
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        CredentialOfferContract::accept_offer(env.clone(), holder.clone(), offer_id.clone())
            .unwrap();

        let result = CredentialOfferContract::accept_offer(env.clone(), holder, offer_id);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), CredentialOfferError::AlreadyAccepted);
    }

    #[test]
    fn test_reject_offer() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer,
            holder.clone(),
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        let reason = Bytes::from_slice(&env, b"Not interested");
        CredentialOfferContract::reject_offer(
            env.clone(),
            holder.clone(),
            offer_id.clone(),
            Some(reason.clone()),
        )
        .unwrap();

        let offer = CredentialOfferContract::get_offer(env.clone(), offer_id).unwrap();
        assert_eq!(offer.status, OfferStatusCode::Rejected);
        assert_eq!(offer.rejection_reason, Some(reason));
    }

    #[test]
    fn test_cancel_offer() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer.clone(),
            holder,
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        CredentialOfferContract::cancel_offer(env.clone(), issuer, offer_id.clone()).unwrap();

        let offer = CredentialOfferContract::get_offer(env.clone(), offer_id).unwrap();
        assert_eq!(offer.status, OfferStatusCode::Cancelled);
    }

    #[test]
    fn test_get_holder_offers() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        for _ in 0..3 {
            let _ = CredentialOfferContract::create_offer(
                env.clone(),
                issuer.clone(),
                holder.clone(),
                vec![&env, Bytes::from_slice(&env, b"Test")],
                Bytes::from_slice(&env, b"data"),
                None,
                Some(1_700_500_000),
                None,
                Bytes::from_slice(&env, b"proof"),
            );
        }

        let offers = CredentialOfferContract::get_holder_offers(env.clone(), holder);
        assert_eq!(offers.len(), 3);
    }

    #[test]
    fn test_get_pending_offers() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer,
            holder.clone(),
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        let pending = CredentialOfferContract::get_pending_offers(env.clone(), holder.clone());
        assert_eq!(pending.len(), 1);

        CredentialOfferContract::accept_offer(env.clone(), holder.clone(), offer_id).unwrap();

        let pending = CredentialOfferContract::get_pending_offers(env.clone(), holder);
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_paginated_holder_offers() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        for _ in 0..25 {
            let _ = CredentialOfferContract::create_offer(
                env.clone(),
                issuer.clone(),
                holder.clone(),
                vec![&env, Bytes::from_slice(&env, b"Test")],
                Bytes::from_slice(&env, b"data"),
                None,
                Some(1_700_500_000),
                None,
                Bytes::from_slice(&env, b"proof"),
            );
        }

        let page0 = CredentialOfferContract::get_holder_offers_paginated(
            env.clone(),
            holder.clone(),
            0,
            10,
        );
        assert_eq!(page0.data.len(), 10);
        assert_eq!(page0.total, 25);
        assert!(page0.has_more);

        let page2 =
            CredentialOfferContract::get_holder_offers_paginated(env.clone(), holder, 2, 10);
        assert_eq!(page2.data.len(), 5);
        assert!(!page2.has_more);
    }

    #[test]
    fn test_reject_rejected_offer_fails() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer,
            holder.clone(),
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        CredentialOfferContract::reject_offer(env.clone(), holder.clone(), offer_id.clone(), None)
            .unwrap();

        let result = CredentialOfferContract::reject_offer(env.clone(), holder, offer_id, None);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), CredentialOfferError::AlreadyRejected);
    }

    #[test]
    fn test_cancel_accepted_offer_fails() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer.clone(),
            holder.clone(),
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        CredentialOfferContract::accept_offer(env.clone(), holder, offer_id.clone()).unwrap();

        let result = CredentialOfferContract::cancel_offer(env.clone(), issuer, offer_id);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), CredentialOfferError::AlreadyAccepted);
    }

    #[test]
    fn test_unauthorized_accept_fails() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);
        let attacker = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer,
            holder,
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        let result = CredentialOfferContract::accept_offer(env.clone(), attacker, offer_id);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), CredentialOfferError::Unauthorized);
    }

    #[test]
    fn test_is_offer_expired() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer,
            holder,
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        assert!(!CredentialOfferContract::is_offer_expired(env.clone(), offer_id).unwrap());
    }

    #[test]
    fn test_get_offer_status() {
        let env = setup_env();
        let issuer = Address::generate(&env);
        let holder = Address::generate(&env);

        let offer_id = CredentialOfferContract::create_offer(
            env.clone(),
            issuer,
            holder,
            vec![&env, Bytes::from_slice(&env, b"Test")],
            Bytes::from_slice(&env, b"data"),
            None,
            Some(1_700_500_000),
            None,
            Bytes::from_slice(&env, b"proof"),
        )
        .unwrap();

        let status =
            CredentialOfferContract::get_offer_status(env.clone(), offer_id.clone()).unwrap();
        assert_eq!(status.status, OfferStatusCode::Pending);

        // Non-existent offer
        let result = CredentialOfferContract::get_offer_status(
            env.clone(),
            Bytes::from_slice(&env, b"nonexistent"),
        );
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), CredentialOfferError::NotFound);
    }
}
