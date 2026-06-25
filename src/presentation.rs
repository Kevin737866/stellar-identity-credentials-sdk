use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Map, Symbol, Vec,
};

use crate::{VerifiablePresentation, PresentationRequest, PresentationResponse};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PresentationError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidFormat = 4,
    Expired = 5,
    InvalidCredential = 6,
    InvalidProof = 7,
    RequestAlreadyFulfilled = 8,
    RequestExpired = 9,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct SelectiveDisclosureEntry {
    pub credential_id: Bytes,
    pub zk_proof_ids: Vec<Bytes>,
    pub revealed_attributes: Vec<Symbol>,
}

#[contract]
pub struct PresentationManager;

#[contractimpl]
impl PresentationManager {
    const MAX_PRESENTATION_TYPE_LENGTH: u32 = 128;

    /// Create a verifiable presentation from a list of credential IDs.
    pub fn create_presentation(
        env: Env,
        holder: Address,
        credential_ids: Vec<Bytes>,
        presentation_type: Vec<Bytes>,
        proof: Option<Bytes>,
        expires_at: Option<u64>,
    ) -> Result<Bytes, PresentationError> {
        holder.require_auth();

        // Validate presentation types
        for pt in presentation_type.iter() {
            if pt.len() > Self::MAX_PRESENTATION_TYPE_LENGTH {
                return Err(PresentationError::InvalidFormat);
            }
        }

        // Validate credentials list is not empty
        if credential_ids.is_empty() {
            return Err(PresentationError::InvalidCredential);
        }

        // Generate presentation ID
        let presentation_id = Self::generate_presentation_id(&env, &holder);

        let now = env.ledger().timestamp();

        let presentation = VerifiablePresentation {
            id: presentation_id.clone(),
            holder: holder.clone(),
            credentials: credential_ids,
            type_: presentation_type,
            proof,
            created: now,
            expires_at,
        };

        // Store presentation
        env.storage().persistent().set(&presentation_id, &presentation);

        // Add to holder's presentations list
        let mut holder_presentations: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&holder)
            .unwrap_or_else(|| Vec::new(&env));
        holder_presentations.push_back(presentation_id.clone());
        env.storage().persistent().set(&holder, &holder_presentations);

        Ok(presentation_id)
    }

    /// Create a verifiable presentation with selective disclosure using ZK proofs.
    pub fn create_selective_disclosure_presentation(
        env: Env,
        holder: Address,
        presentation_type: Vec<Bytes>,
        disclosures: Vec<SelectiveDisclosureEntry>,
        proof: Option<Bytes>,
        expires_at: Option<u64>,
    ) -> Result<Bytes, PresentationError> {
        holder.require_auth();

        // Validate presentation types
        for pt in presentation_type.iter() {
            if pt.len() > Self::MAX_PRESENTATION_TYPE_LENGTH {
                return Err(PresentationError::InvalidFormat);
            }
        }

        if disclosures.is_empty() {
            return Err(PresentationError::InvalidCredential);
        }

        // Collect credential IDs from disclosures
        let mut credential_ids: Vec<Bytes> = Vec::new(&env);
        for entry in disclosures.iter() {
            credential_ids.push_back(entry.credential_id.clone());
        }

        let presentation_id = Self::generate_presentation_id(&env, &holder);
        let now = env.ledger().timestamp();

        let presentation = VerifiablePresentation {
            id: presentation_id.clone(),
            holder: holder.clone(),
            credentials: credential_ids,
            type_: presentation_type,
            proof,
            created: now,
            expires_at,
        };

        env.storage().persistent().set(&presentation_id, &presentation);

        // Store selective disclosure entries keyed by presentation_id
        let disclosure_key = Symbol::new(&env, &format!("disclosure:{}", presentation_id.to_string()));
        env.storage().persistent().set(&disclosure_key, &disclosures);

        // Add to holder's presentations list
        let mut holder_presentations: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&holder)
            .unwrap_or_else(|| Vec::new(&env));
        holder_presentations.push_back(presentation_id.clone());
        env.storage().persistent().set(&holder, &holder_presentations);

        Ok(presentation_id)
    }

    /// Get selective disclosure entries for a presentation.
    pub fn get_selective_disclosures(
        env: Env,
        presentation_id: Bytes,
    ) -> Vec<SelectiveDisclosureEntry> {
        let disclosure_key = Symbol::new(&env, &format!("disclosure:{}", presentation_id.to_string()));
        env.storage()
            .persistent()
            .get(&disclosure_key)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Verify a verifiable presentation.
    pub fn verify_presentation(
        env: Env,
        presentation_id: Bytes,
    ) -> Result<bool, PresentationError> {
        let presentation: VerifiablePresentation = env
            .storage()
            .persistent()
            .get(&presentation_id)
            .ok_or(PresentationError::NotFound)?;

        // Check expiration
        if let Some(expires_at) = presentation.expires_at {
            if env.ledger().timestamp() > expires_at {
                return Ok(false);
            }
        }

        // Verify proof if present (simplified)
        if let Some(proof) = presentation.proof {
            if proof.is_empty() {
                return Err(PresentationError::InvalidProof);
            }
        }

        Ok(true)
    }

    /// Get a verifiable presentation by ID.
    pub fn get_presentation(
        env: Env,
        presentation_id: Bytes,
    ) -> Result<VerifiablePresentation, PresentationError> {
        env.storage()
            .persistent()
            .get(&presentation_id)
            .ok_or(PresentationError::NotFound)
    }

    /// Manually expire a presentation (only the holder can expire).
    pub fn expire_presentation(
        env: Env,
        holder: Address,
        presentation_id: Bytes,
    ) -> Result<(), PresentationError> {
        holder.require_auth();

        let mut presentation: VerifiablePresentation = env
            .storage()
            .persistent()
            .get(&presentation_id)
            .ok_or(PresentationError::NotFound)?;

        if presentation.holder != holder {
            return Err(PresentationError::Unauthorized);
        }

        let now = env.ledger().timestamp();
        presentation.expires_at = Some(now);
        env.storage().persistent().set(&presentation_id, &presentation);

        Ok(())
    }

    /// Get all presentations for a holder.
    pub fn get_holder_presentations(env: Env, holder: Address) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&holder)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Create a presentation request (request/response protocol).
    pub fn create_presentation_request(
        env: Env,
        verifier: Address,
        query: Vec<Bytes>,
        challenge: Bytes,
        domain: Option<Bytes>,
        expires_at: Option<u64>,
    ) -> Result<Bytes, PresentationError> {
        verifier.require_auth();

        if query.is_empty() {
            return Err(PresentationError::InvalidFormat);
        }

        let request_id = Self::generate_request_id(&env, &verifier);
        let now = env.ledger().timestamp();

        let request = PresentationRequest {
            id: request_id.clone(),
            verifier: verifier.clone(),
            query,
            challenge,
            domain,
            expires_at,
            created: now,
        };

        env.storage().persistent().set(&request_id, &request);

        // Add to verifier's requests list
        let mut verifier_requests: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&verifier)
            .unwrap_or_else(|| Vec::new(&env));
        verifier_requests.push_back(request_id.clone());
        env.storage().persistent().set(&verifier, &verifier_requests);

        Ok(request_id)
    }

    /// Get a presentation request by ID.
    pub fn get_presentation_request(
        env: Env,
        request_id: Bytes,
    ) -> Result<PresentationRequest, PresentationError> {
        env.storage()
            .persistent()
            .get(&request_id)
            .ok_or(PresentationError::NotFound)
    }

    /// Fulfill a presentation request by submitting a presentation.
    pub fn fulfill_presentation_request(
        env: Env,
        responder: Address,
        request_id: Bytes,
        presentation_id: Bytes,
    ) -> Result<(), PresentationError> {
        responder.require_auth();

        // Verify request exists
        let request: PresentationRequest = env
            .storage()
            .persistent()
            .get(&request_id)
            .ok_or(PresentationError::NotFound)?;

        // Check request expiration
        if let Some(expires_at) = request.expires_at {
            if env.ledger().timestamp() > expires_at {
                return Err(PresentationError::RequestExpired);
            }
        }

        // Verify presentation exists
        let presentation: VerifiablePresentation = env
            .storage()
            .persistent()
            .get(&presentation_id)
            .ok_or(PresentationError::NotFound)?;

        if presentation.holder != responder {
            return Err(PresentationError::Unauthorized);
        }

        // Check if already fulfilled
        let fulfillment_key = Symbol::new(&env, &format!("fulfillment:{}", request_id.to_string()));
        if env.storage().persistent().has(&fulfillment_key) {
            return Err(PresentationError::RequestAlreadyFulfilled);
        }

        let now = env.ledger().timestamp();
        let response = PresentationResponse {
            request_id: request_id.clone(),
            presentation_id: presentation_id.clone(),
            responder: responder.clone(),
            created: now,
        };

        // Mark request as fulfilled
        env.storage().persistent().set(&fulfillment_key, &response);

        // Add to responder's fulfilled requests
        let mut responder_responses: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&responder)
            .unwrap_or_else(|| Vec::new(&env));
        responder_responses.push_back(request_id.clone());
        env.storage().persistent().set(&responder, &responder_responses);

        Ok(())
    }

    /// Get fulfilled response for a request.
    pub fn get_fulfillment(
        env: Env,
        request_id: Bytes,
    ) -> Option<PresentationResponse> {
        let fulfillment_key = Symbol::new(&env, &format!("fulfillment:{}", request_id.to_string()));
        env.storage().persistent().get(&fulfillment_key)
    }

    /// Generate a unique presentation ID.
    fn generate_presentation_id(env: &Env, holder: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let id_string = format!("vp:{}:{}", holder.to_string(), timestamp);
        Bytes::from_slice(env, id_string.as_bytes())
    }

    /// Generate a unique request ID.
    fn generate_request_id(env: &Env, verifier: &Address) -> Bytes {
        let timestamp = env.ledger().timestamp();
        let id_string = format!("req:{}:{}", verifier.to_string(), timestamp);
        Bytes::from_slice(env, id_string.as_bytes())
    }
}
