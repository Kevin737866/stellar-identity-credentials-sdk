use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Address, Bytes, Env, Map, Symbol, Vec,
};

use crate::{clamp_page_size};

// ── Constants ─────────────────────────────────────────────────────────────────

const GDPR_TTL_LEDGERS: u32 = 6_307_200;
const MAX_CONSENT_RECORDS: u32 = 100;
const MAX_RETENTION_POLICIES: u32 = 20;
const MAX_PROCESSING_RECORDS: u32 = 200;
const MAX_DATA_SUBJECTS: u32 = 1000;

// ── Storage keys ──────────────────────────────────────────────────────────────

const KEY_ADMIN: &str = "admin";

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum GDPRComplianceError {
    Unauthorized = 1,
    NotFound = 2,
    InvalidInput = 3,
    NotInitialized = 4,
    AlreadyInitialized = 5,
    AlreadyExists = 6,
    ConsentNotGranted = 7,
    ConsentWithdrawn = 8,
    DataRetentionPeriodNotElapsed = 9,
    ErasureAlreadyRequested = 10,
    RectificationMismatch = 11,
    ExportTooLarge = 12,
    ProcessingRecordExists = 13,
    PolicyConflict = 14,
    DataSubjectRestricted = 15,
}

// ── Storage key enum ──────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum GdprKey {
    Config,
    Consent(Address, Bytes),
    ConsentIndex(Address),
    ErasureRequest(Address),
    RectificationRequest(Address, u64),
    RectificationIndex(Address),
    DataPortabilityExport(Address, u64),
    ExportIndex(Address),
    ProcessingRecord(Bytes),
    ProcessingRecordIndex,
    RetentionPolicy(Bytes),
    RetentionPolicyIndex,
    ErasureAudit(Address, u64),
    ErasureAuditIndex(Address),
}

// ── Data structures ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GDPRConfig {
    pub enabled: bool,
    pub default_retention_days: u64,
    pub erasure_grace_period_days: u64,
    pub consent_renewal_interval_days: u64,
    pub max_export_items: u32,
    pub require_rectification_verification: bool,
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsentStatus {
    Granted,
    Withdrawn,
    Expired,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessingBasis {
    Consent,
    ContractualNecessity,
    LegalObligation,
    VitalInterests,
    PublicTask,
    LegitimateInterests,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentRecord {
    pub data_subject: Address,
    pub purpose: Bytes,
    pub status: ConsentStatus,
    pub granted_at: u64,
    pub expires_at: u64,
    pub withdrawn_at: Option<u64>,
    pub processing_basis: ProcessingBasis,
    pub data_categories: Vec<Bytes>,
    pub third_party_sharing: bool,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRequest {
    pub data_subject: Address,
    pub requested_at: u64,
    pub processed_at: Option<u64>,
    pub retention_until: u64,
    pub scope: Bytes,
    pub reason: Bytes,
    pub status: Bytes,
    pub verified: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RectificationRequest {
    pub data_subject: Address,
    pub field_name: Bytes,
    pub current_value: Bytes,
    pub requested_value: Bytes,
    pub requested_at: u64,
    pub resolved_at: Option<u64>,
    pub status: Bytes,
    pub verified_by: Option<Address>,
    pub reason: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataPortabilityExport {
    pub data_subject: Address,
    pub requested_at: u64,
    pub format: Bytes,
    pub data_categories: Vec<Bytes>,
    pub consent_records: u32,
    pub processing_records: u32,
    pub content_hash: Bytes,
    pub status: Bytes,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingRecord {
    pub record_id: Bytes,
    pub controller: Address,
    pub processing_purpose: Bytes,
    pub processing_basis: ProcessingBasis,
    pub data_categories: Vec<Bytes>,
    pub data_subjects: Vec<Address>,
    pub retention_period_days: u64,
    pub third_party_transfers: Vec<Bytes>,
    pub security_measures: Vec<Bytes>,
    pub registered_at: u64,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    pub policy_id: Bytes,
    pub data_category: Bytes,
    pub retention_days: u64,
    pub legal_basis: Bytes,
    pub auto_delete: bool,
    pub active: bool,
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuditEntry {
    pub data_subject: Address,
    pub erased_at: u64,
    pub scope: Bytes,
    pub retention_until: u64,
    pub verified_by: Address,
    pub evidence_hash: Bytes,
}

// ── Paginated types ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedConsents {
    pub data: Vec<ConsentRecord>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedExports {
    pub data: Vec<DataPortabilityExport>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct GDPRCompliance;

#[contractimpl]
impl GDPRCompliance {
    // ── Initialization ────────────────────────────────────────────────────────

    pub fn initialize(env: Env, admin: Address) -> Result<(), GDPRComplianceError> {
        if env.storage().instance().has(&Symbol::new(&env, KEY_ADMIN)) {
            return Err(GDPRComplianceError::AlreadyInitialized);
        }

        env.storage().instance().set(&Symbol::new(&env, KEY_ADMIN), &admin);

        let config = GDPRConfig {
            enabled: true,
            default_retention_days: 365,
            erasure_grace_period_days: 30,
            consent_renewal_interval_days: 365,
            max_export_items: 100,
            require_rectification_verification: true,
            last_updated: env.ledger().timestamp(),
        };
        Self::persist(&env, &GdprKey::Config, &config);

        Ok(())
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    pub fn update_config(
        env: Env,
        caller: Address,
        enabled: Option<bool>,
        default_retention_days: Option<u64>,
        erasure_grace_period_days: Option<u64>,
        consent_renewal_interval_days: Option<u64>,
        max_export_items: Option<u32>,
        require_rectification_verification: Option<bool>,
    ) -> Result<(), GDPRComplianceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GDPRComplianceError::Unauthorized);
        }

        let mut config: GDPRConfig = env.storage().persistent()
            .get(&GdprKey::Config)
            .ok_or(GDPRComplianceError::NotInitialized)?;

        if let Some(v) = enabled { config.enabled = v; }
        if let Some(v) = default_retention_days { config.default_retention_days = v; }
        if let Some(v) = erasure_grace_period_days { config.erasure_grace_period_days = v; }
        if let Some(v) = consent_renewal_interval_days { config.consent_renewal_interval_days = v; }
        if let Some(v) = max_export_items { config.max_export_items = v; }
        if let Some(v) = require_rectification_verification { config.require_rectification_verification = v; }
        config.last_updated = env.ledger().timestamp();

        Self::persist(&env, &GdprKey::Config, &config);
        Ok(())
    }

    pub fn get_config(env: Env) -> GDPRConfig {
        env.storage().persistent()
            .get(&GdprKey::Config)
            .unwrap_or(GDPRConfig {
                enabled: true,
                default_retention_days: 365,
                erasure_grace_period_days: 30,
                consent_renewal_interval_days: 365,
                max_export_items: 100,
                require_rectification_verification: true,
                last_updated: 0,
            })
    }

    // ── Consent management ────────────────────────────────────────────────────

    pub fn grant_consent(
        env: Env,
        data_subject: Address,
        purpose: Bytes,
        processing_basis: ProcessingBasis,
        data_categories: Vec<Bytes>,
        third_party_sharing: bool,
    ) -> Result<(), GDPRComplianceError> {
        data_subject.require_auth();

        if purpose.is_empty() {
            return Err(GDPRComplianceError::InvalidInput);
        }

        let config = Self::get_config(env.clone());
        let now = env.ledger().timestamp();
        let expires_at = now + config.consent_renewal_interval_days * 24 * 60 * 60;

        let ck = GdprKey::Consent(data_subject.clone(), purpose.clone());
        if env.storage().persistent().has(&ck) {
            let existing: ConsentRecord = env.storage().persistent().get(&ck).unwrap();
            if existing.status == ConsentStatus::Granted {
                return Err(GDPRComplianceError::AlreadyExists);
            }
        }

        let consent = ConsentRecord {
            data_subject: data_subject.clone(),
            purpose: purpose.clone(),
            status: ConsentStatus::Granted,
            granted_at: now,
            expires_at,
            withdrawn_at: None,
            processing_basis,
            data_categories,
            third_party_sharing,
            timestamp: now,
        };

        Self::persist(&env, &ck, &consent);

        let mut idx: Vec<Bytes> = env.storage().persistent()
            .get(&GdprKey::ConsentIndex(data_subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        if idx.len() as u32 < MAX_CONSENT_RECORDS {
            idx.push_back(purpose);
            Self::persist(&env, &GdprKey::ConsentIndex(data_subject), &idx);
        }

        env.events().publish(
            (Symbol::new(&env, "consent_granted"), data_subject),
            purpose,
        );
        Ok(())
    }

    pub fn withdraw_consent(
        env: Env,
        data_subject: Address,
        purpose: Bytes,
    ) -> Result<(), GDPRComplianceError> {
        data_subject.require_auth();

        let ck = GdprKey::Consent(data_subject.clone(), purpose.clone());
        let mut consent: ConsentRecord = env.storage().persistent()
            .get(&ck)
            .ok_or(GDPRComplianceError::ConsentNotGranted)?;

        if consent.status == ConsentStatus::Withdrawn {
            return Err(GDPRComplianceError::ConsentWithdrawn);
        }

        consent.status = ConsentStatus::Withdrawn;
        consent.withdrawn_at = Some(env.ledger().timestamp());
        Self::persist(&env, &ck, &consent);

        env.events().publish(
            (Symbol::new(&env, "consent_withdrawn"), data_subject),
            purpose,
        );
        Ok(())
    }

    pub fn check_consent(
        env: Env,
        data_subject: Address,
        purpose: Bytes,
    ) -> Result<ConsentStatus, GDPRComplianceError> {
        let ck = GdprKey::Consent(data_subject.clone(), purpose.clone());
        let consent: ConsentRecord = env.storage().persistent()
            .get(&ck)
            .ok_or(GDPRComplianceError::ConsentNotGranted)?;

        let now = env.ledger().timestamp();
        if consent.status == ConsentStatus::Granted && now > consent.expires_at {
            return Ok(ConsentStatus::Expired);
        }

        Ok(consent.status)
    }

    pub fn get_consent_purposes(env: Env, data_subject: Address) -> Vec<Bytes> {
        env.storage().persistent()
            .get(&GdprKey::ConsentIndex(data_subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_consent(
        env: Env,
        data_subject: Address,
        purpose: Bytes,
    ) -> Option<ConsentRecord> {
        env.storage().persistent().get(&GdprKey::Consent(data_subject, purpose))
    }

    pub fn get_consents_paginated(
        env: Env,
        data_subject: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedConsents {
        let purposes: Vec<Bytes> = env.storage().persistent()
            .get(&GdprKey::ConsentIndex(data_subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = purposes.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(purpose) = purposes.get(i) {
                    if let Some(consent) = env.storage().persistent()
                        .get::<GdprKey, ConsentRecord>(&GdprKey::Consent(data_subject.clone(), purpose))
                    {
                        data.push_back(consent);
                    }
                }
            }
        }

        PaginatedConsents { data, page, total, has_more: (start + size) < total }
    }

    // ── Right to erasure (right to be forgotten) ──────────────────────────────

    pub fn request_erasure(
        env: Env,
        data_subject: Address,
        scope: Bytes,
        reason: Bytes,
    ) -> Result<(), GDPRComplianceError> {
        data_subject.require_auth();

        if scope.is_empty() || reason.is_empty() {
            return Err(GDPRComplianceError::InvalidInput);
        }

        let ek = GdprKey::ErasureRequest(data_subject.clone());
        if env.storage().persistent().has(&ek) {
            let existing: ErasureRequest = env.storage().persistent().get(&ek).unwrap();
            if existing.processed_at.is_none() {
                return Err(GDPRComplianceError::ErasureAlreadyRequested);
            }
        }

        let config = Self::get_config(env.clone());
        let now = env.ledger().timestamp();

        let request = ErasureRequest {
            data_subject: data_subject.clone(),
            requested_at: now,
            processed_at: None,
            retention_until: now + config.default_retention_days * 24 * 60 * 60,
            scope: scope.clone(),
            reason: reason.clone(),
            status: Bytes::from_slice(&env, b"pending"),
            verified: false,
        };

        Self::persist(&env, &ek, &request);

        env.events().publish(
            (Symbol::new(&env, "erasure_requested"), data_subject),
            (scope, reason),
        );
        Ok(())
    }

    pub fn process_erasure(
        env: Env,
        verifier: Address,
        data_subject: Address,
        evidence_hash: Bytes,
    ) -> Result<(), GDPRComplianceError> {
        verifier.require_auth();
        let admin = Self::require_admin(&env)?;
        if verifier != admin {
            return Err(GDPRComplianceError::Unauthorized);
        }

        let ek = GdprKey::ErasureRequest(data_subject.clone());
        let mut request: ErasureRequest = env.storage().persistent()
            .get(&ek)
            .ok_or(GDPRComplianceError::NotFound)?;

        if request.processed_at.is_some() {
            return Err(GDPRComplianceError::ErasureAlreadyRequested);
        }

        let now = env.ledger().timestamp();
        if now < request.retention_until {
            return Err(GDPRComplianceError::DataRetentionPeriodNotElapsed);
        }

        request.processed_at = Some(now);
        request.status = Bytes::from_slice(&env, b"processed");
        request.verified = true;
        Self::persist(&env, &ek, &request);

        let audit_key = GdprKey::ErasureAudit(data_subject.clone(), now);
        let audit_entry = ErasureAuditEntry {
            data_subject: data_subject.clone(),
            erased_at: now,
            scope: request.scope.clone(),
            retention_until: request.retention_until,
            verified_by: verifier.clone(),
            evidence_hash,
        };
        Self::persist(&env, &audit_key, &audit_entry);

        let mut audit_idx: Vec<u64> = env.storage().persistent()
            .get(&GdprKey::ErasureAuditIndex(data_subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        audit_idx.push_back(now);
        Self::persist(&env, &GdprKey::ErasureAuditIndex(data_subject), &audit_idx);

        env.events().publish(
            (Symbol::new(&env, "erasure_processed"), data_subject),
            now,
        );
        Ok(())
    }

    pub fn get_erasure_request(env: Env, data_subject: Address) -> Option<ErasureRequest> {
        env.storage().persistent().get(&GdprKey::ErasureRequest(data_subject))
    }

    pub fn get_erasure_audit_trail(env: Env, data_subject: Address) -> Vec<u64> {
        env.storage().persistent()
            .get(&GdprKey::ErasureAuditIndex(data_subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ── Right to rectification ────────────────────────────────────────────────

    pub fn request_rectification(
        env: Env,
        data_subject: Address,
        field_name: Bytes,
        current_value: Bytes,
        requested_value: Bytes,
        reason: Bytes,
    ) -> Result<u64, GDPRComplianceError> {
        data_subject.require_auth();

        if field_name.is_empty() || reason.is_empty() {
            return Err(GDPRComplianceError::InvalidInput);
        }

        let config = Self::get_config(env.clone());
        if config.require_rectification_verification && current_value == requested_value {
            return Err(GDPRComplianceError::RectificationMismatch);
        }

        let now = env.ledger().timestamp();
        let request = RectificationRequest {
            data_subject: data_subject.clone(),
            field_name: field_name.clone(),
            current_value: current_value.clone(),
            requested_value: requested_value.clone(),
            requested_at: now,
            resolved_at: None,
            status: Bytes::from_slice(&env, b"pending"),
            verified_by: None,
            reason: reason.clone(),
        };

        let rk = GdprKey::RectificationRequest(data_subject.clone(), now);
        Self::persist(&env, &rk, &request);

        let mut idx: Vec<u64> = env.storage().persistent()
            .get(&GdprKey::RectificationIndex(data_subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        idx.push_back(now);
        Self::persist(&env, &GdprKey::RectificationIndex(data_subject), &idx);

        env.events().publish(
            (Symbol::new(&env, "rectification_requested"), data_subject),
            (field_name, requested_value),
        );
        Ok(now)
    }

    pub fn resolve_rectification(
        env: Env,
        verifier: Address,
        data_subject: Address,
        timestamp: u64,
        status: Bytes,
        reason: Bytes,
    ) -> Result<(), GDPRComplianceError> {
        verifier.require_auth();
        let admin = Self::require_admin(&env)?;
        if verifier != admin {
            return Err(GDPRComplianceError::Unauthorized);
        }

        let rk = GdprKey::RectificationRequest(data_subject.clone(), timestamp);
        let mut request: RectificationRequest = env.storage().persistent()
            .get(&rk)
            .ok_or(GDPRComplianceError::NotFound)?;

        request.resolved_at = Some(env.ledger().timestamp());
        request.status = status;
        request.verified_by = Some(verifier);
        request.reason = reason;
        Self::persist(&env, &rk, &request);

        env.events().publish(
            (Symbol::new(&env, "rectification_resolved"), data_subject),
            (request.field_name, request.requested_value),
        );
        Ok(())
    }

    pub fn get_rectification_requests(
        env: Env,
        data_subject: Address,
    ) -> Vec<u64> {
        env.storage().persistent()
            .get(&GdprKey::RectificationIndex(data_subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_rectification(
        env: Env,
        data_subject: Address,
        timestamp: u64,
    ) -> Option<RectificationRequest> {
        env.storage().persistent()
            .get(&GdprKey::RectificationRequest(data_subject, timestamp))
    }

    // ── Data portability ──────────────────────────────────────────────────────

    pub fn request_data_export(
        env: Env,
        data_subject: Address,
        format: Bytes,
        data_categories: Vec<Bytes>,
    ) -> Result<u64, GDPRComplianceError> {
        data_subject.require_auth();

        if format.is_empty() || data_categories.is_empty() {
            return Err(GDPRComplianceError::InvalidInput);
        }

        let config = Self::get_config(env.clone());
        let now = env.ledger().timestamp();

        let purposes = Self::get_consent_purposes(env.clone(), data_subject.clone());
        let consent_count = purposes.len() as u32;

        let proc_idx: Vec<Bytes> = env.storage().persistent()
            .get(&GdprKey::ProcessingRecordIndex)
            .unwrap_or_else(|| Vec::new(&env));

        if consent_count > config.max_export_items || proc_idx.len() as u32 > config.max_export_items {
            return Err(GDPRComplianceError::ExportTooLarge);
        }

        let export = DataPortabilityExport {
            data_subject: data_subject.clone(),
            requested_at: now,
            format: format.clone(),
            data_categories: data_categories.clone(),
            consent_records: consent_count,
            processing_records: proc_idx.len() as u32,
            content_hash: Bytes::new(&env),
            status: Bytes::from_slice(&env, b"pending"),
            expires_at: now + 30 * 24 * 60 * 60,
        };

        let ek = GdprKey::DataPortabilityExport(data_subject.clone(), now);
        Self::persist(&env, &ek, &export);

        let mut idx: Vec<u64> = env.storage().persistent()
            .get(&GdprKey::ExportIndex(data_subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        idx.push_back(now);
        Self::persist(&env, &GdprKey::ExportIndex(data_subject), &idx);

        env.events().publish(
            (Symbol::new(&env, "data_export_requested"), data_subject),
            (format, now),
        );
        Ok(now)
    }

    pub fn complete_data_export(
        env: Env,
        verifier: Address,
        data_subject: Address,
        timestamp: u64,
        content_hash: Bytes,
    ) -> Result<(), GDPRComplianceError> {
        verifier.require_auth();
        let admin = Self::require_admin(&env)?;
        if verifier != admin {
            return Err(GDPRComplianceError::Unauthorized);
        }

        let ek = GdprKey::DataPortabilityExport(data_subject.clone(), timestamp);
        let mut export: DataPortabilityExport = env.storage().persistent()
            .get(&ek)
            .ok_or(GDPRComplianceError::NotFound)?;

        export.content_hash = content_hash;
        export.status = Bytes::from_slice(&env, b"completed");
        Self::persist(&env, &ek, &export);

        env.events().publish(
            (Symbol::new(&env, "data_export_completed"), data_subject),
            timestamp,
        );
        Ok(())
    }

    pub fn get_data_exports(env: Env, data_subject: Address) -> Vec<u64> {
        env.storage().persistent()
            .get(&GdprKey::ExportIndex(data_subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_data_export(
        env: Env,
        data_subject: Address,
        timestamp: u64,
    ) -> Option<DataPortabilityExport> {
        env.storage().persistent()
            .get(&GdprKey::DataPortabilityExport(data_subject, timestamp))
    }

    pub fn get_exports_paginated(
        env: Env,
        data_subject: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedExports {
        let timestamps: Vec<u64> = env.storage().persistent()
            .get(&GdprKey::ExportIndex(data_subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = timestamps.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(ts) = timestamps.get(i) {
                    if let Some(export) = env.storage().persistent()
                        .get::<GdprKey, DataPortabilityExport>(&GdprKey::DataPortabilityExport(data_subject.clone(), ts))
                    {
                        data.push_back(export);
                    }
                }
            }
        }

        PaginatedExports { data, page, total, has_more: (start + size) < total }
    }

    // ── Processing records ────────────────────────────────────────────────────

    pub fn register_processing_record(
        env: Env,
        caller: Address,
        record_id: Bytes,
        controller: Address,
        processing_purpose: Bytes,
        processing_basis: ProcessingBasis,
        data_categories: Vec<Bytes>,
        data_subjects: Vec<Address>,
        retention_period_days: u64,
        third_party_transfers: Vec<Bytes>,
        security_measures: Vec<Bytes>,
    ) -> Result<(), GDPRComplianceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GDPRComplianceError::Unauthorized);
        }

        if record_id.is_empty() || processing_purpose.is_empty() {
            return Err(GDPRComplianceError::InvalidInput);
        }

        let pk = GdprKey::ProcessingRecord(record_id.clone());
        if env.storage().persistent().has(&pk) {
            return Err(GDPRComplianceError::ProcessingRecordExists);
        }

        let record = ProcessingRecord {
            record_id: record_id.clone(),
            controller,
            processing_purpose,
            processing_basis,
            data_categories,
            data_subjects,
            retention_period_days,
            third_party_transfers,
            security_measures,
            registered_at: env.ledger().timestamp(),
            active: true,
        };

        Self::persist(&env, &pk, &record);

        let mut idx: Vec<Bytes> = env.storage().persistent()
            .get(&GdprKey::ProcessingRecordIndex)
            .unwrap_or_else(|| Vec::new(&env));
        if idx.len() as u32 < MAX_PROCESSING_RECORDS {
            idx.push_back(record_id);
            Self::persist(&env, &GdprKey::ProcessingRecordIndex, &idx);
        }

        env.events().publish(
            (Symbol::new(&env, "processing_record_registered"),),
            record_id,
        );
        Ok(())
    }

    pub fn deactivate_processing_record(
        env: Env,
        caller: Address,
        record_id: Bytes,
    ) -> Result<(), GDPRComplianceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GDPRComplianceError::Unauthorized);
        }

        let pk = GdprKey::ProcessingRecord(record_id.clone());
        let mut record: ProcessingRecord = env.storage().persistent()
            .get(&pk)
            .ok_or(GDPRComplianceError::NotFound)?;
        record.active = false;
        Self::persist(&env, &pk, &record);
        Ok(())
    }

    pub fn get_processing_record(env: Env, record_id: Bytes) -> Option<ProcessingRecord> {
        env.storage().persistent().get(&GdprKey::ProcessingRecord(record_id))
    }

    pub fn get_all_processing_record_ids(env: Env) -> Vec<Bytes> {
        env.storage().persistent()
            .get(&GdprKey::ProcessingRecordIndex)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ── Retention policies ────────────────────────────────────────────────────

    pub fn register_retention_policy(
        env: Env,
        caller: Address,
        policy_id: Bytes,
        data_category: Bytes,
        retention_days: u64,
        legal_basis: Bytes,
        auto_delete: bool,
    ) -> Result<(), GDPRComplianceError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GDPRComplianceError::Unauthorized);
        }

        if policy_id.is_empty() || data_category.is_empty() {
            return Err(GDPRComplianceError::InvalidInput);
        }

        let pk = GdprKey::RetentionPolicy(policy_id.clone());
        if env.storage().persistent().has(&pk) {
            return Err(GDPRComplianceError::AlreadyExists);
        }

        let config = Self::get_config(env.clone());
        if retention_days < config.default_retention_days / 2 {
            return Err(GDPRComplianceError::PolicyConflict);
        }

        let policy = RetentionPolicy {
            policy_id: policy_id.clone(),
            data_category,
            retention_days,
            legal_basis,
            auto_delete,
            active: true,
            created_at: env.ledger().timestamp(),
        };

        Self::persist(&env, &pk, &policy);

        let mut idx: Vec<Bytes> = env.storage().persistent()
            .get(&GdprKey::RetentionPolicyIndex)
            .unwrap_or_else(|| Vec::new(&env));
        if idx.len() as u32 < MAX_RETENTION_POLICIES {
            idx.push_back(policy_id);
            Self::persist(&env, &GdprKey::RetentionPolicyIndex, &idx);
        }

        Ok(())
    }

    pub fn get_retention_policy(env: Env, policy_id: Bytes) -> Option<RetentionPolicy> {
        env.storage().persistent().get(&GdprKey::RetentionPolicy(policy_id))
    }

    pub fn get_all_retention_policy_ids(env: Env) -> Vec<Bytes> {
        env.storage().persistent()
            .get(&GdprKey::RetentionPolicyIndex)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<Address, GDPRComplianceError> {
        env.storage().instance()
            .get::<Symbol, Address>(&Symbol::new(env, KEY_ADMIN))
            .ok_or(GDPRComplianceError::NotInitialized)
    }

    fn persist<K, V>(env: &Env, key: &K, value: &V)
    where
        K: soroban_sdk::TryIntoVal<Env, soroban_sdk::Val>
            + soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
        V: soroban_sdk::TryIntoVal<Env, soroban_sdk::Val>
            + soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
    {
        env.storage().persistent().set(key, value);
        env.storage()
            .persistent()
            .extend_ttl(key, GDPR_TTL_LEDGERS, GDPR_TTL_LEDGERS);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{Address, Bytes, Env, Symbol, Vec};

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

    fn bootstrap(env: &Env) -> Address {
        let admin = Address::generate(env);
        GDPRCompliance::initialize(env.clone(), admin.clone()).unwrap();
        admin
    }

    #[test]
    fn initializes_successfully() {
        let env = setup_env();
        let admin = Address::generate(&env);
        assert!(GDPRCompliance::initialize(env, admin).is_ok());
    }

    #[test]
    fn double_initialize_returns_error() {
        let env = setup_env();
        bootstrap(&env);
        let result = GDPRCompliance::initialize(env.clone(), Address::generate(&env));
        assert_eq!(result.unwrap_err(), GDPRComplianceError::AlreadyInitialized);
    }

    // ── Consent tests ─────────────────────────────────────────────────────────

    #[test]
    fn grant_and_check_consent() {
        let env = setup_env();
        bootstrap(&env);
        let user = Address::generate(&env);

        GDPRCompliance::grant_consent(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"kyc_processing"),
            ProcessingBasis::Consent,
            Vec::from_array(&env, [Bytes::from_slice(&env, b"identity")]),
            false,
        ).unwrap();

        let status = GDPRCompliance::check_consent(
            env.clone(),
            user,
            Bytes::from_slice(&env, b"kyc_processing"),
        ).unwrap();
        assert_eq!(status, ConsentStatus::Granted);
    }

    #[test]
    fn withdraw_consent() {
        let env = setup_env();
        bootstrap(&env);
        let user = Address::generate(&env);

        GDPRCompliance::grant_consent(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"data_analytics"),
            ProcessingBasis::Consent,
            Vec::from_array(&env, [Bytes::from_slice(&env, b"usage")]),
            false,
        ).unwrap();

        GDPRCompliance::withdraw_consent(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"data_analytics"),
        ).unwrap();

        let status = GDPRCompliance::check_consent(
            env.clone(),
            user,
            Bytes::from_slice(&env, b"data_analytics"),
        ).unwrap();
        assert_eq!(status, ConsentStatus::Withdrawn);
    }

    #[test]
    fn duplicate_consent_returns_error() {
        let env = setup_env();
        bootstrap(&env);
        let user = Address::generate(&env);

        GDPRCompliance::grant_consent(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"marketing"),
            ProcessingBasis::Consent,
            Vec::new(&env),
            false,
        ).unwrap();

        let result = GDPRCompliance::grant_consent(
            env.clone(),
            user,
            Bytes::from_slice(&env, b"marketing"),
            ProcessingBasis::Consent,
            Vec::new(&env),
            false,
        );
        assert_eq!(result.unwrap_err(), GDPRComplianceError::AlreadyExists);
    }

    #[test]
    fn get_consent_purposes() {
        let env = setup_env();
        bootstrap(&env);
        let user = Address::generate(&env);

        GDPRCompliance::grant_consent(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"purpose_a"),
            ProcessingBasis::Consent,
            Vec::new(&env),
            false,
        ).unwrap();

        GDPRCompliance::grant_consent(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"purpose_b"),
            ProcessingBasis::LegalObligation,
            Vec::new(&env),
            false,
        ).unwrap();

        let purposes = GDPRCompliance::get_consent_purposes(env.clone(), user);
        assert_eq!(purposes.len(), 2);
    }

    // ── Erasure tests ─────────────────────────────────────────────────────────

    #[test]
    fn request_and_process_erasure() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let user = Address::generate(&env);

        GDPRCompliance::request_erasure(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"all_data"),
            Bytes::from_slice(&env, b"no_longer_needed"),
        ).unwrap();

        let request = GDPRCompliance::get_erasure_request(env.clone(), user.clone()).unwrap();
        assert_eq!(request.status, Bytes::from_slice(&env, b"pending"));

        let future_time = 1_700_000_000 + 366 * 24 * 60 * 60;
        env.ledger().set(LedgerInfo {
            timestamp: future_time,
            protocol_version: 22,
            sequence_number: 5000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });

        GDPRCompliance::process_erasure(
            env.clone(),
            admin,
            user.clone(),
            Bytes::from_slice(&env, b"evidence_hash_123"),
        ).unwrap();

        let processed = GDPRCompliance::get_erasure_request(env.clone(), user.clone()).unwrap();
        assert_eq!(processed.status, Bytes::from_slice(&env, b"processed"));

        let audit = GDPRCompliance::get_erasure_audit_trail(env, user);
        assert_eq!(audit.len(), 1);
    }

    #[test]
    fn duplicate_erasure_request_fails() {
        let env = setup_env();
        bootstrap(&env);
        let user = Address::generate(&env);

        GDPRCompliance::request_erasure(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"all"),
            Bytes::from_slice(&env, b"reason"),
        ).unwrap();

        let result = GDPRCompliance::request_erasure(
            env.clone(),
            user,
            Bytes::from_slice(&env, b"all"),
            Bytes::from_slice(&env, b"reason"),
        );
        assert_eq!(result.unwrap_err(), GDPRComplianceError::ErasureAlreadyRequested);
    }

    // ── Rectification tests ───────────────────────────────────────────────────

    #[test]
    fn request_and_resolve_rectification() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let user = Address::generate(&env);

        let ts = GDPRCompliance::request_rectification(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"name"),
            Bytes::from_slice(&env, b"John"),
            Bytes::from_slice(&env, b"Jonathan"),
            Bytes::from_slice(&env, b"legal_name_change"),
        ).unwrap();

        let requests = GDPRCompliance::get_rectification_requests(env.clone(), user.clone());
        assert_eq!(requests.len(), 1);

        GDPRCompliance::resolve_rectification(
            env.clone(),
            admin,
            user.clone(),
            ts,
            Bytes::from_slice(&env, b"approved"),
            Bytes::from_slice(&env, b"verified_with_document"),
        ).unwrap();

        let rect = GDPRCompliance::get_rectification(env, user, ts).unwrap();
        assert_eq!(rect.status, Bytes::from_slice(&env, b"approved"));
    }

    #[test]
    fn rectification_rejects_identical_values() {
        let env = setup_env();
        bootstrap(&env);
        let user = Address::generate(&env);

        let result = GDPRCompliance::request_rectification(
            env.clone(),
            user,
            Bytes::from_slice(&env, b"name"),
            Bytes::from_slice(&env, b"John"),
            Bytes::from_slice(&env, b"John"),
            Bytes::from_slice(&env, b"no_change"),
        );
        assert_eq!(result.unwrap_err(), GDPRComplianceError::RectificationMismatch);
    }

    // ── Data portability tests ────────────────────────────────────────────────

    #[test]
    fn request_and_complete_data_export() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let user = Address::generate(&env);

        GDPRCompliance::grant_consent(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"processing"),
            ProcessingBasis::Consent,
            Vec::new(&env),
            false,
        ).unwrap();

        let ts = GDPRCompliance::request_data_export(
            env.clone(),
            user.clone(),
            Bytes::from_slice(&env, b"json"),
            Vec::from_array(&env, [Bytes::from_slice(&env, b"identity")]),
        ).unwrap();

        GDPRCompliance::complete_data_export(
            env.clone(),
            admin,
            user.clone(),
            ts,
            Bytes::from_slice(&env, b"hash_v1"),
        ).unwrap();

        let export = GDPRCompliance::get_data_export(env.clone(), user.clone(), ts).unwrap();
        assert_eq!(export.status, Bytes::from_slice(&env, b"completed"));

        let exports = GDPRCompliance::get_data_exports(env, user);
        assert_eq!(exports.len(), 1);
    }

    // ── Processing records tests ──────────────────────────────────────────────

    #[test]
    fn register_and_retrieve_processing_record() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let controller = Address::generate(&env);

        GDPRCompliance::register_processing_record(
            env.clone(),
            admin.clone(),
            Bytes::from_slice(&env, b"REC-001"),
            controller,
            Bytes::from_slice(&env, b"identity_verification"),
            ProcessingBasis::LegalObligation,
            Vec::from_array(&env, [Bytes::from_slice(&env, b"pii")]),
            Vec::new(&env),
            365,
            Vec::new(&env),
            Vec::from_array(&env, [Bytes::from_slice(&env, b"encryption_at_rest")]),
        ).unwrap();

        let record = GDPRCompliance::get_processing_record(
            env.clone(),
            Bytes::from_slice(&env, b"REC-001"),
        ).unwrap();
        assert!(record.active);
        assert_eq!(
            record.processing_purpose,
            Bytes::from_slice(&env, b"identity_verification")
        );

        let all_ids = GDPRCompliance::get_all_processing_record_ids(env);
        assert_eq!(all_ids.len(), 1);
    }

    #[test]
    fn duplicate_processing_record_fails() {
        let env = setup_env();
        let admin = bootstrap(&env);

        GDPRCompliance::register_processing_record(
            env.clone(),
            admin.clone(),
            Bytes::from_slice(&env, b"REC-001"),
            Address::generate(&env),
            Bytes::from_slice(&env, b"purpose"),
            ProcessingBasis::Consent,
            Vec::new(&env),
            Vec::new(&env),
            365,
            Vec::new(&env),
            Vec::new(&env),
        ).unwrap();

        let result = GDPRCompliance::register_processing_record(
            env.clone(),
            admin,
            Bytes::from_slice(&env, b"REC-001"),
            Address::generate(&env),
            Bytes::from_slice(&env, b"purpose"),
            ProcessingBasis::Consent,
            Vec::new(&env),
            Vec::new(&env),
            365,
            Vec::new(&env),
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), GDPRComplianceError::ProcessingRecordExists);
    }

    // ── Retention policy tests ────────────────────────────────────────────────

    #[test]
    fn register_and_retrieve_retention_policy() {
        let env = setup_env();
        let admin = bootstrap(&env);

        GDPRCompliance::register_retention_policy(
            env.clone(),
            admin,
            Bytes::from_slice(&env, b"POL-KYC"),
            Bytes::from_slice(&env, b"kyc_data"),
            730,
            Bytes::from_slice(&env, b"AML_obligation"),
            true,
        ).unwrap();

        let policy = GDPRCompliance::get_retention_policy(
            env.clone(),
            Bytes::from_slice(&env, b"POL-KYC"),
        ).unwrap();
        assert!(policy.active);
        assert_eq!(policy.retention_days, 730);

        let all = GDPRCompliance::get_all_retention_policy_ids(env);
        assert_eq!(all.len(), 1);
    }
}
