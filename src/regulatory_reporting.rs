//! Regulatory Reporting Contract (#114)
//!
//! On-chain regulatory reporting with:
//!   - Customizable report templates (e.g. FATF, MiCA, FINCEN, GDPR)
//!   - Transaction reporting for financial regulators
//!   - Suspicious Activity Report (SAR) generation
//!   - Report scheduling and automation
//!   - Structured data for off-chain export (PDF, CSV, JSON)
//!   - Immutable audit trail integration

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Map, Symbol, Vec,
};

use crate::{clamp_page_size, PaginatedAddresses};

// ── Constants ─────────────────────────────────────────────────────────────────

const REPORTING_TTL_LEDGERS: u32 = 6_307_200;
const MAX_TEMPLATE_SECTIONS: u32 = 20;
const MAX_SCHEDULED_REPORTS: u32 = 50;
const MAX_REPORT_FIELDS: u32 = 30;
const MAX_TAG_COUNT: u32 = 10;

// ── Storage keys ──────────────────────────────────────────────────────────────

const KEY_ADMIN: &str = "admin";
const KEY_TEMPLATE_COUNT: &str = "tpl_count";
const KEY_REPORT_COUNT: &str = "rpt_count";
const KEY_SAR_COUNT: &str = "sar_count";

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum RegulatoryReportingError {
    /// Caller is not authorized for this operation.
    Unauthorized = 1,
    /// Requested resource was not found.
    NotFound = 2,
    /// Input argument is empty or structurally invalid.
    InvalidInput = 3,
    /// Contract has not been initialized.
    NotInitialized = 4,
    /// Contract is already initialized.
    AlreadyInitialized = 5,
    /// Resource already exists (e.g. duplicate template ID).
    AlreadyExists = 6,
    /// Template has too many sections.
    TemplateTooLarge = 7,
    /// Scheduled report count exceeds maximum.
    TooManySchedules = 8,
    /// Invalid schedule configuration (e.g. bad cron expression).
    InvalidSchedule = 9,
    /// Report generation failed.
    GenerationFailed = 10,
    /// Export format not supported.
    UnsupportedFormat = 11,
}

// ── Storage key enum ──────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum RrKey {
    /// Report template keyed by template ID string.
    Template(Bytes),
    /// Index of all template IDs.
    TemplateIndex,
    /// Generated regulatory report keyed by (subject address, timestamp).
    Report(Address, u64),
    /// Report index for a subject.
    ReportIndex(Address),
    /// SAR report keyed by SAR ID.
    SAR(Bytes),
    /// SAR index (global list of SAR IDs).
    SARIndex,
    /// Scheduled report configuration keyed by schedule ID.
    Schedule(Bytes),
    /// Schedule index (global list of schedule IDs).
    ScheduleIndex,
    /// Audit trail export snapshot keyed by (subject, timestamp).
    ExportSnapshot(Address, u64),
    /// Export snapshot index for a subject.
    ExportIndex(Address),
}

// ── Data structures ───────────────────────────────────────────────────────────

/// A section within a report template.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateSection {
    /// Section title (e.g. "Transaction Summary", "Risk Assessment")
    pub title: Bytes,
    /// Section description / instructions
    pub description: Bytes,
    /// Field names for this section
    pub fields: Vec<Bytes>,
    /// Whether this section is required
    pub required: bool,
    /// Sort order within the template
    pub order: u32,
}

/// A regulatory report template.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportTemplate {
    /// Unique template ID (e.g. "FATF_TRAVEL_RULE", "MICA_QUARTERLY")
    pub id: Bytes,
    /// Human-readable template name
    pub name: Bytes,
    /// Regulatory jurisdiction (e.g. "FATF", "MiCA", "FINCEN", "GDPR")
    pub jurisdiction: Bytes,
    /// Template version for schema evolution
    pub version: u32,
    /// Sections within the template
    pub sections: Vec<TemplateSection>,
    /// Template-level tags for categorization
    pub tags: Vec<Bytes>,
    /// Whether the template is active
    pub active: bool,
    /// Creation timestamp
    pub created: u64,
    /// Last update timestamp
    pub updated: u64,
}

/// A field value within a generated report section.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportField {
    /// Field name matching a template section field
    pub name: Bytes,
    /// Field value (stringified)
    pub value: Bytes,
}

/// A populated section within a generated report.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportSection {
    /// Section title from the template
    pub title: Bytes,
    /// Populated field values
    pub fields: Vec<ReportField>,
}

/// A generated regulatory report.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegulatoryReport {
    /// Report ID (template_id:subject:timestamp)
    pub id: Bytes,
    /// Template ID used to generate this report
    pub template_id: Bytes,
    /// Subject address the report is about
    pub subject: Address,
    /// Reporter address who generated the report
    pub reporter: Address,
    /// Populated sections
    pub sections: Vec<ReportSection>,
    /// Overall risk assessment (0-100) if applicable
    pub risk_score: u32,
    /// Report status
    pub status: Bytes,
    /// Generation timestamp
    pub generated_at: u64,
    /// Ledger sequence at generation time
    pub ledger_sequence: u32,
    /// Arbitrary metadata tags
    pub tags: Vec<Bytes>,
}

/// Suspicious Activity Report (SAR).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SARReport {
    /// Unique SAR ID
    pub id: Bytes,
    /// Subject of the suspicious activity
    pub subject: Address,
    /// Filing entity / reporter
    pub filer: Address,
    /// Type of suspicious activity
    pub activity_type: Bytes,
    /// Detailed description of suspicious activity
    pub description: Bytes,
    /// Related transaction hashes
    pub related_transactions: Vec<Bytes>,
    /// Estimated value involved
    pub estimated_value: Bytes,
    /// Currency / asset
    pub currency: Bytes,
    /// SAR status: draft, filed, acknowledged, closed
    pub status: Bytes,
    /// Regulatory bodies to be notified
    pub notify_regulators: Vec<Bytes>,
    /// Evidence / supporting document hashes
    pub evidence_hashes: Vec<BytesN<32>>,
    /// Filing timestamp
    pub filed_at: u64,
    /// When the suspicious activity was detected
    pub activity_timestamp: u64,
    /// Ledger sequence
    pub ledger_sequence: u32,
}

/// Schedule configuration for automated report generation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportSchedule {
    /// Unique schedule ID
    pub id: Bytes,
    /// Template ID to use for generation
    pub template_id: Bytes,
    /// Subject address (or wildcard for batch)
    pub subject: Option<Address>,
    /// Schedule interval in seconds (e.g. 86400 = daily)
    pub interval_seconds: u64,
    /// Next scheduled generation timestamp
    pub next_run_at: u64,
    /// Last successful run timestamp
    pub last_run_at: Option<u64>,
    /// Export formats requested
    pub export_formats: Vec<Bytes>,
    /// Whether the schedule is active
    pub active: bool,
    /// Creator address
    pub created_by: Address,
    /// Creation timestamp
    pub created_at: u64,
}

/// Audit trail export snapshot.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportSnapshot {
    /// Subject address
    pub subject: Address,
    /// Snapshot timestamp
    pub snapshot_at: u64,
    /// Export format (pdf, csv, json)
    pub format: Bytes,
    /// Content hash for integrity verification
    pub content_hash: BytesN<32>,
    /// Number of audit entries in this snapshot
    pub entry_count: u32,
    /// Ledger sequence
    pub ledger_sequence: u32,
}

/// Paginated report list.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedReports {
    pub data: Vec<RegulatoryReport>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

/// Paginated SAR list.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedSARs {
    pub data: Vec<SARReport>,
    pub page: u32,
    pub total: u32,
    pub has_more: bool,
}

/// Transaction report data for financial regulators.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionReport {
    /// Unique report ID
    pub id: Bytes,
    /// Subject address
    pub subject: Address,
    /// Total number of transactions in period
    pub transaction_count: u32,
    /// Total volume in smallest unit
    pub total_volume: u64,
    /// Report period start timestamp
    pub period_start: u64,
    /// Report period end timestamp
    pub period_end: u64,
    /// Currency/asset this report covers
    pub asset: Bytes,
    /// Average transaction size
    pub avg_transaction_size: u64,
    /// Largest transaction in period
    pub max_transaction_size: u64,
    /// Number of transactions flagged as suspicious
    pub suspicious_count: u32,
    /// Whether this exceeds any reporting thresholds
    pub exceeds_threshold: bool,
    /// Generation timestamp
    pub generated_at: u64,
    /// Ledger sequence
    pub ledger_sequence: u32,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct RegulatoryReporting;

#[contractimpl]
impl RegulatoryReporting {
    // ── Initialization ────────────────────────────────────────────────────────

    /// Initialize the contract with a designated admin.
    pub fn initialize(env: Env, admin: Address) -> Result<(), RegulatoryReportingError> {
        if env
            .storage()
            .instance()
            .has(&Symbol::new(&env, KEY_ADMIN))
        {
            return Err(RegulatoryReportingError::AlreadyInitialized);
        }
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_ADMIN), &admin);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_TEMPLATE_COUNT), &0u32);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_REPORT_COUNT), &0u32);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_SAR_COUNT), &0u32);
        Ok(())
    }

    // ── Admin management ──────────────────────────────────────────────────────

    /// Transfer admin rights.
    pub fn transfer_admin(
        env: Env,
        caller: Address,
        new_admin: Address,
    ) -> Result<(), RegulatoryReportingError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(RegulatoryReportingError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_ADMIN), &new_admin);
        env.events().publish(
            (Symbol::new(&env, "rr_admin_xfer"), admin),
            new_admin,
        );
        Ok(())
    }

    // ── Report template management ────────────────────────────────────────────

    /// Register a new report template. Admin only.
    pub fn register_template(
        env: Env,
        admin: Address,
        id: Bytes,
        name: Bytes,
        jurisdiction: Bytes,
        sections: Vec<TemplateSection>,
        tags: Vec<Bytes>,
    ) -> Result<(), RegulatoryReportingError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if id.is_empty() || name.is_empty() || jurisdiction.is_empty() {
            return Err(RegulatoryReportingError::InvalidInput);
        }
        if sections.len() > MAX_TEMPLATE_SECTIONS {
            return Err(RegulatoryReportingError::TemplateTooLarge);
        }
        if tags.len() > MAX_TAG_COUNT {
            return Err(RegulatoryReportingError::InvalidInput);
        }

        let key = RrKey::Template(id.clone());
        if env.storage().persistent().has(&key) {
            return Err(RegulatoryReportingError::AlreadyExists);
        }

        let ts = env.ledger().timestamp();
        let template = ReportTemplate {
            id: id.clone(),
            name,
            jurisdiction,
            version: 1,
            sections,
            tags,
            active: true,
            created: ts,
            updated: ts,
        };

        Self::persist(&env, &key, &template);

        // Update template index
        let mut tpl_idx: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&RrKey::TemplateIndex)
            .unwrap_or_else(|| Vec::new(&env));
        if !tpl_idx.iter().any(|existing| existing == id) {
            tpl_idx.push_back(id.clone());
            Self::persist(&env, &RrKey::TemplateIndex, &tpl_idx);
        }

        let count: u32 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, KEY_TEMPLATE_COUNT))
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_TEMPLATE_COUNT), &(count + 1));

        env.events()
            .publish((Symbol::new(&env, "template_registered"),), id);
        Ok(())
    }

    /// Update an existing template. Creates a new version.
    pub fn update_template(
        env: Env,
        admin: Address,
        id: Bytes,
        name: Bytes,
        jurisdiction: Bytes,
        sections: Vec<TemplateSection>,
        tags: Vec<Bytes>,
    ) -> Result<(), RegulatoryReportingError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        if sections.len() > MAX_TEMPLATE_SECTIONS {
            return Err(RegulatoryReportingError::TemplateTooLarge);
        }

        let key = RrKey::Template(id.clone());
        let mut template: ReportTemplate = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(RegulatoryReportingError::NotFound)?;

        template.name = name;
        template.jurisdiction = jurisdiction;
        template.version += 1;
        template.sections = sections;
        template.tags = tags;
        template.updated = env.ledger().timestamp();

        Self::persist(&env, &key, &template);

        env.events()
            .publish((Symbol::new(&env, "template_updated"),), id);
        Ok(())
    }

    /// Deactivate a template without deleting it.
    pub fn deactivate_template(
        env: Env,
        admin: Address,
        id: Bytes,
    ) -> Result<(), RegulatoryReportingError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        let key = RrKey::Template(id.clone());
        let mut template: ReportTemplate = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(RegulatoryReportingError::NotFound)?;
        template.active = false;
        template.updated = env.ledger().timestamp();
        Self::persist(&env, &key, &template);
        Ok(())
    }

    /// Get a template by ID.
    pub fn get_template(env: Env, id: Bytes) -> Option<ReportTemplate> {
        env.storage().persistent().get(&RrKey::Template(id))
    }

    /// List all template IDs.
    pub fn get_all_template_ids(env: Env) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&RrKey::TemplateIndex)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ── Report generation ─────────────────────────────────────────────────────

    /// Generate a regulatory report using a template for a subject.
    pub fn generate_report(
        env: Env,
        reporter: Address,
        template_id: Bytes,
        subject: Address,
        sections: Vec<ReportSection>,
        risk_score: u32,
        tags: Vec<Bytes>,
    ) -> Result<Bytes, RegulatoryReportingError> {
        reporter.require_auth();

        // Validate template exists and is active
        let template: ReportTemplate = env
            .storage()
            .persistent()
            .get(&RrKey::Template(template_id.clone()))
            .ok_or(RegulatoryReportingError::NotFound)?;
        if !template.active {
            return Err(RegulatoryReportingError::NotFound);
        }
        if risk_score > 100 {
            return Err(RegulatoryReportingError::InvalidInput);
        }

        let ts = env.ledger().timestamp();
        let id = Self::make_report_id(&env, &template_id, &subject, ts);

        let report = RegulatoryReport {
            id: id.clone(),
            template_id: template_id.clone(),
            subject: subject.clone(),
            reporter,
            sections,
            risk_score,
            status: Bytes::from_slice(&env, b"generated"),
            generated_at: ts,
            ledger_sequence: env.ledger().sequence(),
            tags,
        };

        let rk = RrKey::Report(subject.clone(), ts);
        Self::persist(&env, &rk, &report);

        // Update report index for the subject
        let mut idx: Vec<u64> = env
            .storage()
            .persistent()
            .get(&RrKey::ReportIndex(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        idx.push_back(ts);
        env.storage()
            .persistent()
            .set(&RrKey::ReportIndex(subject.clone()), &idx);

        let count: u32 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, KEY_REPORT_COUNT))
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_REPORT_COUNT), &(count + 1));

        env.events().publish(
            (Symbol::new(&env, "report_generated"), subject, template_id),
            ts,
        );
        Ok(id)
    }

    /// Get a report by subject and timestamp.
    pub fn get_report(
        env: Env,
        subject: Address,
        timestamp: u64,
    ) -> Option<RegulatoryReport> {
        env.storage()
            .persistent()
            .get(&RrKey::Report(subject, timestamp))
    }

    /// Get all report timestamps for a subject.
    pub fn get_report_index(env: Env, subject: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&RrKey::ReportIndex(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get paginated reports for a subject.
    pub fn get_reports_paginated(
        env: Env,
        subject: Address,
        page: u32,
        page_size: u32,
    ) -> PaginatedReports {
        let timestamps: Vec<u64> = env
            .storage()
            .persistent()
            .get(&RrKey::ReportIndex(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = timestamps.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(ts) = timestamps.get(i) {
                    if let Some(report) = env
                        .storage()
                        .persistent()
                        .get(&RrKey::Report(subject.clone(), ts))
                    {
                        data.push_back(report);
                    }
                }
            }
        }

        PaginatedReports {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }

    // ── Transaction reporting ─────────────────────────────────────────────────

    /// File a transaction report for financial regulators.
    pub fn file_transaction_report(
        env: Env,
        reporter: Address,
        subject: Address,
        transaction_count: u32,
        total_volume: u64,
        period_start: u64,
        period_end: u64,
        asset: Bytes,
        avg_transaction_size: u64,
        max_transaction_size: u64,
        suspicious_count: u32,
    ) -> Result<Bytes, RegulatoryReportingError> {
        reporter.require_auth();

        if period_end <= period_start {
            return Err(RegulatoryReportingError::InvalidInput);
        }
        if asset.is_empty() {
            return Err(RegulatoryReportingError::InvalidInput);
        }

        let ts = env.ledger().timestamp();
        let id = Self::make_report_id(&env, &Bytes::from_slice(&env, b"TXN_RPT"), &subject, ts);

        let exceeds = total_volume >= 10_000_000_000; // 10k USD equivalent threshold
        let report = TransactionReport {
            id: id.clone(),
            subject: subject.clone(),
            transaction_count,
            total_volume,
            period_start,
            period_end,
            asset,
            avg_transaction_size,
            max_transaction_size,
            suspicious_count,
            exceeds_threshold: exceeds,
            generated_at: ts,
            ledger_sequence: env.ledger().sequence(),
        };

        // Store as a tagged regulatory report via sections for unified retrieval
        let mut sections = Vec::new(&env);
        let mut section_fields = Vec::new(&env);
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"transaction_count"),
            value: Bytes::from_slice(&env, &Self::u32_to_bytes(transaction_count)),
        });
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"total_volume"),
            value: Bytes::from_slice(&env, &Self::u64_to_bytes(total_volume)),
        });
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"period_start"),
            value: Bytes::from_slice(&env, &Self::u64_to_bytes(period_start)),
        });
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"period_end"),
            value: Bytes::from_slice(&env, &Self::u64_to_bytes(period_end)),
        });
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"asset"),
            value: asset.clone(),
        });
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"avg_transaction_size"),
            value: Bytes::from_slice(&env, &Self::u64_to_bytes(avg_transaction_size)),
        });
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"max_transaction_size"),
            value: Bytes::from_slice(&env, &Self::u64_to_bytes(max_transaction_size)),
        });
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"suspicious_count"),
            value: Bytes::from_slice(&env, &Self::u32_to_bytes(suspicious_count)),
        });
        section_fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"exceeds_threshold"),
            value: Bytes::from_slice(&env, if exceeds { b"true" } else { b"false" }),
        });
        sections.push_back(ReportSection {
            title: Bytes::from_slice(&env, b"Transaction Report"),
            fields: section_fields,
        });

        let rk = RrKey::Report(subject.clone(), ts);
        let report_data = RegulatoryReport {
            id: id.clone(),
            template_id: Bytes::from_slice(&env, b"TXN_RPT"),
            subject: subject.clone(),
            reporter,
            sections,
            risk_score: if exceeds { 70 } else { 30 },
            status: Bytes::from_slice(&env, b"generated"),
            generated_at: ts,
            ledger_sequence: env.ledger().sequence(),
            tags: Vec::from_array(
                &env,
                [
                    Bytes::from_slice(&env, b"transaction_report"),
                    Bytes::from_slice(&env, b"financial_regulator"),
                ],
            ),
        };
        Self::persist(&env, &rk, &report_data);

        // Update index
        let mut idx: Vec<u64> = env
            .storage()
            .persistent()
            .get(&RrKey::ReportIndex(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        idx.push_back(ts);
        env.storage()
            .persistent()
            .set(&RrKey::ReportIndex(subject), &idx);

        env.events().publish(
            (Symbol::new(&env, "txn_report_filed"), subject),
            ts,
        );
        Ok(id)
    }

    // ── SAR (Suspicious Activity Report) ──────────────────────────────────────

    /// File a Suspicious Activity Report (SAR).
    pub fn file_sar(
        env: Env,
        filer: Address,
        subject: Address,
        activity_type: Bytes,
        description: Bytes,
        related_transactions: Vec<Bytes>,
        estimated_value: Bytes,
        currency: Bytes,
        notify_regulators: Vec<Bytes>,
        evidence_hashes: Vec<BytesN<32>>,
        activity_timestamp: u64,
    ) -> Result<Bytes, RegulatoryReportingError> {
        filer.require_auth();

        if activity_type.is_empty() || description.is_empty() {
            return Err(RegulatoryReportingError::InvalidInput);
        }

        let ts = env.ledger().timestamp();
        // SAR ID: SAR:<subject>:<timestamp>
        let mut id_bytes = Bytes::from_slice(&env, b"SAR:");
        id_bytes.append(&Bytes::from_slice(&env, &Self::address_to_bytes(&subject)));
        id_bytes.append(&Bytes::from_slice(&env, b":"));
        id_bytes.append(&Bytes::from_slice(&env, &Self::u64_to_bytes(ts)));
        let id: Bytes = id_bytes;

        let sar = SARReport {
            id: id.clone(),
            subject: subject.clone(),
            filer,
            activity_type,
            description,
            related_transactions,
            estimated_value,
            currency,
            status: Bytes::from_slice(&env, b"filed"),
            notify_regulators,
            evidence_hashes,
            filed_at: ts,
            activity_timestamp,
            ledger_sequence: env.ledger().sequence(),
        };

        let sk = RrKey::SAR(id.clone());
        Self::persist(&env, &sk, &sar);

        // Update SAR index
        let mut sar_idx: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&RrKey::SARIndex)
            .unwrap_or_else(|| Vec::new(&env));
        sar_idx.push_back(id.clone());
        env.storage()
            .persistent()
            .set(&RrKey::SARIndex, &sar_idx);

        let count: u32 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, KEY_SAR_COUNT))
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&Symbol::new(&env, KEY_SAR_COUNT), &(count + 1));

        env.events()
            .publish((Symbol::new(&env, "sar_filed"), subject), id);
        Ok(id)
    }

    /// Get a SAR by ID.
    pub fn get_sar(env: Env, sar_id: Bytes) -> Option<SARReport> {
        env.storage().persistent().get(&RrKey::SAR(sar_id))
    }

    /// Update SAR status (e.g. acknowledged, closed).
    pub fn update_sar_status(
        env: Env,
        admin: Address,
        sar_id: Bytes,
        new_status: Bytes,
    ) -> Result<(), RegulatoryReportingError> {
        admin.require_auth();
        Self::assert_admin(&env, &admin)?;

        let sk = RrKey::SAR(sar_id.clone());
        let mut sar: SARReport = env
            .storage()
            .persistent()
            .get(&sk)
            .ok_or(RegulatoryReportingError::NotFound)?;

        sar.status = new_status;
        Self::persist(&env, &sk, &sar);

        env.events()
            .publish((Symbol::new(&env, "sar_updated"),), sar_id);
        Ok(())
    }

    /// Get all SAR IDs.
    pub fn get_all_sar_ids(env: Env) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&RrKey::SARIndex)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get paginated SARs.
    pub fn get_sars_paginated(
        env: Env,
        page: u32,
        page_size: u32,
    ) -> PaginatedSARs {
        let all_ids: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&RrKey::SARIndex)
            .unwrap_or_else(|| Vec::new(&env));

        let size = clamp_page_size(page_size);
        let total = all_ids.len() as u32;
        let start = page * size;
        let mut data = Vec::new(&env);

        if start < total {
            let end = core::cmp::min(start + size, total);
            for i in start..end {
                if let Some(id) = all_ids.get(i) {
                    if let Some(sar) = env
                        .storage()
                        .persistent()
                        .get(&RrKey::SAR(id))
                    {
                        data.push_back(sar);
                    }
                }
            }
        }

        PaginatedSARs {
            data,
            page,
            total,
            has_more: (start + size) < total,
        }
    }

    // ── Report scheduling ─────────────────────────────────────────────────────

    /// Register a scheduled report for automated generation.
    pub fn schedule_report(
        env: Env,
        creator: Address,
        schedule_id: Bytes,
        template_id: Bytes,
        subject: Option<Address>,
        interval_seconds: u64,
        export_formats: Vec<Bytes>,
    ) -> Result<(), RegulatoryReportingError> {
        creator.require_auth();

        if schedule_id.is_empty() || template_id.is_empty() || interval_seconds == 0 {
            return Err(RegulatoryReportingError::InvalidInput);
        }
        if interval_seconds < 60 {
            return Err(RegulatoryReportingError::InvalidSchedule);
        }

        let sk = RrKey::Schedule(schedule_id.clone());
        if env.storage().persistent().has(&sk) {
            return Err(RegulatoryReportingError::AlreadyExists);
        }

        let schedule = ReportSchedule {
            id: schedule_id.clone(),
            template_id,
            subject,
            interval_seconds,
            next_run_at: env.ledger().timestamp(),
            last_run_at: None,
            export_formats,
            active: true,
            created_by: creator,
            created_at: env.ledger().timestamp(),
        };

        Self::persist(&env, &sk, &schedule);

        // Update schedule index
        let mut sched_idx: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&RrKey::ScheduleIndex)
            .unwrap_or_else(|| Vec::new(&env));
        sched_idx.push_back(schedule_id);
        env.storage()
            .persistent()
            .set(&RrKey::ScheduleIndex, &sched_idx);

        env.events()
            .publish((Symbol::new(&env, "report_scheduled"),), schedule_id);
        Ok(())
    }

    /// Deactivate a scheduled report.
    pub fn cancel_schedule(
        env: Env,
        caller: Address,
        schedule_id: Bytes,
    ) -> Result<(), RegulatoryReportingError> {
        caller.require_auth();

        let sk = RrKey::Schedule(schedule_id.clone());
        let mut schedule: ReportSchedule = env
            .storage()
            .persistent()
            .get(&sk)
            .ok_or(RegulatoryReportingError::NotFound)?;

        if caller != schedule.created_by {
            // Allow admin to cancel any schedule
            let admin = Self::require_admin(&env)?;
            if caller != admin {
                return Err(RegulatoryReportingError::Unauthorized);
            }
        }

        schedule.active = false;
        Self::persist(&env, &sk, &schedule);
        Ok(())
    }

    /// Get a schedule by ID.
    pub fn get_schedule(env: Env, schedule_id: Bytes) -> Option<ReportSchedule> {
        env.storage()
            .persistent()
            .get(&RrKey::Schedule(schedule_id))
    }

    /// Get all schedule IDs.
    pub fn get_all_schedule_ids(env: Env) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&RrKey::ScheduleIndex)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Mark a scheduled report as having run. Called after off-chain execution.
    pub fn mark_schedule_run(
        env: Env,
        caller: Address,
        schedule_id: Bytes,
    ) -> Result<(), RegulatoryReportingError> {
        caller.require_auth();

        let sk = RrKey::Schedule(schedule_id.clone());
        let mut schedule: ReportSchedule = env
            .storage()
            .persistent()
            .get(&sk)
            .ok_or(RegulatoryReportingError::NotFound)?;

        schedule.last_run_at = Some(env.ledger().timestamp());
        schedule.next_run_at = env.ledger().timestamp() + schedule.interval_seconds;
        Self::persist(&env, &sk, &schedule);
        Ok(())
    }

    // ── Export snapshots ──────────────────────────────────────────────────────

    /// Record an export snapshot hash for integrity verification.
    pub fn record_export_snapshot(
        env: Env,
        reporter: Address,
        subject: Address,
        format: Bytes,
        content_hash: BytesN<32>,
        entry_count: u32,
    ) -> Result<u64, RegulatoryReportingError> {
        reporter.require_auth();

        if format.is_empty() {
            return Err(RegulatoryReportingError::InvalidInput);
        }

        let ts = env.ledger().timestamp();
        let snapshot = ExportSnapshot {
            subject: subject.clone(),
            snapshot_at: ts,
            format,
            content_hash,
            entry_count,
            ledger_sequence: env.ledger().sequence(),
        };

        let ek = RrKey::ExportSnapshot(subject.clone(), ts);
        Self::persist(&env, &ek, &snapshot);

        // Update export index
        let mut idx: Vec<u64> = env
            .storage()
            .persistent()
            .get(&RrKey::ExportIndex(subject.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        idx.push_back(ts);
        env.storage()
            .persistent()
            .set(&RrKey::ExportIndex(subject), &idx);

        env.events()
            .publish((Symbol::new(&env, "export_recorded"), subject), ts);
        Ok(ts)
    }

    /// Get export snapshots for a subject.
    pub fn get_export_snapshots(env: Env, subject: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&RrKey::ExportIndex(subject))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get a specific export snapshot.
    pub fn get_export_snapshot(
        env: Env,
        subject: Address,
        timestamp: u64,
    ) -> Option<ExportSnapshot> {
        env.storage()
            .persistent()
            .get(&RrKey::ExportSnapshot(subject, timestamp))
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Get total counts.
    pub fn get_statistics(env: Env) -> Map<Bytes, u32> {
        let mut stats = Map::new(&env);
        let template_count: u32 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, KEY_TEMPLATE_COUNT))
            .unwrap_or(0);
        let report_count: u32 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, KEY_REPORT_COUNT))
            .unwrap_or(0);
        let sar_count: u32 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, KEY_SAR_COUNT))
            .unwrap_or(0);
        stats.set(Bytes::from_slice(&env, b"templates"), template_count);
        stats.set(Bytes::from_slice(&env, b"reports"), report_count);
        stats.set(Bytes::from_slice(&env, b"sars"), sar_count);
        stats
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<Address, RegulatoryReportingError> {
        env.storage()
            .instance()
            .get::<Symbol, Address>(&Symbol::new(env, KEY_ADMIN))
            .ok_or(RegulatoryReportingError::NotInitialized)
    }

    fn assert_admin(env: &Env, caller: &Address) -> Result<(), RegulatoryReportingError> {
        let admin = Self::require_admin(env)?;
        if *caller != admin {
            return Err(RegulatoryReportingError::Unauthorized);
        }
        Ok(())
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
            .extend_ttl(key, REPORTING_TTL_LEDGERS, REPORTING_TTL_LEDGERS);
    }

    fn make_report_id(env: &Env, template_id: &Bytes, subject: &Address, ts: u64) -> Bytes {
        let mut id = Bytes::from_slice(env, b"RPT:");
        id.append(template_id);
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(env, &Self::address_to_bytes(subject)));
        id.append(&Bytes::from_slice(env, b":"));
        id.append(&Bytes::from_slice(env, &Self::u64_to_bytes(ts)));
        id
    }

    fn u32_to_bytes(v: u32) -> [u8; 4] { v.to_be_bytes() }

    fn u64_to_bytes(v: u64) -> [u8; 8] { v.to_be_bytes() }

    fn address_to_bytes(addr: &Address) -> [u8; 32] {
        let s = addr.to_string();
        let mut buf = [0u8; 32];
        let bytes = s.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{Address, Bytes, BytesN, Env};

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
        RegulatoryReporting::initialize(env.clone(), admin.clone()).unwrap();
        admin
    }

    fn make_section(env: &Env, title: &str, fields: &[&str]) -> TemplateSection {
        let mut f = Vec::new(env);
        for field in fields {
            f.push_back(Bytes::from_slice(env, field.as_bytes()));
        }
        TemplateSection {
            title: Bytes::from_slice(env, title.as_bytes()),
            description: Bytes::from_slice(env, b"Test section"),
            fields: f,
            required: true,
            order: 0,
        }
    }

    // ── Initialization ────────────────────────────────────────────────────────

    #[test]
    fn initializes_successfully() {
        let env = setup_env();
        let admin = Address::generate(&env);
        assert!(RegulatoryReporting::initialize(env.clone(), admin).is_ok());
    }

    #[test]
    fn double_initialize_returns_error() {
        let env = setup_env();
        bootstrap(&env);
        let result = RegulatoryReporting::initialize(env.clone(), Address::generate(&env));
        assert_eq!(result.unwrap_err(), RegulatoryReportingError::AlreadyInitialized);
    }

    // ── Template management ───────────────────────────────────────────────────

    #[test]
    fn register_and_retrieve_template() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let id = Bytes::from_slice(&env, b"FATF_TRAVEL_RULE");
        let mut sections = Vec::new(&env);
        sections.push_back(make_section(&env, "Transfer Details", &["amount", "asset", "timestamp"]));

        RegulatoryReporting::register_template(
            env.clone(),
            admin,
            id.clone(),
            Bytes::from_slice(&env, b"FATF Travel Rule Report"),
            Bytes::from_slice(&env, b"FATF"),
            sections,
            Vec::from_array(&env, [Bytes::from_slice(&env, b"travel_rule")]),
        )
        .unwrap();

        let tpl = RegulatoryReporting::get_template(env.clone(), id).unwrap();
        assert!(tpl.active);
        assert_eq!(tpl.version, 1);
        assert_eq!(tpl.jurisdiction, Bytes::from_slice(&env, b"FATF"));
    }

    #[test]
    fn duplicate_template_registration_fails() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let id = Bytes::from_slice(&env, b"DUPE");
        let sections = Vec::new(&env);
        RegulatoryReporting::register_template(
            env.clone(),
            admin.clone(),
            id.clone(),
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"EU"),
            sections.clone(),
            Vec::new(&env),
        )
        .unwrap();

        let result = RegulatoryReporting::register_template(
            env.clone(),
            admin,
            id,
            Bytes::from_slice(&env, b"test2"),
            Bytes::from_slice(&env, b"EU"),
            sections,
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), RegulatoryReportingError::AlreadyExists);
    }

    #[test]
    fn deactivate_template() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let id = Bytes::from_slice(&env, b"TO_DEACTIVATE");
        let sections = Vec::new(&env);
        RegulatoryReporting::register_template(
            env.clone(),
            admin.clone(),
            id.clone(),
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"EU"),
            sections,
            Vec::new(&env),
        )
        .unwrap();

        RegulatoryReporting::deactivate_template(env.clone(), admin, id.clone()).unwrap();
        let tpl = RegulatoryReporting::get_template(env, id).unwrap();
        assert!(!tpl.active);
    }

    #[test]
    fn update_template_increments_version() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let id = Bytes::from_slice(&env, b"UPDATE_TEST");
        let sections = Vec::new(&env);
        RegulatoryReporting::register_template(
            env.clone(),
            admin.clone(),
            id.clone(),
            Bytes::from_slice(&env, b"old"),
            Bytes::from_slice(&env, b"EU"),
            sections,
            Vec::new(&env),
        )
        .unwrap();

        let mut new_sections = Vec::new(&env);
        new_sections.push_back(make_section(&env, "New Section", &["field1"]));

        RegulatoryReporting::update_template(
            env.clone(),
            admin,
            id.clone(),
            Bytes::from_slice(&env, b"new name"),
            Bytes::from_slice(&env, b"US"),
            new_sections,
            Vec::new(&env),
        )
        .unwrap();

        let tpl = RegulatoryReporting::get_template(env, id).unwrap();
        assert_eq!(tpl.version, 2);
        assert_eq!(tpl.name, Bytes::from_slice(&env, b"new name"));
    }

    // ── Report generation ─────────────────────────────────────────────────────

    #[test]
    fn generate_and_retrieve_report() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);

        let tpl_id = Bytes::from_slice(&env, b"FATF_TRAVEL_RULE");
        let mut sections = Vec::new(&env);
        sections.push_back(make_section(&env, "Transfer Details", &["amount", "asset"]));
        RegulatoryReporting::register_template(
            env.clone(),
            admin,
            tpl_id.clone(),
            Bytes::from_slice(&env, b"FATF Travel Rule"),
            Bytes::from_slice(&env, b"FATF"),
            sections,
            Vec::new(&env),
        )
        .unwrap();

        let mut report_sections = Vec::new(&env);
        let mut fields = Vec::new(&env);
        fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"amount"),
            value: Bytes::from_slice(&env, b"5000"),
        });
        fields.push_back(ReportField {
            name: Bytes::from_slice(&env, b"asset"),
            value: Bytes::from_slice(&env, b"USDC"),
        });
        report_sections.push_back(ReportSection {
            title: Bytes::from_slice(&env, b"Transfer Details"),
            fields,
        });

        let ts = env.ledger().timestamp();
        let report_id = RegulatoryReporting::generate_report(
            env.clone(),
            reporter.clone(),
            tpl_id.clone(),
            subject.clone(),
            report_sections,
            50,
            Vec::new(&env),
        )
        .unwrap();

        assert!(!report_id.is_empty());

        let report = RegulatoryReporting::get_report(env.clone(), subject.clone(), ts);
        assert!(report.is_some());
        assert_eq!(report.unwrap().risk_score, 50);
    }

    #[test]
    fn generate_report_with_inactive_template_fails() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let tpl_id = Bytes::from_slice(&env, b"INACTIVE");
        let sections = Vec::new(&env);
        RegulatoryReporting::register_template(
            env.clone(),
            admin.clone(),
            tpl_id.clone(),
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"EU"),
            sections,
            Vec::new(&env),
        )
        .unwrap();
        RegulatoryReporting::deactivate_template(env.clone(), admin, tpl_id.clone()).unwrap();

        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);
        let result = RegulatoryReporting::generate_report(
            env.clone(),
            reporter,
            tpl_id,
            subject,
            Vec::new(&env),
            0,
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), RegulatoryReportingError::NotFound);
    }

    #[test]
    fn report_index_is_maintained() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);

        let tpl_id = Bytes::from_slice(&env, b"FATF_TRAVEL_RULE");
        let sections = Vec::new(&env);
        RegulatoryReporting::register_template(
            env.clone(),
            admin,
            tpl_id.clone(),
            Bytes::from_slice(&env, b"FATF"),
            Bytes::from_slice(&env, b"FATF"),
            sections,
            Vec::new(&env),
        )
        .unwrap();

        RegulatoryReporting::generate_report(
            env.clone(),
            reporter.clone(),
            tpl_id,
            subject.clone(),
            Vec::new(&env),
            30,
            Vec::new(&env),
        )
        .unwrap();

        let idx = RegulatoryReporting::get_report_index(env.clone(), subject);
        assert_eq!(idx.len(), 1);
    }

    // ── Transaction reporting ─────────────────────────────────────────────────

    #[test]
    fn file_transaction_report_success() {
        let env = setup_env();
        bootstrap(&env);
        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);

        let id = RegulatoryReporting::file_transaction_report(
            env.clone(),
            reporter,
            subject.clone(),
            150,         // tx count
            5_000_000,   // volume
            1_700_000_000,
            1_700_100_000,
            Bytes::from_slice(&env, b"USDC"),
            33_333,
            500_000,
            2,
        )
        .unwrap();

        assert!(!id.is_empty());
        let idx = RegulatoryReporting::get_report_index(env, subject);
        assert!(!idx.is_empty());
    }

    #[test]
    fn transaction_report_rejects_invalid_period() {
        let env = setup_env();
        bootstrap(&env);
        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);

        let result = RegulatoryReporting::file_transaction_report(
            env.clone(),
            reporter,
            subject,
            10,
            1000,
            1_700_100_000,
            1_700_000_000, // end before start
            Bytes::from_slice(&env, b"USDC"),
            100,
            500,
            0,
        );
        assert_eq!(result.unwrap_err(), RegulatoryReportingError::InvalidInput);
    }

    // ── SAR ───────────────────────────────────────────────────────────────────

    #[test]
    fn file_and_retrieve_sar() {
        let env = setup_env();
        bootstrap(&env);
        let filer = Address::generate(&env);
        let subject = Address::generate(&env);

        let sar_id = RegulatoryReporting::file_sar(
            env.clone(),
            filer,
            subject.clone(),
            Bytes::from_slice(&env, b"structuring"),
            Bytes::from_slice(&env, b"Multiple deposits just below $10,000 threshold"),
            Vec::from_array(&env, [Bytes::from_slice(&env, b"tx_hash_1")]),
            Bytes::from_slice(&env, b"95000"),
            Bytes::from_slice(&env, b"USD"),
            Vec::from_array(&env, [Bytes::from_slice(&env, b"FINCEN")]),
            Vec::new(&env),
            1_699_000_000,
        )
        .unwrap();

        assert!(!sar_id.is_empty());

        let sar = RegulatoryReporting::get_sar(env.clone(), sar_id.clone()).unwrap();
        assert_eq!(sar.activity_type, Bytes::from_slice(&env, b"structuring"));
        assert_eq!(sar.status, Bytes::from_slice(&env, b"filed"));
    }

    #[test]
    fn update_sar_status() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let filer = Address::generate(&env);
        let subject = Address::generate(&env);

        let sar_id = RegulatoryReporting::file_sar(
            env.clone(),
            filer,
            subject,
            Bytes::from_slice(&env, b"fraud"),
            Bytes::from_slice(&env, b"Fraudulent activity detected"),
            Vec::new(&env),
            Bytes::from_slice(&env, b"50000"),
            Bytes::from_slice(&env, b"EUR"),
            Vec::from_array(&env, [Bytes::from_slice(&env, b"FIU")]),
            Vec::new(&env),
            1_699_000_000,
        )
        .unwrap();

        RegulatoryReporting::update_sar_status(
            env.clone(),
            admin,
            sar_id.clone(),
            Bytes::from_slice(&env, b"acknowledged"),
        )
        .unwrap();

        let sar = RegulatoryReporting::get_sar(env, sar_id).unwrap();
        assert_eq!(sar.status, Bytes::from_slice(&env, b"acknowledged"));
    }

    #[test]
    fn empty_sar_fields_rejected() {
        let env = setup_env();
        bootstrap(&env);
        let filer = Address::generate(&env);
        let subject = Address::generate(&env);

        let result = RegulatoryReporting::file_sar(
            env.clone(),
            filer,
            subject,
            Bytes::new(&env),
            Bytes::from_slice(&env, b"desc"),
            Vec::new(&env),
            Bytes::from_slice(&env, b"0"),
            Bytes::from_slice(&env, b"USD"),
            Vec::new(&env),
            Vec::new(&env),
            0,
        );
        assert_eq!(result.unwrap_err(), RegulatoryReportingError::InvalidInput);
    }

    #[test]
    fn paginated_sars() {
        let env = setup_env();
        bootstrap(&env);
        let filer = Address::generate(&env);
        let subject = Address::generate(&env);

        RegulatoryReporting::file_sar(
            env.clone(),
            filer.clone(),
            subject,
            Bytes::from_slice(&env, b"type1"),
            Bytes::from_slice(&env, b"desc1"),
            Vec::new(&env),
            Bytes::from_slice(&env, b"100"),
            Bytes::from_slice(&env, b"USD"),
            Vec::new(&env),
            Vec::new(&env),
            1_699_000_000,
        )
        .unwrap();

        let page = RegulatoryReporting::get_sars_paginated(env.clone(), 0, 10);
        assert_eq!(page.total, 1);
        assert!(!page.has_more);
    }

    // ── Scheduling ────────────────────────────────────────────────────────────

    #[test]
    fn schedule_and_retrieve() {
        let env = setup_env();
        bootstrap(&env);
        let admin = Address::generate(&env);
        let subject = Address::generate(&env);

        // Register a template first
        let tpl_id = Bytes::from_slice(&env, b"FATF_TRAVEL_RULE");
        let sections = Vec::new(&env);
        RegulatoryReporting::register_template(
            env.clone(),
            admin.clone(),
            tpl_id.clone(),
            Bytes::from_slice(&env, b"FATF"),
            Bytes::from_slice(&env, b"FATF"),
            sections,
            Vec::new(&env),
        )
        .unwrap();

        let sched_id = Bytes::from_slice(&env, b"DAILY_FATF");
        RegulatoryReporting::schedule_report(
            env.clone(),
            admin.clone(),
            sched_id.clone(),
            tpl_id,
            Some(subject),
            86400, // daily
            Vec::from_array(
                &env,
                [Bytes::from_slice(&env, b"json"), Bytes::from_slice(&env, b"csv")],
            ),
        )
        .unwrap();

        let sched = RegulatoryReporting::get_schedule(env.clone(), sched_id).unwrap();
        assert!(sched.active);
        assert_eq!(sched.interval_seconds, 86400);
    }

    #[test]
    fn cancel_schedule() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let tpl_id = Bytes::from_slice(&env, b"TMPL");
        RegulatoryReporting::register_template(
            env.clone(),
            admin.clone(),
            tpl_id.clone(),
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"EU"),
            Vec::new(&env),
            Vec::new(&env),
        )
        .unwrap();

        let sched_id = Bytes::from_slice(&env, b"SCHED_CANCEL");
        RegulatoryReporting::schedule_report(
            env.clone(),
            admin.clone(),
            sched_id.clone(),
            tpl_id,
            None,
            3600,
            Vec::new(&env),
        )
        .unwrap();

        RegulatoryReporting::cancel_schedule(env.clone(), admin.clone(), sched_id.clone()).unwrap();
        let sched = RegulatoryReporting::get_schedule(env.clone(), sched_id).unwrap();
        assert!(!sched.active);
    }

    #[test]
    fn mark_schedule_run_updates_timestamps() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let tpl_id = Bytes::from_slice(&env, b"TMPL2");
        RegulatoryReporting::register_template(
            env.clone(),
            admin.clone(),
            tpl_id.clone(),
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"EU"),
            Vec::new(&env),
            Vec::new(&env),
        )
        .unwrap();

        let sched_id = Bytes::from_slice(&env, b"SCHED_RUN");
        RegulatoryReporting::schedule_report(
            env.clone(),
            admin.clone(),
            sched_id.clone(),
            tpl_id,
            None,
            3600,
            Vec::new(&env),
        )
        .unwrap();

        RegulatoryReporting::mark_schedule_run(env.clone(), admin, sched_id.clone()).unwrap();
        let sched = RegulatoryReporting::get_schedule(env.clone(), sched_id).unwrap();
        assert!(sched.last_run_at.is_some());
    }

    // ── Export snapshots ──────────────────────────────────────────────────────

    #[test]
    fn record_and_retrieve_export_snapshot() {
        let env = setup_env();
        bootstrap(&env);
        let reporter = Address::generate(&env);
        let subject = Address::generate(&env);

        let hash = BytesN::from_array(&env, &[1u8; 32]);
        let ts = RegulatoryReporting::record_export_snapshot(
            env.clone(),
            reporter,
            subject.clone(),
            Bytes::from_slice(&env, b"json"),
            hash,
            42,
        )
        .unwrap();

        let snapshots = RegulatoryReporting::get_export_snapshots(env.clone(), subject.clone());
        assert_eq!(snapshots.len(), 1);

        let snapshot = RegulatoryReporting::get_export_snapshot(env, subject, ts).unwrap();
        assert_eq!(snapshot.entry_count, 42);
        assert_eq!(snapshot.format, Bytes::from_slice(&env, b"json"));
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    #[test]
    fn statistics_reflect_operations() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let tpl_id = Bytes::from_slice(&env, b"STAT_TEST");
        RegulatoryReporting::register_template(
            env.clone(),
            admin,
            tpl_id.clone(),
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"EU"),
            Vec::new(&env),
            Vec::new(&env),
        )
        .unwrap();

        let stats = RegulatoryReporting::get_statistics(env.clone());
        let tpl_count = stats.get(Bytes::from_slice(&env, b"templates")).unwrap();
        assert!(tpl_count >= 1);
    }

    // ── Non-admin operations ──────────────────────────────────────────────────

    #[test]
    fn non_admin_cannot_register_template() {
        let env = setup_env();
        bootstrap(&env);
        let intruder = Address::generate(&env);

        let result = RegulatoryReporting::register_template(
            env.clone(),
            intruder,
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"test"),
            Bytes::from_slice(&env, b"EU"),
            Vec::new(&env),
            Vec::new(&env),
        );
        assert_eq!(result.unwrap_err(), RegulatoryReportingError::Unauthorized);
    }
}
