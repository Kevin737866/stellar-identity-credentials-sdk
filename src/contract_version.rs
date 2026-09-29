//! Contract Version Tracking & Compatibility Checks (#198)
//!
//! Every contract in this crate embeds a compile-time semantic version and
//! records a version history on chain so that auditors and integrators can
//! answer "what is running, and when did it change?".
//!
//! The module also provides the compatibility rules used by cross-contract
//! calls.  When contract A calls into contract B, A can ask B for its
//! version and assert that the pair is compatible *before* performing the
//! call, which turns a silent ABI mismatch into a clear, catchable error.
//!
//! # Compatibility rules
//!
//! Follows the usual semantic-versioning guarantee: a consumer is compatible
//! with a provider when
//!
//! * the **major** versions are equal, and
//! * the provider's **minor** version is not newer than the consumer's.
//!
//! In other words, a `1.4.x` contract may call a `1.2.x` contract safely, but
//! a `1.2.x` contract must not call a `1.4.x` one, because `1.4` may have
//! introduced a response field `1.2` cannot interpret.  Any change to the
//! major version is a breaking change and requires both sides to move
//! together.
//!
//! # Usage (within a contract)
//!
//! ```ignore
//! use crate::contract_version::{self, SemanticVersion};
//!
//! pub fn cross_call(env: &Env, remote: Address) -> Result<(), MyError> {
//!     let remote_version = contract_version::query_version(env, &remote)?;
//!     contract_version::require_compatible(env, &remote_version)?;
//!     // … the actual cross-contract call …
//!     Ok(())
//! }
//! ```

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol, Vec,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Compile-time major version of the contract set.
///
/// Bump this whenever a breaking (ABI-incompatible) change is made.
pub const VERSION_MAJOR: u32 = 1;
/// Compile-time minor version of the contract set.
pub const VERSION_MINOR: u32 = 0;
/// Compile-time patch version of the contract set.
pub const VERSION_PATCH: u32 = 0;

/// TTL for version-related persistent storage entries (in ledgers).
const VERSION_TTL_LEDGERS: u32 = 6_307_200; // ~1 year

/// Maximum number of version history entries retained on chain.
const MAX_VERSION_HISTORY: u32 = 64;

/// Prefix used when publishing the Prometheus-style `get_version` output.
const VERSION_LABEL: &str = "stellar_identity_contract_version";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A semantic version triple.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SemanticVersion {
    /// Breaking-change counter. Must match across interacting contracts.
    pub major: u32,
    /// Additive (backward compatible) feature counter.
    pub minor: u32,
    /// Bug-fix counter. Never affects compatibility.
    pub patch: u32,
}

impl SemanticVersion {
    /// The version this WASM build was compiled with.
    pub const fn current() -> Self {
        Self {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            patch: VERSION_PATCH,
        }
    }
}

/// A single entry in the on-chain version history.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionHistoryEntry {
    /// The version that became active.
    pub version: SemanticVersion,
    /// Address that activated the version, or `None` for the build-time
    /// deployment entry when the contract has no admin registered yet.
    pub activated_by: Option<Address>,
    /// Ledger timestamp at which the version became active.
    pub activated_at: u64,
    /// Ledger sequence at which the version became active.
    pub ledger_sequence: u32,
    /// Optional free-form note, e.g. the reason for the change.
    pub note: Bytes,
}

/// Outcome of a compatibility evaluation between two versions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityReport {
    /// `true` when the interaction is safe to proceed.
    pub compatible: bool,
    /// The calling (consumer) side version.
    pub consumer: SemanticVersion,
    /// The remote (provider) side version.
    pub provider: SemanticVersion,
    /// Machine-readable reason: `compatible`, `major_mismatch`,
    /// `provider_too_new`, or `uninitialized`.
    pub reason: Symbol,
    /// Human-readable elaboration of `reason`.
    pub detail: Bytes,
}

/// The version of a named contract, as observed from outside.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractVersionInfo {
    /// Logical contract name, e.g. `credential_issuer`.
    pub name: Symbol,
    /// The version reported by the contract.
    pub version: SemanticVersion,
    /// `false` when the contract does not implement `get_version`.
    pub supported: bool,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub enum VersionKey {
    /// The currently active semantic version.
    Current,
    /// Vec<VersionHistoryEntry>, oldest first.
    History,
    /// Set once `init_version` has run.
    Initialized,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum VersionError {
    /// The version module has already been initialised.
    AlreadyInitialized = 1,
    /// The version module has not been initialised yet.
    NotInitialized = 2,
    /// A supplied `SemanticVersion` is malformed (e.g. a zero major).
    InvalidVersion = 3,
    /// The new version is not strictly newer than the active one.
    VersionNotIncreasing = 4,
    /// The caller is not permitted to change the recorded version.
    Unauthorized = 5,
    /// The consumer and provider versions are on different major versions.
    IncompatibleMajorVersion = 6,
    /// The provider is on a newer minor version than the consumer.
    ProviderTooNew = 7,
    /// The remote contract does not expose a `get_version` entry point.
    RemoteVersionUnsupported = 8,
}

// ---------------------------------------------------------------------------
// Pure compatibility rules
// ---------------------------------------------------------------------------

/// Render a version as a dotted string such as `1.4.2`.
///
/// The formatting is done without `alloc::format!` to keep the contract WASM
/// small; the result is returned as `Bytes` so it can be published in events
/// and returned across the ABI.
pub fn version_to_bytes(env: &Env, version: &SemanticVersion) -> Bytes {
    let mut out = Bytes::new(env);
    for (idx, part) in [version.major, version.minor, version.patch]
        .iter()
        .enumerate()
    {
        if idx > 0 {
            out.append(&Bytes::from_slice(env, b"."));
        }
        out.append(&Bytes::from_slice(env, part.to_string().as_bytes()));
    }
    out
}

/// Validate a version triple.
///
/// A zero major version is rejected because it cannot be ordered against the
/// semver major-version compatibility rule.
pub fn validate_version(version: &SemanticVersion) -> Result<(), VersionError> {
    if version.major == 0 {
        return Err(VersionError::InvalidVersion);
    }
    Ok(())
}

/// Evaluate whether a `consumer` may safely call a `provider`.
///
/// See the module-level docs for the exact rules.  This function is pure: it
/// performs no storage reads and is safe to call from any contract.
pub fn check_compatibility(
    env: &Env,
    consumer: &SemanticVersion,
    provider: &SemanticVersion,
) -> CompatibilityReport {
    let reason = if consumer.major != provider.major {
        "major_mismatch"
    } else if provider.minor > consumer.minor {
        "provider_too_new"
    } else {
        "compatible"
    };

    let compatible = reason == "compatible";

    let detail = if compatible {
        Bytes::from_slice(env, b"versions are compatible")
    } else if reason == "major_mismatch" {
        version_to_bytes(env, consumer)
    } else {
        version_to_bytes(env, provider)
    };

    CompatibilityReport {
        compatible,
        consumer: consumer.clone(),
        provider: provider.clone(),
        reason: Symbol::new(env, reason),
        detail,
    }
}

/// `true` when `consumer` may safely call `provider`.
pub fn are_compatible(consumer: &SemanticVersion, provider: &SemanticVersion) -> bool {
    consumer.major == provider.major && provider.minor <= consumer.minor
}

// ---------------------------------------------------------------------------
// Storage-backed API
// ---------------------------------------------------------------------------

/// Initialise the version module and record the build version in history.
///
/// Safe to call more than once: subsequent calls are no-ops so that contract
/// upgrade paths can invoke it unconditionally.
pub fn init_version(env: &Env) {
    if is_initialized(env) {
        return;
    }
    let current = SemanticVersion::current();
    env.storage()
        .persistent()
        .set(&VersionKey::Current, &current);
    env.storage()
        .persistent()
        .set(&VersionKey::Initialized, &true);

    // Attribute the initial deployment to the contract admin when one has been
    // registered, so the history is attributable.  Contracts without an admin
    // simply start with an unattributed entry rather than failing to
    // initialise — version reporting must never be a hard dependency.
    let admin: Option<Address> = env.storage().instance().get(&Symbol::new(env, "admin"));
    push_history(
        env,
        current,
        admin,
        Bytes::from_slice(env, b"initial deployment"),
    );

    extend_ttls(env);
}

/// `true` once [`init_version`] has run.
pub fn is_initialized(env: &Env) -> bool {
    env.storage().persistent().has(&VersionKey::Initialized)
}

/// Return the version recorded on chain, falling back to the compile-time
/// constant for contracts that predate this module.
pub fn get_version(env: &Env) -> SemanticVersion {
    env.storage()
        .persistent()
        .get(&VersionKey::Current)
        .unwrap_or_else(SemanticVersion::current)
}

/// Return the full version history, oldest first.
pub fn get_version_history(env: &Env) -> Vec<VersionHistoryEntry> {
    env.storage()
        .persistent()
        .get(&VersionKey::History)
        .unwrap_or_else(|| Vec::new(env))
}

/// Record a new active version, appending to the history for audit.
///
/// The new version must be strictly greater than the current one, which
/// prevents an operator from silently rolling the recorded version backwards
/// and confusing integrators.
pub fn record_version(
    env: &Env,
    caller: &Address,
    new_version: SemanticVersion,
    note: Bytes,
) -> Result<(), VersionError> {
    validate_version(&new_version)?;

    let current = get_version(env);
    if new_version <= current {
        return Err(VersionError::VersionNotIncreasing);
    }

    env.storage()
        .persistent()
        .set(&VersionKey::Current, &new_version);
    push_history(env, new_version.clone(), Some(caller.clone()), note);

    env.events().publish(
        (Symbol::new(env, "ContractVersionChanged"),),
        (
            caller.clone(),
            new_version.clone(),
            version_to_bytes(env, &new_version),
        ),
    );

    extend_ttls(env);
    Ok(())
}

fn push_history(env: &Env, version: SemanticVersion, by: Option<Address>, note: Bytes) {
    let mut history: Vec<VersionHistoryEntry> = get_version_history(env);
    history.push_back(VersionHistoryEntry {
        version,
        activated_by: by,
        activated_at: env.ledger().timestamp(),
        ledger_sequence: env.ledger().sequence(),
        note,
    });

    // Keep the log bounded; the oldest entries fall off the front.
    let len = history.len();
    if len > MAX_VERSION_HISTORY as u32 {
        let mut trimmed = Vec::new(env);
        let start = len - MAX_VERSION_HISTORY;
        for i in start..len {
            if let Some(entry) = history.get(i) {
                trimmed.push_back(entry);
            }
        }
        history = trimmed;
    }

    env.storage()
        .persistent()
        .set(&VersionKey::History, &history);
}

/// Compare this contract's version against a remote version supplied by a
/// caller and return a full report.
pub fn check_remote_version(env: &Env, provider: &SemanticVersion) -> CompatibilityReport {
    check_compatibility(env, &get_version(env), provider)
}

/// Assert that a remote version is compatible with this contract.
///
/// Intended to be called at the top of a cross-contract entry point:
///
/// ```ignore
/// let remote = contract_version::query_version(&env, &other)?;
/// contract_version::require_compatible(&env, &remote)?;
/// ```
pub fn require_compatible(env: &Env, provider: &SemanticVersion) -> Result<(), VersionError> {
    let consumer = get_version(env);
    let report = check_compatibility(env, &consumer, provider);
    if report.compatible {
        return Ok(());
    }
    classify_incompatibility(&consumer, provider)
}

/// Map an incompatible `(consumer, provider)` pair onto a typed error.
///
/// Split out so that [`require_compatible`] and
/// [`ContractVersion::require_compatible`] agree on which error a given
/// mismatch produces.
fn classify_incompatibility(
    consumer: &SemanticVersion,
    provider: &SemanticVersion,
) -> Result<(), VersionError> {
    if provider.major == consumer.major && provider.minor > consumer.minor {
        Err(VersionError::ProviderTooNew)
    } else {
        Err(VersionError::IncompatibleMajorVersion)
    }
}

/// Query a remote contract's version via its `get_version` entry point.
///
/// Returns [`VersionError::RemoteVersionUnsupported`] when the target does
/// not implement the entry point, so a caller can degrade gracefully instead
/// of trapping.
pub fn query_version(env: &Env, remote: &Address) -> Result<SemanticVersion, VersionError> {
    let client = ContractVersionClient::new(env, remote);
    match client.try_get_version() {
        // `try_` on a client returns `Result<Result<T, ConversionError>, _>`:
        // the outer error is a transport failure, the inner a return-value
        // conversion failure. Both mean "this peer is not usable".
        Ok(Ok(version)) => Ok(version),
        Ok(Err(_)) | Err(_) => Err(VersionError::RemoteVersionUnsupported),
    }
}

/// Return the version of several remote contracts in one call, so integrators
/// can render a fleet-wide compatibility matrix.
pub fn describe_remotes(
    env: &Env,
    remotes: &Vec<Address>,
    names: &Vec<Symbol>,
) -> Vec<ContractVersionInfo> {
    let mut out = Vec::new(env);
    for i in 0..remotes.len() {
        let address = remotes.get(i).unwrap();
        let name = names.get(i).unwrap_or_else(|| Symbol::new(env, "unknown"));
        match query_version(env, &address) {
            Ok(version) => out.push_back(ContractVersionInfo {
                name,
                version,
                supported: true,
            }),
            Err(_) => out.push_back(ContractVersionInfo {
                name,
                version: SemanticVersion::current(),
                supported: false,
            }),
        }
    }
    out
}

/// Render the current version in a Prometheus exposition-format line, e.g.
/// `stellar_identity_contract_version{contract="credential_issuer"} 1.0.0`.
///
/// Intended to be embedded in the output of
/// [`crate::contract_telemetry::prometheus_export`].
pub fn prometheus_version_line(env: &Env, contract_name: Symbol) -> Bytes {
    let mut line = Bytes::from_slice(env, VERSION_LABEL.as_bytes());
    line.append(&Bytes::from_slice(env, b"{contract=\""));
    line.append(&Bytes::from_slice(
        env,
        Symbol::to_string(&contract_name).as_bytes(),
    ));
    line.append(&Bytes::from_slice(env, b"\"} "));
    line.append(&version_to_bytes(env, &get_version(env)));
    line.append(&Bytes::from_slice(env, b"\n"));
    line
}

fn extend_ttls(env: &Env) {
    env.storage().persistent().extend_ttl(
        &VersionKey::Current,
        VERSION_TTL_LEDGERS,
        VERSION_TTL_LEDGERS,
    );
    env.storage().persistent().extend_ttl(
        &VersionKey::History,
        VERSION_TTL_LEDGERS,
        VERSION_TTL_LEDGERS,
    );
    env.storage().persistent().extend_ttl(
        &VersionKey::Initialized,
        VERSION_TTL_LEDGERS,
        VERSION_TTL_LEDGERS,
    );
}

// ---------------------------------------------------------------------------
// Standalone contract surface
// ---------------------------------------------------------------------------

/// A minimal contract that reports the shared version constants, so
/// integrators can read the version of the deployment without holding a
/// reference to every other contract.
#[contract]
pub struct ContractVersion;

#[contractimpl]
impl ContractVersion {
    /// The semantic version this WASM was built with.
    pub fn get_version(_env: Env) -> SemanticVersion {
        SemanticVersion::current()
    }

    /// The version as a dotted string, e.g. `1.0.0`.
    pub fn get_version_string(env: Env) -> Bytes {
        version_to_bytes(&env, &SemanticVersion::current())
    }

    /// The major version number.
    pub fn major() -> u32 {
        VERSION_MAJOR
    }

    /// The minor version number.
    pub fn minor() -> u32 {
        VERSION_MINOR
    }

    /// The patch version number.
    pub fn patch() -> u32 {
        VERSION_PATCH
    }

    /// Evaluate compatibility with a caller-supplied provider version.
    pub fn check_compatibility(env: Env, provider: SemanticVersion) -> CompatibilityReport {
        check_compatibility(&env, &SemanticVersion::current(), &provider)
    }

    /// Fail unless `provider` is compatible with this contract.
    pub fn require_compatible(provider: SemanticVersion) -> Result<(), VersionError> {
        let consumer = SemanticVersion::current();
        if are_compatible(&consumer, &provider) {
            return Ok(());
        }
        classify_incompatibility(&consumer, &provider)
    }

    /// The Prometheus exposition line for this contract.
    pub fn prometheus_version(env: Env) -> Bytes {
        prometheus_version_line(&env, Symbol::new(&env, "contract_version"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};

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

    fn v(major: u32, minor: u32, patch: u32) -> SemanticVersion {
        SemanticVersion {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn current_version_matches_constants() {
        assert_eq!(SemanticVersion::current().major, VERSION_MAJOR);
        assert_eq!(SemanticVersion::current().minor, VERSION_MINOR);
        assert_eq!(SemanticVersion::current().patch, VERSION_PATCH);
    }

    #[test]
    fn version_to_bytes_renders_dotted_string() {
        let env = setup_env();
        let rendered = version_to_bytes(&env, &v(1, 4, 2));
        assert_eq!(rendered, Bytes::from_slice(&env, b"1.4.2".as_slice()));
    }

    #[test]
    fn same_major_and_older_provider_is_compatible() {
        let env = setup_env();
        let report = check_compatibility(&env, &v(1, 4, 0), &v(1, 2, 9));
        assert!(report.compatible);
    }

    #[test]
    fn same_minor_is_compatible() {
        let env = setup_env();
        let report = check_compatibility(&env, &v(2, 0, 3), &v(2, 0, 0));
        assert!(report.compatible);
    }

    #[test]
    fn major_mismatch_is_incompatible() {
        let env = setup_env();
        let report = check_compatibility(&env, &v(1, 4, 0), &v(2, 0, 0));
        assert!(!report.compatible);
        assert_eq!(report.reason, Symbol::new(&env, "major_mismatch"));
    }

    #[test]
    fn newer_provider_minor_is_incompatible() {
        let env = setup_env();
        let report = check_compatibility(&env, &v(1, 2, 0), &v(1, 4, 0));
        assert!(!report.compatible);
        assert_eq!(report.reason, Symbol::new(&env, "provider_too_new"));
    }

    #[test]
    fn are_compatible_matches_check_compatibility() {
        assert!(are_compatible(&v(1, 4, 0), &v(1, 4, 0)));
        assert!(are_compatible(&v(1, 4, 0), &v(1, 0, 0)));
        assert!(!are_compatible(&v(1, 0, 0), &v(1, 4, 0)));
        assert!(!are_compatible(&v(1, 4, 0), &v(2, 0, 0)));
    }

    #[test]
    fn validate_rejects_zero_major() {
        assert_eq!(
            validate_version(&v(0, 1, 0)),
            Err(VersionError::InvalidVersion)
        );
        assert!(validate_version(&v(1, 0, 0)).is_ok());
    }

    #[test]
    fn require_compatible_passes_for_older_provider() {
        let env = setup_env();
        assert!(require_compatible(&env, &v(1, 0, 0)).is_ok());
    }

    #[test]
    fn require_compatible_rejects_newer_provider() {
        let env = setup_env();
        assert_eq!(
            require_compatible(&env, &v(1, 99, 0)),
            Err(VersionError::ProviderTooNew)
        );
    }

    #[test]
    fn require_compatible_rejects_major_mismatch() {
        let env = setup_env();
        assert_eq!(
            require_compatible(&env, &v(2, 0, 0)),
            Err(VersionError::IncompatibleMajorVersion)
        );
    }

    #[test]
    fn init_version_is_idempotent() {
        let env = setup_env();
        assert!(!is_initialized(&env));
        init_version(&env);
        assert!(is_initialized(&env));
        assert_eq!(get_version(&env), SemanticVersion::current());

        // Second call must not duplicate the history entry.
        let before = get_version_history(&env).len();
        init_version(&env);
        assert_eq!(get_version_history(&env).len(), before);
    }

    #[test]
    fn get_version_falls_back_to_build_constant() {
        let env = setup_env();
        assert_eq!(get_version(&env), SemanticVersion::current());
    }

    #[test]
    fn record_version_appends_history() {
        let env = setup_env();
        let admin = Address::generate(&env);
        init_version(&env);

        record_version(
            &env,
            &admin,
            v(1, 1, 0),
            Bytes::from_slice(&env, b"new credential type"),
        )
        .unwrap();

        assert_eq!(get_version(&env), v(1, 1, 0));
        let history = get_version_history(&env);
        assert_eq!(history.len(), 2);
        assert_eq!(history.get(1).unwrap().version, v(1, 1, 0));
        assert_eq!(history.get(1).unwrap().activated_by, Some(admin));
    }

    #[test]
    fn record_version_rejects_non_increasing() {
        let env = setup_env();
        let admin = Address::generate(&env);
        init_version(&env);

        assert_eq!(
            record_version(&env, &admin, v(1, 0, 0), Bytes::new(&env)),
            Err(VersionError::VersionNotIncreasing)
        );
        assert_eq!(
            record_version(&env, &admin, v(0, 9, 0), Bytes::new(&env)),
            Err(VersionError::InvalidVersion)
        );
    }

    #[test]
    fn prometheus_line_contains_version() {
        let env = setup_env();
        init_version(&env);
        let line = prometheus_version_line(&env, Symbol::new(&env, "did_registry"));
        let expected = Bytes::from_slice(
            &env,
            b"stellar_identity_contract_version{contract=\"did_registry\"} 1.0.0\n".as_slice(),
        );
        assert_eq!(line, expected);
    }
}
