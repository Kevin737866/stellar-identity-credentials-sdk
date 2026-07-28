//! Access Control Audit Trail (#74)
//!
//! Provides an append-only log of admin / privileged actions.  Each event is
//! stored individually under a sequenced key so the log cannot be rewritten.
//! Query helpers let callers page through the history or filter by actor /
//! event type.

use soroban_sdk::{contracttype, Address, Bytes, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum AuditKey {
    /// Individual event at sequence number `n`.
    Event(u64),
    /// Global event counter (u64).
    Counter,
    /// Index: actor → list of sequence numbers.
    ActorIndex(Address),
    /// Index: event_type tag → list of sequence numbers.
    TypeIndex(Symbol),
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// All auditable event categories.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditEventType {
    /// A new role or permission was granted.
    RoleGranted,
    /// A role or permission was revoked.
    RoleRevoked,
    /// Admin transferred ownership.
    AdminTransferred,
    /// A credential was issued.
    CredentialIssued,
    /// A credential was revoked.
    CredentialRevoked,
    /// A DID was created.
    DIDCreated,
    /// A DID was deactivated.
    DIDDeactivated,
    /// A sanctions-list was updated.
    SanctionsListUpdated,
    /// An address was added to a sanctions list.
    AddressSanctioned,
    /// An address was removed from a sanctions list.
    AddressUnsanctioned,
    /// A compliance rule was registered or updated.
    ComplianceRuleChanged,
    /// A ZK circuit was registered.
    CircuitRegistered,
    /// A custom / catch-all admin action.
    AdminAction,
}

/// A single immutable audit record.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditEvent {
    /// Monotonically increasing sequence number (1-based).
    pub seq: u64,
    /// Who performed the action.
    pub actor: Address,
    /// Category of the event.
    pub event_type: AuditEventType,
    /// Optional identifier of the affected resource (DID, credential_id …).
    pub resource_id: Option<Bytes>,
    /// Human-readable detail / reason (max 256 bytes recommended).
    pub detail: Bytes,
    /// Ledger timestamp when the event was recorded.
    pub timestamp: u64,
    /// Ledger sequence number for additional ordering context.
    pub ledger_sequence: u32,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn current_counter(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get::<_, u64>(&AuditKey::Counter)
        .unwrap_or(0)
}

fn increment_counter(env: &Env) -> u64 {
    let next = current_counter(env) + 1;
    env.storage()
        .instance()
        .set(&AuditKey::Counter, &next);
    next
}

fn event_type_symbol(env: &Env, et: &AuditEventType) -> Symbol {
    let tag = match et {
        AuditEventType::RoleGranted => "role_granted",
        AuditEventType::RoleRevoked => "role_revoked",
        AuditEventType::AdminTransferred => "admin_xfer",
        AuditEventType::CredentialIssued => "cred_issued",
        AuditEventType::CredentialRevoked => "cred_revoked",
        AuditEventType::DIDCreated => "did_created",
        AuditEventType::DIDDeactivated => "did_deact",
        AuditEventType::SanctionsListUpdated => "sanct_upd",
        AuditEventType::AddressSanctioned => "addr_sanct",
        AuditEventType::AddressUnsanctioned => "addr_unsanct",
        AuditEventType::ComplianceRuleChanged => "comp_rule",
        AuditEventType::CircuitRegistered => "circuit_reg",
        AuditEventType::AdminAction => "admin_act",
    };
    Symbol::new(env, tag)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Append a new audit event to the log.
///
/// Returns the assigned sequence number.
pub fn emit_audit_event(
    env: &Env,
    actor: Address,
    event_type: AuditEventType,
    resource_id: Option<Bytes>,
    detail: Bytes,
) -> u64 {
    let seq = increment_counter(env);

    let event = AuditEvent {
        seq,
        actor: actor.clone(),
        event_type: event_type.clone(),
        resource_id,
        detail,
        timestamp: env.ledger().timestamp(),
        ledger_sequence: env.ledger().sequence(),
    };

    // Store the event.
    env.storage()
        .persistent()
        .set(&AuditKey::Event(seq), &event);

    // Update actor index.
    let mut actor_idx: Vec<u64> = env
        .storage()
        .persistent()
        .get(&AuditKey::ActorIndex(actor.clone()))
        .unwrap_or_else(|| Vec::new(env));
    actor_idx.push_back(seq);
    env.storage()
        .persistent()
        .set(&AuditKey::ActorIndex(actor), &actor_idx);

    // Update type index.
    let type_sym = event_type_symbol(env, &event_type);
    let mut type_idx: Vec<u64> = env
        .storage()
        .persistent()
        .get(&AuditKey::TypeIndex(type_sym.clone()))
        .unwrap_or_else(|| Vec::new(env));
    type_idx.push_back(seq);
    env.storage()
        .persistent()
        .set(&AuditKey::TypeIndex(type_sym), &type_idx);

    // Emit a Soroban event for off-chain indexers.
    env.events().publish(
        (Symbol::new(env, "AuditEvent"),),
        (seq, event_type_symbol(env, &event_type)),
    );

    seq
}

/// Retrieve a single event by its sequence number.
pub fn get_audit_event(env: &Env, seq: u64) -> Option<AuditEvent> {
    env.storage().persistent().get(&AuditKey::Event(seq))
}

/// Return the total number of events recorded so far.
pub fn audit_event_count(env: &Env) -> u64 {
    current_counter(env)
}

/// Retrieve a page of events ordered by sequence number.
///
/// `page` is 0-based; `page_size` is clamped to 1–50.
pub fn get_audit_history(env: &Env, page: u32, page_size: u32) -> Vec<AuditEvent> {
    let size = page_size.clamp(1, 50);
    let total = current_counter(env);
    let start = (page as u64) * (size as u64) + 1; // seq numbers are 1-based
    let mut result = Vec::new(env);
    for seq in start..=(start + size as u64 - 1) {
        if seq > total {
            break;
        }
        if let Some(ev) = get_audit_event(env, seq) {
            result.push_back(ev);
        }
    }
    result
}

/// Retrieve all event sequence numbers attributed to a specific `actor`.
pub fn get_events_by_actor(env: &Env, actor: Address) -> Vec<u64> {
    env.storage()
        .persistent()
        .get(&AuditKey::ActorIndex(actor))
        .unwrap_or_else(|| Vec::new(env))
}

/// Retrieve all event sequence numbers of a particular `event_type`.
pub fn get_events_by_type(env: &Env, event_type: AuditEventType) -> Vec<u64> {
    let sym = event_type_symbol(env, &event_type);
    env.storage()
        .persistent()
        .get(&AuditKey::TypeIndex(sym))
        .unwrap_or_else(|| Vec::new(env))
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
            sequence_number: 1000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });
        env
    }

    #[test]
    fn emit_and_retrieve_single_event() {
        let env = setup();
        let actor = Address::generate(&env);
        let detail = Bytes::from_slice(&env, b"admin granted role to user");

        let seq = emit_audit_event(
            &env,
            actor.clone(),
            AuditEventType::RoleGranted,
            None,
            detail.clone(),
        );
        assert_eq!(seq, 1);

        let ev = get_audit_event(&env, seq).expect("event must be stored");
        assert_eq!(ev.seq, 1);
        assert_eq!(ev.actor, actor);
        assert_eq!(ev.event_type, AuditEventType::RoleGranted);
        assert_eq!(ev.detail, detail);
    }

    #[test]
    fn sequence_numbers_are_monotonically_increasing() {
        let env = setup();
        let actor = Address::generate(&env);

        for i in 1u64..=5 {
            let seq = emit_audit_event(
                &env,
                actor.clone(),
                AuditEventType::AdminAction,
                None,
                Bytes::from_slice(&env, b"action"),
            );
            assert_eq!(seq, i);
        }
        assert_eq!(audit_event_count(&env), 5);
    }

    #[test]
    fn actor_index_tracks_correct_events() {
        let env = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        emit_audit_event(&env, alice.clone(), AuditEventType::CredentialIssued, None, Bytes::from_slice(&env, b"c1"));
        emit_audit_event(&env, bob.clone(), AuditEventType::CredentialRevoked, None, Bytes::from_slice(&env, b"c2"));
        emit_audit_event(&env, alice.clone(), AuditEventType::DIDCreated, None, Bytes::from_slice(&env, b"c3"));

        let alice_seqs = get_events_by_actor(&env, alice);
        assert_eq!(alice_seqs.len(), 2);

        let bob_seqs = get_events_by_actor(&env, bob);
        assert_eq!(bob_seqs.len(), 1);
    }

    #[test]
    fn type_index_tracks_correct_events() {
        let env = setup();
        let actor = Address::generate(&env);

        emit_audit_event(&env, actor.clone(), AuditEventType::RoleGranted, None, Bytes::from_slice(&env, b"r1"));
        emit_audit_event(&env, actor.clone(), AuditEventType::RoleRevoked, None, Bytes::from_slice(&env, b"r2"));
        emit_audit_event(&env, actor.clone(), AuditEventType::RoleGranted, None, Bytes::from_slice(&env, b"r3"));

        let granted = get_events_by_type(&env, AuditEventType::RoleGranted);
        assert_eq!(granted.len(), 2);

        let revoked = get_events_by_type(&env, AuditEventType::RoleRevoked);
        assert_eq!(revoked.len(), 1);
    }

    #[test]
    fn pagination_returns_correct_pages() {
        let env = setup();
        let actor = Address::generate(&env);

        for _ in 0..15 {
            emit_audit_event(&env, actor.clone(), AuditEventType::AdminAction, None, Bytes::from_slice(&env, b"x"));
        }

        let page0 = get_audit_history(&env, 0, 10);
        assert_eq!(page0.len(), 10);

        let page1 = get_audit_history(&env, 1, 10);
        assert_eq!(page1.len(), 5);
    }

    #[test]
    fn resource_id_is_stored_and_retrieved() {
        let env = setup();
        let actor = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-abc-123");

        let seq = emit_audit_event(
            &env,
            actor,
            AuditEventType::CredentialRevoked,
            Some(cred_id.clone()),
            Bytes::from_slice(&env, b"expired"),
        );

        let ev = get_audit_event(&env, seq).unwrap();
        assert_eq!(ev.resource_id, Some(cred_id));
    }

    #[test]
    fn missing_event_returns_none() {
        let env = setup();
        assert!(get_audit_event(&env, 9999).is_none());
    }
}
//! Access Control Audit Trail (#74)
//!
//! Provides an append-only log of admin / privileged actions.  Each event is
//! stored individually under a sequenced key so the log cannot be rewritten.
//! Query helpers let callers page through the history or filter by actor /
//! event type.

use soroban_sdk::{contracttype, Address, Bytes, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum AuditKey {
    /// Individual event at sequence number `n`.
    Event(u64),
    /// Global event counter (u64).
    Counter,
    /// Index: actor → list of sequence numbers.
    ActorIndex(Address),
    /// Index: event_type tag → list of sequence numbers.
    TypeIndex(Symbol),
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// All auditable event categories.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditEventType {
    /// A new role or permission was granted.
    RoleGranted,
    /// A role or permission was revoked.
    RoleRevoked,
    /// Admin transferred ownership.
    AdminTransferred,
    /// A credential was issued.
    CredentialIssued,
    /// A credential was revoked.
    CredentialRevoked,
    /// A DID was created.
    DIDCreated,
    /// A DID was deactivated.
    DIDDeactivated,
    /// A sanctions-list was updated.
    SanctionsListUpdated,
    /// An address was added to a sanctions list.
    AddressSanctioned,
    /// An address was removed from a sanctions list.
    AddressUnsanctioned,
    /// A compliance rule was registered or updated.
    ComplianceRuleChanged,
    /// A ZK circuit was registered.
    CircuitRegistered,
    /// A custom / catch-all admin action.
    AdminAction,
}

/// A single immutable audit record.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditEvent {
    /// Monotonically increasing sequence number (1-based).
    pub seq: u64,
    /// Who performed the action.
    pub actor: Address,
    /// Category of the event.
    pub event_type: AuditEventType,
    /// Optional identifier of the affected resource (DID, credential_id …).
    pub resource_id: Option<Bytes>,
    /// Human-readable detail / reason (max 256 bytes recommended).
    pub detail: Bytes,
    /// Ledger timestamp when the event was recorded.
    pub timestamp: u64,
    /// Ledger sequence number for additional ordering context.
    pub ledger_sequence: u32,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn current_counter(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get::<_, u64>(&AuditKey::Counter)
        .unwrap_or(0)
}

fn increment_counter(env: &Env) -> u64 {
    let next = current_counter(env) + 1;
    env.storage()
        .instance()
        .set(&AuditKey::Counter, &next);
    next
}

fn event_type_symbol(env: &Env, et: &AuditEventType) -> Symbol {
    let tag = match et {
        AuditEventType::RoleGranted => "role_granted",
        AuditEventType::RoleRevoked => "role_revoked",
        AuditEventType::AdminTransferred => "admin_xfer",
        AuditEventType::CredentialIssued => "cred_issued",
        AuditEventType::CredentialRevoked => "cred_revoked",
        AuditEventType::DIDCreated => "did_created",
        AuditEventType::DIDDeactivated => "did_deact",
        AuditEventType::SanctionsListUpdated => "sanct_upd",
        AuditEventType::AddressSanctioned => "addr_sanct",
        AuditEventType::AddressUnsanctioned => "addr_unsanct",
        AuditEventType::ComplianceRuleChanged => "comp_rule",
        AuditEventType::CircuitRegistered => "circuit_reg",
        AuditEventType::AdminAction => "admin_act",
    };
    Symbol::new(env, tag)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Append a new audit event to the log.
///
/// Returns the assigned sequence number.
pub fn emit_audit_event(
    env: &Env,
    actor: Address,
    event_type: AuditEventType,
    resource_id: Option<Bytes>,
    detail: Bytes,
) -> u64 {
    let seq = increment_counter(env);

    let event = AuditEvent {
        seq,
        actor: actor.clone(),
        event_type: event_type.clone(),
        resource_id,
        detail,
        timestamp: env.ledger().timestamp(),
        ledger_sequence: env.ledger().sequence(),
    };

    // Store the event.
    env.storage()
        .persistent()
        .set(&AuditKey::Event(seq), &event);

    // Update actor index.
    let mut actor_idx: Vec<u64> = env
        .storage()
        .persistent()
        .get(&AuditKey::ActorIndex(actor.clone()))
        .unwrap_or_else(|| Vec::new(env));
    actor_idx.push_back(seq);
    env.storage()
        .persistent()
        .set(&AuditKey::ActorIndex(actor), &actor_idx);

    // Update type index.
    let type_sym = event_type_symbol(env, &event_type);
    let mut type_idx: Vec<u64> = env
        .storage()
        .persistent()
        .get(&AuditKey::TypeIndex(type_sym.clone()))
        .unwrap_or_else(|| Vec::new(env));
    type_idx.push_back(seq);
    env.storage()
        .persistent()
        .set(&AuditKey::TypeIndex(type_sym), &type_idx);

    // Emit a Soroban event for off-chain indexers.
    env.events().publish(
        (Symbol::new(env, "AuditEvent"),),
        (seq, event_type_symbol(env, &event_type)),
    );

    seq
}

/// Retrieve a single event by its sequence number.
pub fn get_audit_event(env: &Env, seq: u64) -> Option<AuditEvent> {
    env.storage().persistent().get(&AuditKey::Event(seq))
}

/// Return the total number of events recorded so far.
pub fn audit_event_count(env: &Env) -> u64 {
    current_counter(env)
}

/// Retrieve a page of events ordered by sequence number.
///
/// `page` is 0-based; `page_size` is clamped to 1–50.
pub fn get_audit_history(env: &Env, page: u32, page_size: u32) -> Vec<AuditEvent> {
    let size = page_size.clamp(1, 50);
    let total = current_counter(env);
    let start = (page as u64) * (size as u64) + 1; // seq numbers are 1-based
    let mut result = Vec::new(env);
    for seq in start..=(start + size as u64 - 1) {
        if seq > total {
            break;
        }
        if let Some(ev) = get_audit_event(env, seq) {
            result.push_back(ev);
        }
    }
    result
}

/// Retrieve all event sequence numbers attributed to a specific `actor`.
pub fn get_events_by_actor(env: &Env, actor: Address) -> Vec<u64> {
    env.storage()
        .persistent()
        .get(&AuditKey::ActorIndex(actor))
        .unwrap_or_else(|| Vec::new(env))
}

/// Retrieve all event sequence numbers of a particular `event_type`.
pub fn get_events_by_type(env: &Env, event_type: AuditEventType) -> Vec<u64> {
    let sym = event_type_symbol(env, &event_type);
    env.storage()
        .persistent()
        .get(&AuditKey::TypeIndex(sym))
        .unwrap_or_else(|| Vec::new(env))
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
            sequence_number: 1000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });
        env
    }

    #[test]
    fn emit_and_retrieve_single_event() {
        let env = setup();
        let actor = Address::generate(&env);
        let detail = Bytes::from_slice(&env, b"admin granted role to user");

        let seq = emit_audit_event(
            &env,
            actor.clone(),
            AuditEventType::RoleGranted,
            None,
            detail.clone(),
        );
        assert_eq!(seq, 1);

        let ev = get_audit_event(&env, seq).expect("event must be stored");
        assert_eq!(ev.seq, 1);
        assert_eq!(ev.actor, actor);
        assert_eq!(ev.event_type, AuditEventType::RoleGranted);
        assert_eq!(ev.detail, detail);
    }

    #[test]
    fn sequence_numbers_are_monotonically_increasing() {
        let env = setup();
        let actor = Address::generate(&env);

        for i in 1u64..=5 {
            let seq = emit_audit_event(
                &env,
                actor.clone(),
                AuditEventType::AdminAction,
                None,
                Bytes::from_slice(&env, b"action"),
            );
            assert_eq!(seq, i);
        }
        assert_eq!(audit_event_count(&env), 5);
    }

    #[test]
    fn actor_index_tracks_correct_events() {
        let env = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        emit_audit_event(&env, alice.clone(), AuditEventType::CredentialIssued, None, Bytes::from_slice(&env, b"c1"));
        emit_audit_event(&env, bob.clone(), AuditEventType::CredentialRevoked, None, Bytes::from_slice(&env, b"c2"));
        emit_audit_event(&env, alice.clone(), AuditEventType::DIDCreated, None, Bytes::from_slice(&env, b"c3"));

        let alice_seqs = get_events_by_actor(&env, alice);
        assert_eq!(alice_seqs.len(), 2);

        let bob_seqs = get_events_by_actor(&env, bob);
        assert_eq!(bob_seqs.len(), 1);
    }

    #[test]
    fn type_index_tracks_correct_events() {
        let env = setup();
        let actor = Address::generate(&env);

        emit_audit_event(&env, actor.clone(), AuditEventType::RoleGranted, None, Bytes::from_slice(&env, b"r1"));
        emit_audit_event(&env, actor.clone(), AuditEventType::RoleRevoked, None, Bytes::from_slice(&env, b"r2"));
        emit_audit_event(&env, actor.clone(), AuditEventType::RoleGranted, None, Bytes::from_slice(&env, b"r3"));

        let granted = get_events_by_type(&env, AuditEventType::RoleGranted);
        assert_eq!(granted.len(), 2);

        let revoked = get_events_by_type(&env, AuditEventType::RoleRevoked);
        assert_eq!(revoked.len(), 1);
    }

    #[test]
    fn pagination_returns_correct_pages() {
        let env = setup();
        let actor = Address::generate(&env);

        for _ in 0..15 {
            emit_audit_event(&env, actor.clone(), AuditEventType::AdminAction, None, Bytes::from_slice(&env, b"x"));
        }

        let page0 = get_audit_history(&env, 0, 10);
        assert_eq!(page0.len(), 10);

        let page1 = get_audit_history(&env, 1, 10);
        assert_eq!(page1.len(), 5);
    }

    #[test]
    fn resource_id_is_stored_and_retrieved() {
        let env = setup();
        let actor = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-abc-123");

        let seq = emit_audit_event(
            &env,
            actor,
            AuditEventType::CredentialRevoked,
            Some(cred_id.clone()),
            Bytes::from_slice(&env, b"expired"),
        );

        let ev = get_audit_event(&env, seq).unwrap();
        assert_eq!(ev.resource_id, Some(cred_id));
    }

    #[test]
    fn missing_event_returns_none() {
        let env = setup();
        assert!(get_audit_event(&env, 9999).is_none());
    }
}

