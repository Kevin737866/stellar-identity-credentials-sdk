//! Indexed event log with query and streaming support (#195).
//!
//! Contracts already emit Soroban events, but those are only consumable by an
//! off-chain indexer that replays the whole ledger. This module adds an
//! on-chain, append-only event log with secondary indexes so that historical
//! queries (audit trails, regulatory exports, monitoring) can be served
//! directly from contract state.
//!
//! # Indexes
//!
//! | Index            | Key                | Purpose                              |
//! |------------------|--------------------|--------------------------------------|
//! | primary          | `seq` (1-based)    | total ordering, cursor-based streaming|
//! | type             | event-type symbol  | "show me every revocation"           |
//! | actor            | `Address`          | "what did this address do?"          |
//! | subject          | `Address`          | "what happened *to* this address?"   |
//! | time window      | `ts / WINDOW_SECS` | bounded scan for time-range queries   |
//!
//! Each recorded event is *also* published as a real Soroban event with
//! `(type, actor, timestamp)` in the topic tuple so indexers can filter on
//! chain without scanning every diagnostic event.
//!
//! # Cost model
//!
//! `record_event` performs one write for the record plus one append per index
//! it populates (at most four). Batch callers should use
//! [`record_event_batch`] which stages the appends and flushes each index
//! exactly once.

use soroban_sdk::{contracttype, Address, Bytes, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of a time-window bucket, in seconds (5 minutes).
pub const WINDOW_SECS: u64 = 300;

/// Maximum number of events returned by a single query or stream page.
pub const MAX_PAGE_SIZE: u32 = 50;

/// Default page size when the caller passes `0`.
pub const DEFAULT_PAGE_SIZE: u32 = 10;

/// TTL for event log entries (in ledgers). ~1 year.
pub const EVENT_TTL_LEDGERS: u32 = 6_307_200;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum EvKey {
    /// Global monotonically increasing sequence counter.
    Counter,
    /// Event record at sequence `n`.
    Event(u64),
    /// Index: event-type symbol -> sequence numbers.
    TypeIndex(Symbol),
    /// Index: actor address -> sequence numbers.
    ActorIndex(Address),
    /// Index: subject address -> sequence numbers.
    SubjectIndex(Address),
    /// Index: time-window bucket -> sequence numbers.
    WindowIndex(u64),
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Every operation that is written to the indexed log.
///
/// The variants map 1:1 onto the lifecycle actions exposed by the contracts:
/// create, update, verify, revoke, and administrative mutations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexedEventType {
    CredentialCreated,
    CredentialVerified,
    CredentialRevoked,
    CredentialUpdated,
    CredentialExpired,
    DidCreated,
    DidUpdated,
    DidDeactivated,
    DelegationGranted,
    DelegationRevoked,
    SchemaRegistered,
    SchemaUpdated,
    StatusListCreated,
    StatusListEntrySet,
    SanctionsListUpdated,
    AddressSanctioned,
    AddressUnsanctioned,
    ReputationUpdated,
    ProofGenerated,
    ProofVerified,
    AdminOperation,
    RateLimitRejected,
    GarbageCollected,
}

/// A single immutable log entry.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EventRecord {
    /// Monotonically increasing sequence number (1-based).
    pub seq: u64,
    /// What happened.
    pub event_type: IndexedEventType,
    /// Who performed the action.
    pub actor: Address,
    /// Who or what the action targeted, when meaningful.
    pub subject: Option<Address>,
    /// Opaque resource identifier (credential id, DID string, ...).
    pub resource: Option<Bytes>,
    /// Type-specific payload; also the reason/detail for admin actions.
    pub data: Bytes,
    /// Ledger timestamp.
    pub timestamp: u64,
    /// Ledger sequence number, for deterministic ordering ties.
    pub ledger: u32,
}

/// Filter applied by [`query_events`]. Every field is an `Option`; `None`
/// means "do not constrain on this dimension".
///
/// `event_type` is the short symbol used in `IdentityEvent` topics (for
/// example `cred_revoked`), which is exactly the value an off-chain indexer
/// already sees, so client and chain agree on one vocabulary.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EventFilter {
    pub event_type: Option<Symbol>,
    pub actor: Option<Address>,
    pub subject: Option<Address>,
    /// Inclusive lower bound on `timestamp`.
    pub from_timestamp: Option<u64>,
    /// Inclusive upper bound on `timestamp`.
    pub to_timestamp: Option<u64>,
}

/// A page of query results plus the cursor needed to fetch the next page.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedEvents {
    pub data: Vec<EventRecord>,
    /// 0-based page index.
    pub page: u32,
    /// Effective page size after clamping.
    pub page_size: u32,
    /// Total number of records matching the filter.
    pub total: u32,
    /// True when at least one more record matches.
    pub has_more: bool,
    /// Sequence number to resume from; `None` when the result set is drained.
    pub next_cursor: Option<u64>,
}

/// A page produced by [`stream_events`], used for real-time consumers.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EventStreamPage {
    pub events: Vec<EventRecord>,
    /// Cursor to pass to the next `stream_events` call.
    pub next_cursor: Option<u64>,
    /// Sequence number of the newest event currently on-chain.
    pub head: u64,
    /// True once the stream has caught up with the head of the log.
    pub caught_up: bool,
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Stable, storage-cheap symbol for an event type.
///
/// This is the same value that appears in `IdentityEvent` topics and in the
/// type index, so clients can build an [`EventFilter`] from the vocabulary they
/// already observe off-chain.
pub fn type_symbol(env: &Env, et: &IndexedEventType) -> Symbol {
    let tag = match et {
        IndexedEventType::CredentialCreated => "cred_created",
        IndexedEventType::CredentialVerified => "cred_verified",
        IndexedEventType::CredentialRevoked => "cred_revoked",
        IndexedEventType::CredentialUpdated => "cred_updated",
        IndexedEventType::CredentialExpired => "cred_expired",
        IndexedEventType::DidCreated => "did_created",
        IndexedEventType::DidUpdated => "did_updated",
        IndexedEventType::DidDeactivated => "did_deactivated",
        IndexedEventType::DelegationGranted => "deleg_granted",
        IndexedEventType::DelegationRevoked => "deleg_revoked",
        IndexedEventType::SchemaRegistered => "schema_reg",
        IndexedEventType::SchemaUpdated => "schema_upd",
        IndexedEventType::StatusListCreated => "sl_created",
        IndexedEventType::StatusListEntrySet => "sl_entry_set",
        IndexedEventType::SanctionsListUpdated => "sanctions_upd",
        IndexedEventType::AddressSanctioned => "addr_sanctioned",
        IndexedEventType::AddressUnsanctioned => "addr_unsanctioned",
        IndexedEventType::ReputationUpdated => "rep_updated",
        IndexedEventType::ProofGenerated => "proof_generated",
        IndexedEventType::ProofVerified => "proof_verified",
        IndexedEventType::AdminOperation => "admin_op",
        IndexedEventType::RateLimitRejected => "ratelimit_hit",
        IndexedEventType::GarbageCollected => "gc_ran",
    };
    Symbol::new(env, tag)
}

fn current_head(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get::<_, u64>(&EvKey::Counter)
        .unwrap_or(0)
}

fn read_index(env: &Env, key: &EvKey) -> Vec<u64> {
    env.storage()
        .persistent()
        .get(key)
        .unwrap_or_else(|| Vec::new(env))
}

fn write_index(env: &Env, key: &EvKey, index: &Vec<u64>) {
    env.storage().persistent().set(key, index);
    env.storage()
        .persistent()
        .extend_ttl(key, EVENT_TTL_LEDGERS, EVENT_TTL_LEDGERS);
}

/// Append `seq` to a secondary index, skipping duplicates.
fn index_append(env: &Env, key: &EvKey, seq: u64) {
    let mut index = read_index(env, key);
    let already = index.iter().any(|s| s == seq);
    if !already {
        index.push_back(seq);
        write_index(env, key, &index);
    }
}

fn load_record(env: &Env, seq: u64) -> Option<EventRecord> {
    env.storage().persistent().get(&EvKey::Event(seq))
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// Which secondary index a pending append belongs to.
///
/// Modelled separately from [`EvKey`] so the batch writer can group pending
/// appends by index without building a key for every single entry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum IndexKind {
    Type(Symbol),
    Actor(Address),
    Subject(Address),
    Window(u64),
}

impl IndexKind {
    fn key(&self) -> EvKey {
        match self {
            IndexKind::Type(s) => EvKey::TypeIndex(s.clone()),
            IndexKind::Actor(a) => EvKey::ActorIndex(a.clone()),
            IndexKind::Subject(a) => EvKey::SubjectIndex(a.clone()),
            IndexKind::Window(w) => EvKey::WindowIndex(*w),
        }
    }
}

/// Append an event to the indexed log and publish it as a filterable Soroban
/// event. Returns the assigned sequence number.
///
/// Topics are `(IdentityEvent, <type>, <actor>, <timestamp>)` so off-chain
/// indexers can filter on type / actor / time without decoding the payload.
pub fn record_event(
    env: &Env,
    event_type: IndexedEventType,
    actor: Address,
    subject: Option<Address>,
    resource: Option<Bytes>,
    data: Bytes,
) -> u64 {
    let seq = current_head(env) + 1;
    env.storage().instance().set(&EvKey::Counter, &seq);

    let timestamp = env.ledger().timestamp();
    let record = EventRecord {
        seq,
        event_type: event_type.clone(),
        actor: actor.clone(),
        subject: subject.clone(),
        resource: resource.clone(),
        data,
        timestamp,
        ledger: env.ledger().sequence(),
    };

    env.storage().persistent().set(&EvKey::Event(seq), &record);
    env.storage()
        .persistent()
        .extend_ttl(&EvKey::Event(seq), EVENT_TTL_LEDGERS, EVENT_TTL_LEDGERS);

    index_append(env, &EvKey::TypeIndex(type_symbol(env, &event_type)), seq);
    index_append(env, &EvKey::ActorIndex(actor.clone()), seq);
    if let Some(ref s) = subject {
        index_append(env, &EvKey::SubjectIndex(s.clone()), seq);
    }
    index_append(env, &EvKey::WindowIndex(timestamp / WINDOW_SECS), seq);

    publish_indexed(env, &event_type, &actor, &record);

    seq
}

/// Publish the filterable Soroban event. Split out so [`record_event`] stays
/// short and so batch recorders can reuse the same topic layout.
fn publish_indexed(
    env: &Env,
    event_type: &IndexedEventType,
    actor: &Address,
    record: &EventRecord,
) {
    env.events().publish(
        (
            Symbol::new(env, "IdentityEvent"),
            type_symbol(env, event_type),
            actor.clone(),
            record.timestamp,
        ),
        (record.seq, record.subject.clone(), record.resource.clone()),
    );
}

/// Stage a batch of events for a single flush.
///
/// Returns an *empty* writer; queue one [`EventBatchWriter::push`] per event.
/// `flush` writes them all and touches each secondary index once, which is what
/// makes batch operations materially cheaper than calling [`record_event`] in a
/// loop.
pub fn record_event_batch(env: &Env) -> EventBatchWriter {
    EventBatchWriter::new(env)
}

/// Accumulates events so each storage index is written exactly once per batch.
pub struct EventBatchWriter {
    records: Vec<EventRecord>,
}

impl EventBatchWriter {
    fn new(env: &Env) -> Self {
        EventBatchWriter {
            records: Vec::new(env),
        }
    }

    /// Queue another event. Sequence numbers are assigned eagerly in ledger
    /// order, so a batch always produces a dense, correctly ordered range.
    pub fn push(
        &mut self,
        env: &Env,
        event_type: IndexedEventType,
        actor: Address,
        subject: Option<Address>,
        resource: Option<Bytes>,
        data: Bytes,
    ) {
        let seq = match self.records.last() {
            Some(last) => last.seq + 1,
            None => current_head(env) + 1,
        };
        let record = EventRecord {
            seq,
            event_type,
            actor,
            subject,
            resource,
            data,
            timestamp: env.ledger().timestamp(),
            ledger: env.ledger().sequence(),
        };
        self.records.push_back(record);
    }

    /// Number of staged records.
    pub fn len(&self) -> u32 {
        self.records.len()
    }

    /// True when nothing is staged.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Write every staged record to persistent storage, appending to each
    /// secondary index in a single read-modify-write pass.
    pub fn flush(self, env: &Env) -> Vec<EventRecord> {
        let mut head = current_head(env);
        let mut pending: Vec<(IndexKind, u64)> = Vec::new(env);

        for record in self.records.iter() {
            head = core::cmp::max(head, record.seq);
            env.storage()
                .persistent()
                .set(&EvKey::Event(record.seq), &record);
            env.storage().persistent().extend_ttl(
                &EvKey::Event(record.seq),
                EVENT_TTL_LEDGERS,
                EVENT_TTL_LEDGERS,
            );
            pending.push_back((
                IndexKind::Type(type_symbol(env, &record.event_type)),
                record.seq,
            ));
            pending.push_back((IndexKind::Actor(record.actor.clone()), record.seq));
            if let Some(ref s) = record.subject {
                pending.push_back((IndexKind::Subject(s.clone()), record.seq));
            }
            pending.push_back((
                IndexKind::Window(record.timestamp / WINDOW_SECS),
                record.seq,
            ));
            publish_indexed(env, &record.event_type, &record.actor, &record);
        }

        env.storage().instance().set(&EvKey::Counter, &head);
        merge_index(env, pending);

        self.records
    }
}

/// Group pending appends by index and apply each group with exactly one
/// read-modify-write, turning `O(n)` storage operations into `O(k)` where
/// `k` is the number of distinct indexes touched by the batch.
fn merge_index(env: &Env, pending: Vec<(IndexKind, u64)>) {
    if pending.is_empty() {
        return;
    }

    let mut groups: Vec<(IndexKind, Vec<u64>)> = Vec::new(env);
    for (kind, seq) in pending.iter() {
        match groups.iter().position(|(k, _)| k == kind) {
            Some(pos) => {
                let slot = pos as u32;
                let mut list = groups.get(slot).unwrap().1;
                list.push_back(seq);
                groups.set(slot, (kind.clone(), list));
            }
            None => {
                let mut list = Vec::new(env);
                list.push_back(seq);
                groups.push_back((kind.clone(), list));
            }
        }
    }

    for (kind, list) in groups.iter() {
        let key = kind.key();
        let mut existing = read_index(env, &key);
        existing.append(&list);
        write_index(env, &key, &existing);
    }
}

// ---------------------------------------------------------------------------
// Querying
// ---------------------------------------------------------------------------

/// Query the log with an optional filter, offset pagination and a cursor for
/// resuming.
///
/// The candidate set is taken from the most selective available index so the
/// scan cost stays proportional to the number of matches rather than the total
/// size of the log.
pub fn query_events(env: &Env, filter: EventFilter, page: u32, page_size: u32) -> PaginatedEvents {
    let size = clamp_page_size(page_size);
    let candidates = candidate_seqs(env, &filter);
    let matched = matching_seqs(env, &candidates, &filter);
    let total = matched.len() as u64;
    let start = core::cmp::min((page as u64) * (size as u64), total);
    let end = core::cmp::min(start + size as u64, total);

    let mut data = Vec::new(env);
    let mut last_seq: u64 = 0;
    let mut i = start;
    while i < end {
        if let Some(seq) = matched.get(i as u32) {
            if let Some(rec) = load_record(env, seq) {
                last_seq = rec.seq;
                data.push_back(rec);
            }
        }
        i += 1;
    }

    let has_more = end < total;
    PaginatedEvents {
        data,
        page,
        page_size: size,
        total: total as u32,
        has_more,
        next_cursor: if has_more { Some(last_seq) } else { None },
    }
}

fn clamp_page_size(page_size: u32) -> u32 {
    if page_size == 0 {
        DEFAULT_PAGE_SIZE
    } else if page_size > MAX_PAGE_SIZE {
        MAX_PAGE_SIZE
    } else {
        page_size
    }
}

/// Select the most selective index available for this filter.
fn candidate_seqs(env: &Env, filter: &EventFilter) -> Vec<u64> {
    if let Some(ref sym) = filter.event_type {
        return read_index(env, &EvKey::TypeIndex(sym.clone()));
    }
    if let Some(ref s) = filter.subject {
        return read_index(env, &EvKey::SubjectIndex(s.clone()));
    }
    if let Some(ref a) = filter.actor {
        return read_index(env, &EvKey::ActorIndex(a.clone()));
    }
    if let Some(from) = filter.from_timestamp {
        if let Some(to) = filter.to_timestamp {
            return window_seqs(env, from, to);
        }
    }
    let head = current_head(env);
    let mut all = Vec::new(env);
    let mut i = 1u64;
    while i <= head {
        all.push_back(i);
        i += 1;
    }
    all
}

/// Union of every time window overlapping `[from, to]`.
///
/// Sequence numbers are already strictly increasing and each event belongs to
/// exactly one window, so concatenating the windows in ascending order yields a
/// sorted, duplicate-free candidate list with no extra pass required.
fn window_seqs(env: &Env, from: u64, to: u64) -> Vec<u64> {
    if to < from {
        return Vec::new(env);
    }
    let first = from / WINDOW_SECS;
    let last = to / WINDOW_SECS;
    let mut out = Vec::new(env);
    let mut w = first;
    while w <= last {
        out.append(&read_index(env, &EvKey::WindowIndex(w)));
        w += 1;
    }
    out
}

/// Apply the non-indexed filter dimensions and drop missing records.
fn matching_seqs(env: &Env, candidates: &Vec<u64>, filter: &EventFilter) -> Vec<u64> {
    let mut out = Vec::new(env);
    for seq in candidates.iter() {
        if let Some(rec) = load_record(env, seq) {
            if matches_filter(env, &rec, filter) {
                out.push_back(seq);
            }
        }
    }
    out
}

fn matches_filter(env: &Env, rec: &EventRecord, filter: &EventFilter) -> bool {
    if let Some(ref sym) = filter.event_type {
        if type_symbol(env, &rec.event_type) != *sym {
            return false;
        }
    }
    if let Some(ref a) = filter.actor {
        if &rec.actor != a {
            return false;
        }
    }
    if let Some(ref s) = filter.subject {
        match rec.subject {
            Some(ref actual) => {
                if actual != s {
                    return false;
                }
            }
            None => return false,
        }
    }
    if let Some(from) = filter.from_timestamp {
        if rec.timestamp < from {
            return false;
        }
    }
    if let Some(to) = filter.to_timestamp {
        if rec.timestamp > to {
            return false;
        }
    }
    true
}

/// Cursor-based read for real-time consumers.
///
/// `cursor` is the last sequence number the consumer has already processed
/// (pass `None` on the first call). The returned page is strictly greater than
/// `cursor`, and `next_cursor` is `Some` only while more events remain — a
/// consumer that receives `next_cursor == None` has fully drained the log and
/// can poll again from the returned page's last sequence number.
pub fn stream_events(env: &Env, cursor: Option<u64>, limit: u32) -> EventStreamPage {
    let head = current_head(env);
    let size = clamp_page_size(limit);
    let from = cursor.unwrap_or(0);

    let mut events = Vec::new(env);
    let mut seq = from + 1;
    while seq <= head && events.len() < size {
        if let Some(rec) = load_record(env, seq) {
            events.push_back(rec);
        }
        seq += 1;
    }

    let consumed_through = if events.is_empty() { from } else { seq - 1 };
    let caught_up = consumed_through >= head;
    let next_cursor = if caught_up {
        None
    } else {
        Some(consumed_through)
    };

    EventStreamPage {
        events,
        next_cursor,
        head,
        caught_up,
    }
}

/// Read a single record by sequence number.
pub fn get_event(env: &Env, seq: u64) -> Option<EventRecord> {
    load_record(env, seq)
}

/// Sequence number of the newest event on-chain.
pub fn event_head(env: &Env) -> u64 {
    current_head(env)
}

/// Total number of events recorded.
pub fn event_count(env: &Env) -> u64 {
    current_head(env)
}

/// All sequence numbers attributed to an actor, oldest first.
pub fn events_by_actor(env: &Env, actor: Address) -> Vec<u64> {
    read_index(env, &EvKey::ActorIndex(actor))
}

/// All sequence numbers attributed to a subject, oldest first.
pub fn events_by_subject(env: &Env, subject: Address) -> Vec<u64> {
    read_index(env, &EvKey::SubjectIndex(subject))
}

/// All sequence numbers of a given type, oldest first.
pub fn events_by_type(env: &Env, event_type: IndexedEventType) -> Vec<u64> {
    read_index(env, &EvKey::TypeIndex(type_symbol(env, &event_type)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl, testutils::Address as _, testutils::Events, testutils::Ledger,
        testutils::LedgerInfo, TryFromVal,
    };

    /// Minimal host contract. Instance storage is only reachable from inside a
    /// contract frame, so tests register this and run their body with
    /// [`Env::as_contract`].
    #[contract]
    pub struct EventLogHost;

    #[contractimpl]
    impl EventLogHost {
        pub fn noop() {}
    }

    struct Harness {
        env: Env,
        host: Address,
    }

    impl Harness {
        fn new() -> Self {
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
            let host = env.register(EventLogHost, ());
            Harness { env, host }
        }

        /// Run `body` inside the host contract's frame.
        fn run<R>(&self, body: impl FnOnce() -> R) -> R {
            self.env.as_contract(&self.host, body)
        }

        /// Advance ledger time without leaving the contract frame.
        fn advance(&self, secs: u64) {
            let mut info = self.env.ledger().get();
            info.timestamp += secs;
            self.env.ledger().set(info);
        }
    }

    fn no_filter() -> EventFilter {
        EventFilter {
            event_type: None,
            actor: None,
            subject: None,
            from_timestamp: None,
            to_timestamp: None,
        }
    }

    fn record(h: &Harness, et: IndexedEventType, actor: &Address, subject: &Address) -> u64 {
        record_event(
            &h.env,
            et,
            actor.clone(),
            Some(subject.clone()),
            Some(Bytes::from_slice(&h.env, b"res")),
            Bytes::from_slice(&h.env, b"payload"),
        )
    }

    #[test]
    fn sequence_numbers_start_at_one_and_increment() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            assert_eq!(record(&h, IndexedEventType::CredentialCreated, &a, &b), 1);
            assert_eq!(record(&h, IndexedEventType::CredentialRevoked, &a, &b), 2);
            assert_eq!(event_head(&h.env), 2);
            assert_eq!(event_count(&h.env), 2);
        });
    }

    #[test]
    fn record_is_retrievable_by_sequence() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            let seq = record(&h, IndexedEventType::DidCreated, &a, &b);
            let rec = get_event(&h.env, seq).expect("record must exist");
            assert_eq!(rec.seq, seq);
            assert_eq!(rec.event_type, IndexedEventType::DidCreated);
            assert_eq!(rec.actor, a);
            assert_eq!(rec.subject, Some(b));
        });
    }

    #[test]
    fn type_index_filters_by_event_type() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            record(&h, IndexedEventType::CredentialCreated, &a, &b);
            record(&h, IndexedEventType::CredentialRevoked, &a, &b);
            record(&h, IndexedEventType::CredentialRevoked, &a, &b);

            let revoked = events_by_type(&h.env, IndexedEventType::CredentialRevoked);
            assert_eq!(revoked.len(), 2);

            let mut filter = no_filter();
            filter.event_type = Some(type_symbol(&h.env, &IndexedEventType::CredentialCreated));
            let page = query_events(&h.env, filter, 0, 10);
            assert_eq!(page.total, 1);
        });
    }

    #[test]
    fn actor_and_subject_indexes_are_populated() {
        let h = Harness::new();
        h.run(|| {
            let alice = Address::generate(&h.env);
            let bob = Address::generate(&h.env);

            record(&h, IndexedEventType::CredentialCreated, &alice, &bob);
            record(&h, IndexedEventType::CredentialRevoked, &bob, &alice);

            assert_eq!(events_by_actor(&h.env, alice.clone()).len(), 1);
            assert_eq!(events_by_actor(&h.env, bob.clone()).len(), 1);
            assert_eq!(events_by_subject(&h.env, bob.clone()).len(), 1);
            assert_eq!(events_by_subject(&h.env, alice.clone()).len(), 1);
        });
    }

    #[test]
    fn time_range_filter_excludes_out_of_range() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);

            record(&h, IndexedEventType::CredentialCreated, &a, &b);
            h.advance(WINDOW_SECS * 3);
            let t1 = h.env.ledger().timestamp();
            record(&h, IndexedEventType::CredentialRevoked, &a, &b);

            let mut filter = no_filter();
            filter.from_timestamp = Some(t1);
            let page = query_events(&h.env, filter, 0, 10);
            assert_eq!(page.total, 1);
            assert_eq!(
                page.data.get(0).unwrap().event_type,
                IndexedEventType::CredentialRevoked
            );
        });
    }

    #[test]
    fn combined_filters_are_conjunctive() {
        let h = Harness::new();
        h.run(|| {
            let alice = Address::generate(&h.env);
            let bob = Address::generate(&h.env);
            let carol = Address::generate(&h.env);

            record(&h, IndexedEventType::CredentialCreated, &alice, &bob);
            record(&h, IndexedEventType::CredentialCreated, &alice, &carol);
            record(&h, IndexedEventType::CredentialRevoked, &alice, &bob);

            let mut filter = no_filter();
            filter.event_type = Some(type_symbol(&h.env, &IndexedEventType::CredentialCreated));
            filter.actor = Some(alice.clone());
            filter.subject = Some(bob.clone());

            let page = query_events(&h.env, filter, 0, 10);
            assert_eq!(page.total, 1);
        });
    }

    #[test]
    fn pagination_walks_the_whole_result_set() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            for _ in 0..25 {
                record(&h, IndexedEventType::CredentialCreated, &a, &b);
            }

            let p0 = query_events(&h.env, no_filter(), 0, 10);
            assert_eq!(p0.data.len(), 10);
            assert_eq!(p0.total, 25);
            assert!(p0.has_more);
            assert!(p0.next_cursor.is_some());

            let p1 = query_events(&h.env, no_filter(), 1, 10);
            assert_eq!(p1.data.len(), 10);

            let p2 = query_events(&h.env, no_filter(), 2, 10);
            assert_eq!(p2.data.len(), 5);
            assert!(!p2.has_more);
            assert!(p2.next_cursor.is_none());
        });
    }

    #[test]
    fn page_size_is_clamped() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            for _ in 0..60 {
                record(&h, IndexedEventType::CredentialCreated, &a, &b);
            }
            let big = query_events(&h.env, no_filter(), 0, 1_000);
            assert_eq!(big.page_size, MAX_PAGE_SIZE);
            assert_eq!(big.data.len(), MAX_PAGE_SIZE);

            let zero = query_events(&h.env, no_filter(), 0, 0);
            assert_eq!(zero.page_size, DEFAULT_PAGE_SIZE);
        });
    }

    #[test]
    fn out_of_bounds_page_returns_empty_but_reports_total() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            record(&h, IndexedEventType::CredentialCreated, &a, &b);
            let page = query_events(&h.env, no_filter(), 9, 10);
            assert!(page.data.is_empty());
            assert_eq!(page.total, 1);
            assert!(!page.has_more);
        });
    }

    #[test]
    fn stream_returns_events_after_cursor() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            for _ in 0..5 {
                record(&h, IndexedEventType::CredentialCreated, &a, &b);
            }

            let first = stream_events(&h.env, None, 2);
            assert_eq!(first.events.len(), 2);
            assert_eq!(first.events.get(0).unwrap().seq, 1);
            assert_eq!(first.events.get(1).unwrap().seq, 2);
            assert_eq!(first.head, 5);
            assert!(!first.caught_up);
            assert_eq!(first.next_cursor, Some(2));

            let second = stream_events(&h.env, first.next_cursor, 2);
            assert_eq!(second.events.get(0).unwrap().seq, 3);

            let third = stream_events(&h.env, second.next_cursor, 10);
            assert_eq!(third.events.len(), 1);
            assert!(third.caught_up);
            assert!(third.next_cursor.is_none());
        });
    }

    #[test]
    fn streaming_an_empty_log_yields_nothing() {
        let h = Harness::new();
        h.run(|| {
            let page = stream_events(&h.env, None, 10);
            assert!(page.events.is_empty());
            assert!(page.caught_up);
            assert_eq!(page.head, 0);
        });
    }

    #[test]
    fn batch_writer_produces_contiguous_sequence_numbers() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);

            let mut writer = record_event_batch(&h.env);
            assert!(writer.is_empty());

            writer.push(
                &h.env,
                IndexedEventType::CredentialCreated,
                a.clone(),
                Some(b.clone()),
                None,
                Bytes::from_slice(&h.env, b"0"),
            );
            writer.push(
                &h.env,
                IndexedEventType::CredentialCreated,
                a.clone(),
                Some(b.clone()),
                None,
                Bytes::from_slice(&h.env, b"1"),
            );
            writer.push(
                &h.env,
                IndexedEventType::CredentialRevoked,
                a.clone(),
                Some(b.clone()),
                None,
                Bytes::from_slice(&h.env, b"2"),
            );
            assert_eq!(writer.len(), 3);
            assert!(!writer.is_empty());

            let flushed = writer.flush(&h.env);
            assert_eq!(flushed.len(), 3);
            assert_eq!(flushed.get(0).unwrap().seq, 1);
            assert_eq!(flushed.get(2).unwrap().seq, 3);
            assert_eq!(event_head(&h.env), 3);
            assert_eq!(
                events_by_type(&h.env, IndexedEventType::CredentialCreated).len(),
                2
            );
        });
    }

    #[test]
    fn batch_writer_continues_after_existing_events() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            record(&h, IndexedEventType::DidCreated, &a, &b);

            let mut writer = record_event_batch(&h.env);
            writer.push(
                &h.env,
                IndexedEventType::CredentialCreated,
                a,
                Some(b.clone()),
                None,
                Bytes::new(&h.env),
            );
            writer.push(
                &h.env,
                IndexedEventType::CredentialCreated,
                b.clone(),
                Some(b),
                None,
                Bytes::new(&h.env),
            );
            writer.flush(&h.env);

            assert_eq!(event_head(&h.env), 3);
            assert_eq!(get_event(&h.env, 3).unwrap().seq, 3);
        });
    }

    #[test]
    fn indexed_event_is_published_with_filterable_topics() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            record(&h, IndexedEventType::SanctionsListUpdated, &a, &b);

            let symbol = Symbol::new(&h.env, "IdentityEvent");
            let found = h.env.events().all().iter().any(|(_c, topics, _d)| {
                topics.iter().any(|t| {
                    Symbol::try_from_val(&h.env, &t)
                        .map(|s| s == symbol)
                        .unwrap_or(false)
                })
            });
            assert!(
                found,
                "IdentityEvent must be published with indexable topics"
            );
        });
    }

    #[test]
    fn unknown_sequence_returns_none() {
        let h = Harness::new();
        h.run(|| assert!(get_event(&h.env, 4_242).is_none()));
    }

    #[test]
    fn inverted_time_range_returns_nothing() {
        let h = Harness::new();
        h.run(|| {
            let a = Address::generate(&h.env);
            let b = Address::generate(&h.env);
            record(&h, IndexedEventType::CredentialCreated, &a, &b);

            let mut filter = no_filter();
            filter.from_timestamp = Some(h.env.ledger().timestamp() + 1_000);
            filter.to_timestamp = Some(h.env.ledger().timestamp());
            let page = query_events(&h.env, filter, 0, 10);
            assert_eq!(page.total, 0);
        });
    }
}
