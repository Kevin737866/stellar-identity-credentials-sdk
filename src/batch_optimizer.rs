//! Batch storage access patterns (#197).
//!
//! Soroban charges per storage operation, so the dominant cost of a batch loop
//! is the *number* of reads and writes, not the amount of data moved. The
//! naive pattern
//!
//! ```text
//! for item in items:
//!     vec = storage.get(key)      # read
//!     vec.push(item)
//!     storage.set(key, vec)      # write
//! ```
//!
//! performs `2n` storage operations for `n` items that all target the *same*
//! key, and it re-serialises an ever-growing vector on every iteration.
//!
//! This module provides the two accumulators that fix both problems:
//!
//! - [`IndexAppender`] — coalesces appends to any number of index vectors so
//!   each vector is read once and written once per batch.
//! - [`EntryCache`] — memoises point lookups so a batch that touches the same
//!   record repeatedly (duplicate ids, overlapping retries, a record and its
//!   status) pays for the read once.
//!
//! Both are plain Rust values backed by the SDK's `Vec`, so the extra
//! bookkeeping is a handful of in-memory comparisons — far cheaper than the
//! storage operations it removes.
//!
//! # Expected effect
//!
//! For a batch of `n` items against `k` distinct index keys the index-vector
//! operation count drops from `2n` to `2k`. With `n = 50` and `k = 2` (one
//! issuer, one subject) that is 100 storage operations down to 4. See
//! `docs/gas-benchmarks-batch.md` for the full before/after analysis.
//!
//! The read/write closures keep this module contract-agnostic: each contract
//! supplies its own key encoding, so the same accumulator serves the issuer,
//! status-list, compliance and reputation contracts.

use soroban_sdk::{contracttype, Address, Bytes, Env, Vec};

/// Maximum number of distinct keys a single [`IndexAppender`] will track.
///
/// Bounds the host-memory footprint of one transaction. Beyond this the
/// accumulator reports failure and the caller falls back to the naive path.
pub const MAX_TRACKED_KEYS: u32 = 64;

/// Which persisted index vector an append targets.
///
/// The variants are deliberately contract-agnostic; a contract maps a variant
/// onto its own storage key inside the read/write closures it supplies.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexKey {
    /// Per-issuer index (e.g. credential ids issued by an issuer).
    Issuer(Address),
    /// Per-subject index (e.g. credential ids held by a subject).
    Subject(Address),
    /// Generic address-keyed index.
    Address(Address),
    /// Generic byte-keyed index.
    Bytes(Bytes),
}

/// Read a persisted index vector. Pure; may be called once per tracked key.
///
/// Lifetime-parameterised because a bare `dyn Fn(..)` alias would imply
/// `'static` and reject the non-`'static` closures a contract naturally builds.
pub type IndexReader<'a> = &'a mut dyn Fn(&Env, &IndexKey) -> Vec<Bytes>;

/// Persist an index vector. Called at most once per tracked key.
pub type IndexWriter<'a> = &'a mut dyn Fn(&Env, &IndexKey, &Vec<Bytes>);

// ---------------------------------------------------------------------------
// IndexAppender
// ---------------------------------------------------------------------------

/// Accumulates appends across a batch and writes each target vector once.
///
/// ```ignore
/// let mut w = IndexAppender::new(&env);
/// for item in items.iter() {
///     w.append(&env, &IndexKey::Issuer(issuer.clone()), &cred_id, &read);
///     w.append(&env, &IndexKey::Subject(item.subject.clone()), &cred_id, &read);
/// }
/// w.flush(&env, &write);   // 2 reads + 2 writes total, regardless of batch size
/// ```
pub struct IndexAppender {
    keys: Vec<IndexKey>,
    values: Vec<Vec<Bytes>>,
    dirty: Vec<bool>,
}

impl IndexAppender {
    /// Create an empty appender.
    pub fn new(env: &Env) -> Self {
        IndexAppender {
            keys: Vec::new(env),
            values: Vec::new(env),
            dirty: Vec::new(env),
        }
    }

    /// Number of distinct keys currently tracked.
    pub fn len(&self) -> u32 {
        self.keys.len()
    }

    /// True when nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn position(&self, key: &IndexKey) -> Option<u32> {
        self.keys.iter().position(|k| k == *key).map(|p| p as u32)
    }

    /// Append `value` to the vector for `key`.
    ///
    /// The vector is read at most once for the whole batch and written at most
    /// once on [`IndexAppender::flush`]. Returns `false` when the tracking
    /// budget is exhausted, telling the caller to fall back to a direct
    /// read-modify-write for this item.
    pub fn append(
        &mut self,
        env: &Env,
        key: &IndexKey,
        value: &Bytes,
        read: IndexReader<'_>,
    ) -> bool {
        let slot = match self.position(key) {
            Some(pos) => pos,
            None => {
                if self.keys.len() >= MAX_TRACKED_KEYS {
                    return false;
                }
                let slot = self.keys.len();
                self.keys.push_back(key.clone());
                self.values.push_back(read(env, key));
                self.dirty.push_back(false);
                slot
            }
        };

        let mut current = self.values.get(slot).unwrap();
        if current.iter().any(|v| v == *value) {
            return true;
        }
        current.push_back(value.clone());
        self.values.set(slot, current);
        self.dirty.set(slot, true);
        true
    }

    /// Read the in-memory copy of a tracked key, if it is tracked.
    pub fn peek(&self, key: &IndexKey) -> Option<Vec<Bytes>> {
        self.position(key).map(|pos| self.values.get(pos).unwrap())
    }

    /// Write every dirty vector. Each key costs exactly one write no matter how
    /// many items were appended to it. Returns the number of writes performed.
    pub fn flush(&self, env: &Env, write: IndexWriter<'_>) -> u32 {
        let mut writes = 0u32;
        for i in 0..self.keys.len() {
            if !self.dirty.get(i).unwrap_or(false) {
                continue;
            }
            write(
                env,
                &self.keys.get(i).unwrap(),
                &self.values.get(i).unwrap(),
            );
            writes += 1;
        }
        writes
    }
}

// ---------------------------------------------------------------------------
// EntryCache
// ---------------------------------------------------------------------------

/// Memoises point lookups for the duration of a batch.
///
/// ```ignore
/// let mut cache = EntryCache::new(&env);
/// let (found, value) = cache.get_or(&env, &key, &load);
/// cache.put(&key, &updated);
/// cache.flush(&store, &remove);
/// ```
pub struct EntryCache {
    keys: Vec<Bytes>,
    present: Vec<bool>,
    values: Vec<Bytes>,
    dirty: Vec<bool>,
}

impl EntryCache {
    /// Create an empty cache.
    pub fn new(env: &Env) -> Self {
        EntryCache {
            keys: Vec::new(env),
            present: Vec::new(env),
            values: Vec::new(env),
            dirty: Vec::new(env),
        }
    }

    /// Number of distinct keys cached.
    pub fn len(&self) -> u32 {
        self.keys.len()
    }

    /// True when nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn position(&self, key: &Bytes) -> Option<u32> {
        self.keys.iter().position(|k| k == *key).map(|p| p as u32)
    }

    /// Fetch `key` through the cache. `load` runs at most once per key.
    ///
    /// Returns `(found, value)`. For a miss the value is empty.
    pub fn get_or(
        &mut self,
        env: &Env,
        key: &Bytes,
        load: &mut dyn Fn(&Env, &Bytes) -> Option<Bytes>,
    ) -> (bool, Bytes) {
        if let Some(pos) = self.position(key) {
            let present = self.present.get(pos).unwrap_or(false);
            return (present, self.values.get(pos).unwrap());
        }
        let loaded = load(env, key);
        let (present, value) = match loaded {
            Some(v) => (true, v),
            None => (false, Bytes::new(env)),
        };
        self.keys.push_back(key.clone());
        self.present.push_back(present);
        self.values.push_back(value.clone());
        self.dirty.push_back(false);
        (present, value)
    }

    /// Record a mutation for `key`, which must already be cached (call
    /// [`EntryCache::get_or`] first). Written back on flush.
    pub fn put(&mut self, key: &Bytes, value: &Bytes) {
        if let Some(pos) = self.position(key) {
            self.values.set(pos, value.clone());
            self.present.set(pos, true);
            self.dirty.set(pos, true);
        }
    }

    /// Mark `key` as deleted. Subsequent [`EntryCache::get_or`] calls report a
    /// miss and flush issues a removal instead of a write.
    pub fn delete(&mut self, key: &Bytes) {
        if let Some(pos) = self.position(key) {
            self.present.set(pos, false);
            self.dirty.set(pos, true);
        }
    }

    /// Whether `key` is currently known to be absent.
    pub fn is_deleted(&self, key: &Bytes) -> bool {
        match self.position(key) {
            Some(pos) => {
                self.dirty.get(pos).unwrap_or(false) && !self.present.get(pos).unwrap_or(true)
            }
            None => false,
        }
    }

    /// Write back every mutated entry. Returns the number of write operations
    /// issued (an entry mutated `k` times still costs exactly one write).
    pub fn flush(&self, store: &mut dyn Fn(&Bytes, &Bytes), remove: &mut dyn Fn(&Bytes)) -> u32 {
        let mut writes = 0u32;
        for i in 0..self.keys.len() {
            if !self.dirty.get(i).unwrap_or(false) {
                continue;
            }
            let key = self.keys.get(i).unwrap();
            if self.present.get(i).unwrap_or(false) {
                store(&key, &self.values.get(i).unwrap());
            } else {
                remove(&key);
            }
            writes += 1;
        }
        writes
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::xdr::ToXdr;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger, testutils::LedgerInfo, Env};
    use std::cell::RefCell;
    use std::rc::Rc;

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

    fn b(env: &Env, s: &str) -> Bytes {
        Bytes::from_slice(env, s.as_bytes())
    }

    /// In-memory stand-in for persistent storage, with read/write counters so
    /// the tests can assert on operation counts.
    ///
    /// Shared behind `Rc<RefCell<..>>` because the reader and writer closures
    /// handed to the accumulators both need access to the same store.
    struct Store {
        data: Vec<(Bytes, Vec<Bytes>)>,
        reads: u32,
        writes: u32,
    }

    impl Store {
        fn new(env: &Env) -> Self {
            Store {
                data: Vec::new(env),
                reads: 0,
                writes: 0,
            }
        }

        fn read(&mut self, env: &Env, key: &Bytes) -> Vec<Bytes> {
            self.reads += 1;
            match self.data.iter().position(|(k, _)| k == *key) {
                Some(pos) => self.data.get(pos as u32).unwrap().1,
                None => Vec::new(env),
            }
        }

        /// Read without counting (and without needing &mut self).
        fn peek(&self, env: &Env, key: &Bytes) -> Vec<Bytes> {
            match self.data.iter().position(|(k, _)| k == *key) {
                Some(pos) => self.data.get(pos as u32).unwrap().1,
                None => Vec::new(env),
            }
        }

        fn write(&mut self, key: &Bytes, value: &Vec<Bytes>) {
            self.writes += 1;
            match self.data.iter().position(|(k, _)| k == *key) {
                Some(pos) => self.data.set(pos as u32, (key.clone(), value.clone())),
                None => self.data.push_back((key.clone(), value.clone())),
            }
        }

        fn ops(&self) -> u32 {
            self.reads + self.writes
        }
    }

    type SharedStore = Rc<RefCell<Store>>;

    fn new_store(env: &Env) -> SharedStore {
        Rc::new(RefCell::new(Store::new(env)))
    }

    /// Reader closure over a store whose keys are the raw byte form of the
    /// `IndexKey`, mirroring how a contract would encode its storage key.
    fn reader_for(store: &SharedStore) -> Box<dyn Fn(&Env, &IndexKey) -> Vec<Bytes> + '_> {
        Box::new(move |env, key| {
            let bytes = match key {
                IndexKey::Issuer(a) | IndexKey::Subject(a) | IndexKey::Address(a) => {
                    a.clone().to_xdr(env)
                }
                IndexKey::Bytes(x) => x.clone(),
            };
            store.borrow_mut().read(env, &bytes)
        })
    }

    fn writer_for(store: &SharedStore) -> Box<dyn Fn(&Env, &IndexKey, &Vec<Bytes>) + '_> {
        Box::new(move |env, key, value| {
            let bytes = match key {
                IndexKey::Issuer(a) | IndexKey::Subject(a) | IndexKey::Address(a) => {
                    a.clone().to_xdr(env)
                }
                IndexKey::Bytes(x) => x.clone(),
            };
            store.borrow_mut().write(&bytes, value);
        })
    }

    // ── IndexAppender ───────────────────────────────────────────────────

    #[test]
    fn appender_coalesces_appends_to_one_key() {
        let env = setup();
        let store = new_store(&env);

        let mut appender = IndexAppender::new(&env);
        {
            let mut reader = reader_for(&store);
            let mut writer = writer_for(&store);
            for i in 0..10u32 {
                let value = b(&env, &format!("cred-{}", i));
                assert!(appender.append(
                    &env,
                    &IndexKey::Bytes(b(&env, "idx")),
                    &value,
                    &mut reader
                ));
            }
            assert_eq!(appender.flush(&env, &mut writer), 1);
        }

        {
            let store = store.borrow();
            assert_eq!(store.writes, 1);
            assert_eq!(store.reads, 1, "index vector must be read exactly once");
        }
        assert_eq!(store.borrow().peek(&env, &b(&env, "idx")).len(), 10);
    }

    #[test]
    fn naive_loop_costs_one_write_per_item_where_appender_costs_one_total() {
        let env = setup();
        let naive = new_store(&env);
        for i in 0..10u32 {
            let key = b(&env, "idx");
            let current = {
                let mut guard = naive.borrow_mut();
                let mut current = guard.read(&env, &key);
                current.push_back(b(&env, &format!("cred-{}", i)));
                guard.write(&key, &current);
                current
            };
            let _ = current;
        }
        assert_eq!(
            naive.borrow().ops(),
            20,
            "the naive loop costs 2 ops per item"
        );

        let store = new_store(&env);
        let mut appender = IndexAppender::new(&env);
        {
            let mut reader = reader_for(&store);
            let mut writer = writer_for(&store);
            for i in 0..10u32 {
                let value = b(&env, &format!("cred-{}", i));
                appender.append(&env, &IndexKey::Bytes(b(&env, "idx")), &value, &mut reader);
            }
            appender.flush(&env, &mut writer);
        }
        assert_eq!(
            store.borrow().ops(),
            2,
            "10 items must cost 1 read + 1 write"
        );
    }

    #[test]
    fn appender_handles_multiple_distinct_keys() {
        let env = setup();
        let a = Address::generate(&env);
        let c = Address::generate(&env);
        let store = new_store(&env);
        let mut reader = reader_for(&store);
        let mut writer = writer_for(&store);

        let mut appender = IndexAppender::new(&env);
        appender.append(
            &env,
            &IndexKey::Issuer(a.clone()),
            &b(&env, "x1"),
            &mut reader,
        );
        appender.append(
            &env,
            &IndexKey::Subject(a.clone()),
            &b(&env, "x1"),
            &mut reader,
        );
        appender.append(
            &env,
            &IndexKey::Issuer(c.clone()),
            &b(&env, "x2"),
            &mut reader,
        );

        assert_eq!(appender.len(), 3);
        assert_eq!(appender.flush(&env, &mut writer), 3);
        assert_eq!(store.borrow().reads, 3, "one read per distinct key");
        assert_eq!(store.borrow().writes, 3);
    }

    #[test]
    fn appender_preserves_insertion_order() {
        let env = setup();
        let store = new_store(&env);
        let mut reader = reader_for(&store);
        let mut writer = writer_for(&store);

        let mut appender = IndexAppender::new(&env);
        for i in 0..5u32 {
            let value = b(&env, &i.to_string());
            appender.append(&env, &IndexKey::Bytes(b(&env, "idx")), &value, &mut reader);
        }
        appender.flush(&env, &mut writer);

        let stored = store.borrow().peek(&env, &b(&env, "idx"));
        for i in 0..5u32 {
            assert_eq!(stored.get(i as u32).unwrap(), b(&env, &i.to_string()));
        }
    }

    #[test]
    fn appender_deduplicates_values() {
        let env = setup();
        let store = new_store(&env);
        let mut reader = reader_for(&store);
        let mut writer = writer_for(&store);

        let mut appender = IndexAppender::new(&env);
        for _ in 0..4 {
            appender.append(
                &env,
                &IndexKey::Bytes(b(&env, "idx")),
                &b(&env, "same"),
                &mut reader,
            );
        }
        appender.flush(&env, &mut writer);

        assert_eq!(store.borrow().peek(&env, &b(&env, "idx")).len(), 1);
    }

    #[test]
    fn appender_keeps_existing_entries() {
        let env = setup();
        let store = new_store(&env);
        let key = b(&env, "idx");
        let mut seeded = Vec::new(&env);
        seeded.push_back(b(&env, "pre-existing"));
        store.borrow_mut().write(&key, &seeded);

        let mut reader = reader_for(&store);
        let mut writer = writer_for(&store);
        let mut appender = IndexAppender::new(&env);
        appender.append(
            &env,
            &IndexKey::Bytes(key.clone()),
            &b(&env, "new"),
            &mut reader,
        );
        appender.flush(&env, &mut writer);

        let stored = store.borrow().peek(&env, &key);
        assert_eq!(stored.len(), 2);
        assert_eq!(stored.get(0).unwrap(), b(&env, "pre-existing"));
    }

    #[test]
    fn appender_peek_returns_in_memory_copy() {
        let env = setup();
        let store = new_store(&env);
        let key = IndexKey::Bytes(b(&env, "idx"));
        let mut reader = reader_for(&store);
        let mut writer = writer_for(&store);

        let mut appender = IndexAppender::new(&env);
        assert!(appender.peek(&key).is_none());
        appender.append(&env, &key, &b(&env, "a"), &mut reader);
        assert_eq!(appender.peek(&key).unwrap().len(), 1);
    }

    #[test]
    fn appender_starts_empty() {
        let env = setup();
        let appender = IndexAppender::new(&env);
        assert!(appender.is_empty());
        assert_eq!(appender.len(), 0);
    }

    #[test]
    fn appender_flush_is_noop_when_nothing_appended() {
        let env = setup();
        let store = new_store(&env);
        let mut writer = writer_for(&store);
        let appender = IndexAppender::new(&env);
        assert_eq!(appender.flush(&env, &mut writer), 0);
        assert_eq!(store.borrow().writes, 0);
    }

    #[test]
    fn appender_gives_up_beyond_the_tracking_budget() {
        let env = setup();
        let store = new_store(&env);
        let mut reader = reader_for(&store);
        let mut appender = IndexAppender::new(&env);

        for i in 0..MAX_TRACKED_KEYS {
            let key = IndexKey::Bytes(b(&env, &i.to_string()));
            assert!(appender.append(&env, &key, &b(&env, "v"), &mut reader));
        }
        assert_eq!(appender.len(), MAX_TRACKED_KEYS);
        let overflow = IndexKey::Bytes(b(&env, "overflow"));
        assert!(
            !appender.append(&env, &overflow, &b(&env, "v"), &mut reader),
            "append beyond the budget must report failure so the caller can fall back"
        );
    }

    // ── EntryCache ──────────────────────────────────────────────────────

    #[test]
    fn entry_cache_loads_each_key_once() {
        let env = setup();
        let expected = b(&env, "value");
        let payload = expected.clone();
        let loads = Rc::new(RefCell::new(0u32));
        let counter = loads.clone();
        let mut load = move |_e: &Env, _k: &Bytes| {
            *counter.borrow_mut() += 1;
            Some(payload.clone())
        };

        let mut cache = EntryCache::new(&env);
        for _ in 0..5 {
            let (found, value) = cache.get_or(&env, &b(&env, "k"), &mut load);
            assert!(found);
            assert_eq!(value, expected);
        }
        assert_eq!(*loads.borrow(), 1);
    }

    #[test]
    fn entry_cache_reports_miss_for_absent_keys() {
        let env = setup();
        let loads = Rc::new(RefCell::new(0u32));
        let counter = loads.clone();
        let mut load = move |_e: &Env, _k: &Bytes| {
            *counter.borrow_mut() += 1;
            None
        };

        let mut cache = EntryCache::new(&env);
        let (found, value) = cache.get_or(&env, &b(&env, "missing"), &mut load);
        assert!(!found);
        assert!(value.is_empty());

        let (found2, _) = cache.get_or(&env, &b(&env, "missing"), &mut load);
        assert!(!found2);
        assert_eq!(*loads.borrow(), 1, "loader must not run twice");
    }

    #[test]
    fn entry_cache_writes_each_key_once() {
        let env = setup();
        let mut load = |e: &Env, _k: &Bytes| Some(b(e, "1"));
        let mut cache = EntryCache::new(&env);
        cache.get_or(&env, &b(&env, "a"), &mut load);
        cache.get_or(&env, &b(&env, "b"), &mut load);

        for _ in 0..3 {
            cache.put(&b(&env, "a"), &b(&env, "9"));
        }

        let writes = Rc::new(RefCell::new(0u32));
        let counter = writes.clone();
        let mut store = move |_k: &Bytes, _v: &Bytes| *counter.borrow_mut() += 1;
        let mut remove = |_k: &Bytes| panic!("nothing should be deleted");
        assert_eq!(cache.flush(&mut store, &mut remove), 1);
        assert_eq!(*writes.borrow(), 1);
    }

    #[test]
    fn entry_cache_untouched_keys_are_not_written() {
        let env = setup();
        let mut load = |e: &Env, _k: &Bytes| Some(b(e, "1"));
        let mut cache = EntryCache::new(&env);
        cache.get_or(&env, &b(&env, "a"), &mut load);
        cache.get_or(&env, &b(&env, "b"), &mut load);
        cache.put(&b(&env, "b"), &b(&env, "3"));

        let written: Rc<RefCell<Vec<Bytes>>> = Rc::new(RefCell::new(Vec::new(&env)));
        let sink = written.clone();
        let mut store = move |k: &Bytes, _v: &Bytes| sink.borrow_mut().push_back(k.clone());
        let mut remove = |_k: &Bytes| {};
        assert_eq!(cache.flush(&mut store, &mut remove), 1);
        let written = written.borrow();
        assert_eq!(written.len(), 1);
        assert_eq!(written.get(0).unwrap(), b(&env, "b"));
    }

    #[test]
    fn entry_cache_put_after_get_is_visible_to_later_reads() {
        let env = setup();
        let key = b(&env, "k");
        let mut load = |e: &Env, _k: &Bytes| Some(b(e, "old"));
        let mut never = |_e: &Env, _k: &Bytes| None;

        let mut cache = EntryCache::new(&env);
        cache.get_or(&env, &key, &mut load);
        cache.put(&key, &b(&env, "new"));

        let (found, value) = cache.get_or(&env, &key, &mut never);
        assert!(found);
        assert_eq!(value, b(&env, "new"));
    }

    #[test]
    fn entry_cache_delete_turns_entries_into_removals() {
        let env = setup();
        let key = b(&env, "k");
        let mut load = |e: &Env, _k: &Bytes| Some(b(e, "1"));

        let mut cache = EntryCache::new(&env);
        cache.get_or(&env, &key, &mut load);
        cache.delete(&key);
        assert!(cache.is_deleted(&key));

        let removed = Rc::new(RefCell::new(0u32));
        let counter = removed.clone();
        let mut store = |_k: &Bytes, _v: &Bytes| panic!("deleted entries must not be written");
        let mut remove = move |_k: &Bytes| *counter.borrow_mut() += 1;
        assert_eq!(cache.flush(&mut store, &mut remove), 1);
        assert_eq!(*removed.borrow(), 1);
    }

    #[test]
    fn entry_cache_reports_miss_after_delete() {
        let env = setup();
        let key = b(&env, "k");
        let mut load = |e: &Env, _k: &Bytes| Some(b(e, "1"));
        let mut cache = EntryCache::new(&env);
        cache.get_or(&env, &key, &mut load);
        cache.delete(&key);

        let (found, _) = cache.get_or(&env, &key, &mut load);
        assert!(!found);
    }

    #[test]
    fn entry_cache_starts_empty() {
        let env = setup();
        let cache = EntryCache::new(&env);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn entry_cache_put_on_unknown_key_is_ignored() {
        let env = setup();
        let mut cache = EntryCache::new(&env);
        cache.put(&b(&env, "never-loaded"), &b(&env, "x"));
        let mut store = |_k: &Bytes, _v: &Bytes| panic!("no write expected");
        let mut remove = |_k: &Bytes| panic!("no delete expected");
        assert_eq!(cache.flush(&mut store, &mut remove), 0);
    }
}
