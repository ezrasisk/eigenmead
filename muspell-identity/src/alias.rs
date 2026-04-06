//! Local alias registry — the `Did`-to-petname contact book.
//!
//! ## What this is
//!
//! An `AliasRegistry` is a local, in-memory mapping from [`Did`]s to one or
//! more [`HumanName`] petnames. It is the Muspell equivalent of a contacts
//! list or SSH `known_hosts` file.
//!
//! ## What this is NOT
//!
//! The registry is **not** a global naming authority. Two nodes may assign
//! different names to the same `Did`. Global, unique human-readable names are
//! a namespace-layer concern (see `muspell-proto::namespace`).
//!
//! ## Persistence
//!
//! The registry is purely in-memory. Persistence (serialisation to disk,
//! a SQLite database, etc.) is the responsibility of the calling layer
//! (`muspell-node` or an embedder). The registry can be serialised via
//! `serde` by enabling the `serialize` feature (default on).

use muspell_proto::{Did, HumanName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── AliasEntry ────────────────────────────────────────────────────────────────

/// A single entry in the [`AliasRegistry`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct AliasEntry {
    /// The cryptographic identity.
    pub did: Did,
    /// Human-readable names assigned to this DID (may be empty).
    pub names: Vec<HumanName>,
    /// Optional freeform notes (e.g. "Alice's work machine", "relay node").
    pub notes: Option<String>,
}

impl AliasEntry {
    /// Construct a new entry with no names and no notes.
    #[must_use]
    pub fn new(did: Did) -> Self {
        Self { did, names: Vec::new(), notes: None }
    }

    /// Returns `true` if this entry has at least one name.
    #[must_use]
    pub fn has_names(&self) -> bool {
        !self.names.is_empty()
    }

    /// Returns the primary (first-assigned) name, if any.
    #[must_use]
    pub fn primary_name(&self) -> Option<&HumanName> {
        self.names.first()
    }
}

// ── AliasRegistry ─────────────────────────────────────────────────────────────

/// A local, in-memory contact registry mapping [`Did`]s to petnames.
///
/// ## Thread safety
///
/// `AliasRegistry` is not `Sync` by design — it is a single-owner value.
/// For shared access across async tasks, wrap it in `Arc<Mutex<AliasRegistry>>`.
///
/// ## Ordering
///
/// Entries are stored in insertion order via `IndexMap`-style semantics
/// (implemented here with `Vec` for simplicity; for large registries a
/// `BTreeMap` keyed by `Did` would be faster for lookups).
/// The lookup functions perform linear scans; registries are expected to
/// be small (hundreds to low thousands of entries).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct AliasRegistry {
    // HashMap: Did → AliasEntry. Stable iteration order is not required here;
    // lookup by DID is the hot path.
    entries: HashMap<[u8; 32], AliasEntry>,
}

impl AliasRegistry {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Add a `Did` to the registry with no initial names.
    ///
    /// If the DID is already registered, this is a no-op.
    pub fn add_did(&mut self, did: Did) {
        self.entries.entry(did.0).or_insert_with(|| AliasEntry::new(did));
    }

    /// Assign a petname to a `Did`.
    ///
    /// If the DID is not yet registered, it is added first.
    /// If the name is already present for this DID, it is not duplicated.
    pub fn assign_name(&mut self, did: Did, name: HumanName) {
        let entry = self.entries.entry(did.0).or_insert_with(|| AliasEntry::new(did));
        if !entry.names.contains(&name) {
            entry.names.push(name);
        }
    }

    /// Remove a specific name from a `Did`'s entry.
    ///
    /// The `Did` itself remains in the registry even if all names are removed.
    /// Returns `true` if the name was found and removed.
    pub fn remove_name(&mut self, did: &Did, name: &HumanName) -> bool {
        if let Some(entry) = self.entries.get_mut(&did.0) {
            let before = entry.names.len();
            entry.names.retain(|n| n != name);
            return entry.names.len() < before;
        }
        false
    }

    /// Remove a `Did` and all its associated names from the registry.
    ///
    /// Returns the removed `AliasEntry`, or `None` if the DID was not registered.
    pub fn remove_did(&mut self, did: &Did) -> Option<AliasEntry> {
        self.entries.remove(&did.0)
    }

    /// Set the freeform notes for a `Did`.
    ///
    /// If the DID is not registered, it is added first.
    pub fn set_notes(&mut self, did: Did, notes: impl Into<String>) {
        let entry = self.entries.entry(did.0).or_insert_with(|| AliasEntry::new(did));
        entry.notes = Some(notes.into());
    }

    /// Clear the notes for a `Did`.
    pub fn clear_notes(&mut self, did: &Did) {
        if let Some(entry) = self.entries.get_mut(&did.0) {
            entry.notes = None;
        }
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Look up the entry for a `Did`.
    #[must_use]
    pub fn get(&self, did: &Did) -> Option<&AliasEntry> {
        self.entries.get(&did.0)
    }

    /// Returns `true` if the `Did` is registered.
    #[must_use]
    pub fn contains(&self, did: &Did) -> bool {
        self.entries.contains_key(&did.0)
    }

    /// Look up all `Did`s that have been assigned `name` (exact match).
    ///
    /// Returns an empty `Vec` if no match is found.
    #[must_use]
    pub fn lookup_by_name(&self, name: &HumanName) -> Vec<Did> {
        self.entries
            .values()
            .filter(|e| e.names.contains(name))
            .map(|e| e.did)
            .collect()
    }

    /// Look up all `Did`s whose names contain `substring` (case-sensitive).
    ///
    /// Useful for prefix/fuzzy matching in a UI contact search.
    #[must_use]
    pub fn search_by_name_substring(&self, substring: &str) -> Vec<&AliasEntry> {
        self.entries
            .values()
            .filter(|e| e.names.iter().any(|n| n.as_str().contains(substring)))
            .collect()
    }

    /// Return the primary name for a `Did`, if one is assigned.
    #[must_use]
    pub fn primary_name_for(&self, did: &Did) -> Option<&HumanName> {
        self.entries.get(&did.0)?.primary_name()
    }

    // ── Bulk access ───────────────────────────────────────────────────────────

    /// Iterate over all entries in the registry (unordered).
    pub fn iter(&self) -> impl Iterator<Item = &AliasEntry> {
        self.entries.values()
    }

    /// All entries as an owned `Vec`, sorted by primary name then by DID bytes.
    ///
    /// Useful for display in a sorted contact list.
    #[must_use]
    pub fn entries_sorted(&self) -> Vec<&AliasEntry> {
        let mut v: Vec<&AliasEntry> = self.entries.values().collect();
        v.sort_by(|a, b| {
            let name_a = a.primary_name().map(HumanName::as_str).unwrap_or("");
            let name_b = b.primary_name().map(HumanName::as_str).unwrap_or("");
            name_a.cmp(name_b).then_with(|| a.did.0.cmp(&b.did.0))
        });
        v
    }

    /// Number of registered DIDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the registry contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ── Merge ────────────────────────────────────────────────────────────────

    /// Merge another registry into `self`.
    ///
    /// For each entry in `other`:
    /// - If the DID is not in `self`, it is added with all its names and notes.
    /// - If the DID is already in `self`, names are unioned (no duplicates).
    ///   Notes are overwritten if `other` has non-empty notes.
    pub fn merge(&mut self, other: &AliasRegistry) {
        for entry in other.entries.values() {
            let local = self
                .entries
                .entry(entry.did.0)
                .or_insert_with(|| AliasEntry::new(entry.did));

            for name in &entry.names {
                if !local.names.contains(name) {
                    local.names.push(name.clone());
                }
            }
            if entry.notes.is_some() {
                local.notes.clone_from(&entry.notes);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{Did, HumanName};

    fn did(b: u8) -> Did      { Did::from_bytes([b; 32]) }
    fn name(s: &str) -> HumanName { HumanName::new(s) }

    // ── add / contains ────────────────────────────────────────────────────────

    #[test]
    fn registry_add_did_and_contains() {
        let mut reg = AliasRegistry::new();
        reg.add_did(did(1));
        assert!(reg.contains(&did(1)));
        assert!(!reg.contains(&did(2)));
    }

    #[test]
    fn registry_add_did_idempotent() {
        let mut reg = AliasRegistry::new();
        reg.add_did(did(1));
        reg.add_did(did(1)); // second add is no-op
        assert_eq!(reg.len(), 1);
    }

    // ── assign_name ───────────────────────────────────────────────────────────

    #[test]
    fn registry_assign_name_registers_did_if_absent() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        assert!(reg.contains(&did(1)));
        assert_eq!(reg.primary_name_for(&did(1)), Some(&name("alice")));
    }

    #[test]
    fn registry_assign_name_no_duplicates() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        reg.assign_name(did(1), name("alice")); // duplicate
        let entry = reg.get(&did(1)).unwrap();
        assert_eq!(entry.names.len(), 1);
    }

    #[test]
    fn registry_multiple_names_for_same_did() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        reg.assign_name(did(1), name("alice-work"));
        let entry = reg.get(&did(1)).unwrap();
        assert_eq!(entry.names.len(), 2);
        assert_eq!(entry.primary_name(), Some(&name("alice")));
    }

    // ── lookup_by_name ────────────────────────────────────────────────────────

    #[test]
    fn registry_lookup_by_name_finds_correct_did() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        reg.assign_name(did(2), name("bob"));
        let results = reg.lookup_by_name(&name("alice"));
        assert_eq!(results, vec![did(1)]);
    }

    #[test]
    fn registry_lookup_by_name_not_found_returns_empty() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        assert!(reg.lookup_by_name(&name("charlie")).is_empty());
    }

    #[test]
    fn registry_lookup_by_name_multiple_dids_same_name() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("relay"));
        reg.assign_name(did(2), name("relay"));
        let mut results = reg.lookup_by_name(&name("relay"));
        results.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(results.len(), 2);
    }

    // ── search_by_name_substring ──────────────────────────────────────────────

    #[test]
    fn registry_search_substring_finds_partial_match() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice-home"));
        reg.assign_name(did(2), name("alice-work"));
        reg.assign_name(did(3), name("bob"));
        let results = reg.search_by_name_substring("alice");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn registry_search_substring_no_match_returns_empty() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        assert!(reg.search_by_name_substring("charlie").is_empty());
    }

    // ── remove_name / remove_did ──────────────────────────────────────────────

    #[test]
    fn registry_remove_name_found() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        reg.assign_name(did(1), name("alice-work"));
        let removed = reg.remove_name(&did(1), &name("alice-work"));
        assert!(removed);
        let entry = reg.get(&did(1)).unwrap();
        assert_eq!(entry.names.len(), 1);
        assert_eq!(entry.names[0], name("alice"));
    }

    #[test]
    fn registry_remove_name_not_found_returns_false() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        let removed = reg.remove_name(&did(1), &name("ghost"));
        assert!(!removed);
    }

    #[test]
    fn registry_remove_name_keeps_did_in_registry() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        reg.remove_name(&did(1), &name("alice"));
        // DID stays registered even with no names.
        assert!(reg.contains(&did(1)));
    }

    #[test]
    fn registry_remove_did_full() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(1), name("alice"));
        let removed = reg.remove_did(&did(1));
        assert!(removed.is_some());
        assert!(!reg.contains(&did(1)));
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_remove_did_absent_returns_none() {
        let mut reg = AliasRegistry::new();
        assert!(reg.remove_did(&did(1)).is_none());
    }

    // ── notes ─────────────────────────────────────────────────────────────────

    #[test]
    fn registry_set_and_clear_notes() {
        let mut reg = AliasRegistry::new();
        reg.set_notes(did(1), "relay node in eu-west");
        assert_eq!(
            reg.get(&did(1)).unwrap().notes.as_deref(),
            Some("relay node in eu-west")
        );
        reg.clear_notes(&did(1));
        assert!(reg.get(&did(1)).unwrap().notes.is_none());
    }

    // ── merge ─────────────────────────────────────────────────────────────────

    #[test]
    fn registry_merge_adds_new_dids() {
        let mut a = AliasRegistry::new();
        a.assign_name(did(1), name("alice"));

        let mut b = AliasRegistry::new();
        b.assign_name(did(2), name("bob"));

        a.merge(&b);
        assert!(a.contains(&did(1)));
        assert!(a.contains(&did(2)));
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn registry_merge_unions_names() {
        let mut a = AliasRegistry::new();
        a.assign_name(did(1), name("alice"));

        let mut b = AliasRegistry::new();
        b.assign_name(did(1), name("alice-work"));

        a.merge(&b);
        let entry = a.get(&did(1)).unwrap();
        assert_eq!(entry.names.len(), 2);
    }

    #[test]
    fn registry_merge_does_not_duplicate_names() {
        let mut a = AliasRegistry::new();
        a.assign_name(did(1), name("alice"));

        let mut b = AliasRegistry::new();
        b.assign_name(did(1), name("alice")); // same name

        a.merge(&b);
        let entry = a.get(&did(1)).unwrap();
        assert_eq!(entry.names.len(), 1);
    }

    #[test]
    fn registry_merge_overwrites_notes() {
        let mut a = AliasRegistry::new();
        a.set_notes(did(1), "old note");

        let mut b = AliasRegistry::new();
        b.set_notes(did(1), "new note");

        a.merge(&b);
        assert_eq!(
            a.get(&did(1)).unwrap().notes.as_deref(),
            Some("new note")
        );
    }

    // ── entries_sorted ────────────────────────────────────────────────────────

    #[test]
    fn registry_entries_sorted_alphabetically() {
        let mut reg = AliasRegistry::new();
        reg.assign_name(did(3), name("charlie"));
        reg.assign_name(did(1), name("alice"));
        reg.assign_name(did(2), name("bob"));
        let sorted = reg.entries_sorted();
        let names: Vec<&str> = sorted
            .iter()
            .filter_map(|e| e.primary_name().map(HumanName::as_str))
            .collect();
        assert_eq!(names, vec!["alice", "bob", "charlie"]);
    }

    // ── is_empty / len ────────────────────────────────────────────────────────

    #[test]
    fn registry_is_empty_on_new() {
        assert!(AliasRegistry::new().is_empty());
    }

    #[test]
    fn registry_len_increases_with_each_new_did() {
        let mut reg = AliasRegistry::new();
        assert_eq!(reg.len(), 0);
        reg.add_did(did(1));
        assert_eq!(reg.len(), 1);
        reg.add_did(did(2));
        assert_eq!(reg.len(), 2);
        reg.add_did(did(1)); // duplicate, no change
        assert_eq!(reg.len(), 2);
    }
}
