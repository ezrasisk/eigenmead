//! Topic identity — `TopicId` and `TopicName`.
//!
//! ## Design
//!
//! A topic is identified by its content-addressed `TopicId`: the Blake3
//! hash of the UTF-8 topic name bytes, prefixed with a domain separator.
//! This gives every named topic a globally unique, collision-resistant,
//! fixed-size identifier with no coordination required.
//!
//! The human-readable `TopicName` is the local alias — it is resolved to
//! a `TopicId` by calling `TopicName::id()`. Two nodes that use the same
//! topic name string will always arrive at the same `TopicId`, which is
//! how topics are matched across the network.
//!
//! ## Wire encoding
//!
//! `TopicId` is serialised as 32 raw bytes inside `ExtensionFrame` payloads.
//! The CBOR encoding is handled by serde.
//!
//! ## Topic name syntax
//!
//! No syntax restrictions are imposed at this layer — any valid UTF-8 string
//! is a legal topic name. Conventions recommended for producers:
//!
//! | Pattern                  | Example                       | Use                 |
//! |--------------------------|-------------------------------|---------------------|
//! | `namespace/subtopic`     | `"muspell/node-announce"`     | Protocol topics     |
//! | `did:muspell:<key>/feed` | `"did:muspell:4aRp…/feed"`    | Identity-scoped     |
//! | `ns:<id>/events`         | `"ns:7xKq…/events"`           | Namespace events    |
//! | `app/<name>/<topic>`     | `"app/chat/general"`          | Application-defined |

use serde::{Deserialize, Serialize};
use std::fmt;

/// Domain separator — prefixed before topic name bytes before hashing.
/// This prevents a topic named `"x"` from colliding with any other
/// hash construction in the Muspell stack.
const TOPIC_DOMAIN: &[u8] = b"muspell-topic-v0\0";

// ── TopicId ───────────────────────────────────────────────────────────────────

/// A content-addressed, globally unique topic identifier.
///
/// Computed as `blake3(DOMAIN ‖ topic_name_utf8)`. Two publishers and
/// subscribers using the same `TopicName` string will always converge on
/// the same `TopicId`, enabling cross-node pub/sub without a directory.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TopicId(pub [u8; 32]);

impl TopicId {
    /// Derive a `TopicId` from a topic name string.
    ///
    /// Same as `TopicName::new(name).id()` — provided here for ergonomics
    /// when a `TopicName` value is not needed.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let mut input = Vec::with_capacity(TOPIC_DOMAIN.len() + name.len());
        input.extend_from_slice(TOPIC_DOMAIN);
        input.extend_from_slice(name.as_bytes());
        Self(*blake3::hash(&input).as_bytes())
    }

    /// Construct from raw bytes (e.g. deserialised from the wire).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "topic:{}", bs58::encode(&self.0).into_string())
    }
}

impl fmt::Debug for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TopicId({})", bs58::encode(&self.0).into_string())
    }
}

// ── TopicName ─────────────────────────────────────────────────────────────────

/// A human-readable topic name that resolves to a [`TopicId`].
///
/// The `TopicId` is computed once on construction and cached.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TopicName {
    name: String,
    id:   TopicId,
}

impl TopicName {
    /// Construct from any string-like value.
    ///
    /// The `TopicId` is computed immediately and cached.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let id   = TopicId::from_name(&name);
        Self { name, id }
    }

    /// The derived `TopicId` for this name.
    #[must_use]
    pub fn id(&self) -> TopicId {
        self.id
    }

    /// The raw name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for TopicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TopicName({:?} → {})", self.name, self.id)
    }
}

impl fmt::Display for TopicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&str>  for TopicName { fn from(s: &str)   -> Self { Self::new(s) } }
impl From<String> for TopicName { fn from(s: String) -> Self { Self::new(s) } }

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_id_from_name_is_deterministic() {
        let a = TopicId::from_name("muspell/node-announce");
        let b = TopicId::from_name("muspell/node-announce");
        assert_eq!(a, b);
    }

    #[test]
    fn different_names_produce_different_ids() {
        let a = TopicId::from_name("topic/a");
        let b = TopicId::from_name("topic/b");
        assert_ne!(a, b);
    }

    #[test]
    fn topic_name_id_matches_from_name() {
        let name   = "muspell/events";
        let direct = TopicId::from_name(name);
        let via    = TopicName::new(name).id();
        assert_eq!(direct, via);
    }

    #[test]
    fn topic_name_from_str_and_string_agree() {
        let a = TopicName::from("hello");
        let b = TopicName::from("hello".to_owned());
        assert_eq!(a.id(), b.id());
    }

    #[test]
    fn domain_separator_prevents_collision_with_empty_string() {
        // An empty topic name should still produce a non-trivial ID
        // (the domain separator is hashed in).
        let empty = TopicId::from_name("");
        assert_ne!(empty.as_bytes(), &[0u8; 32]);
        // And it differs from a non-empty name.
        assert_ne!(empty, TopicId::from_name("a"));
    }

    #[test]
    fn topic_id_display_has_prefix() {
        let id = TopicId::from_name("test");
        assert!(id.to_string().starts_with("topic:"));
    }

    #[test]
    fn topic_id_roundtrip_bytes() {
        let id      = TopicId::from_name("roundtrip");
        let bytes   = *id.as_bytes();
        let restored = TopicId::from_bytes(bytes);
        assert_eq!(id, restored);
    }
}
