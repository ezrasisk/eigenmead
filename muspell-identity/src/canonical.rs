//! Canonical byte encoding for signing payloads.
//!
//! ## Format specification
//!
//! This module defines the deterministic byte encoding used when constructing
//! the message that Ed25519 signs or verifies. It is **not** the wire format
//! (that is CBOR, handled by `muspell-transport`).
//!
//! ### Primitives
//!
//! | Value type       | Encoding                                       |
//! |------------------|------------------------------------------------|
//! | Fixed [u8; N]    | N bytes verbatim                               |
//! | u8 discriminant  | 1 byte                                         |
//! | u32              | 4 bytes big-endian                             |
//! | u64              | 8 bytes big-endian                             |
//! | i64              | 8 bytes big-endian                             |
//! | bool             | 1 byte: 0x00=false, 0x01=true                  |
//! | &[u8] (variable) | u32 BE length prefix + bytes                   |
//! | &str             | u32 BE length prefix + UTF-8 bytes             |
//! | Option<T>        | 0x00 if None; 0x01 followed by T if Some       |
//!
//! ### Domain separators
//!
//! Every signing payload begins with a domain separator: a null-terminated
//! ASCII string that uniquely names the payload type. This prevents
//! cross-type signature confusion (an attacker cannot use a namespace
//! signature as a capability signature or vice versa).
//!
//! | Payload         | Domain separator                          |
//! |-----------------|-------------------------------------------|
//! | Capability      | `"muspell-capability-v0\0"`               |
//! | Namespace       | `"muspell-namespace-v0\0"`                |
//! | FrameAuth       | `"muspell-frame-auth-v0\0"`               |
//! | IdentityBinding | `"muspell-identity-binding-v0\0"`         |
//!
//! ### ResourceId encoding
//!
//! | Variant            | Discriminant | Payload                          |
//! |--------------------|--------------|----------------------------------|
//! | Content(cid)       | 0x00         | alg_byte(1) + digest(32)         |
//! | Node(nid)          | 0x01         | node_id_bytes(32)                |
//! | Namespace(ns)      | 0x02         | namespace_id_bytes(32)           |
//! | Wildcard           | 0x03         | (none)                           |
//! | Custom(s)          | 0x04         | length-prefixed UTF-8            |
//!
//! ### Action encoding
//!
//! | Variant       | Discriminant | Payload              |
//! |---------------|--------------|----------------------|
//! | Read          | 0x00         | (none)               |
//! | Write         | 0x01         | (none)               |
//! | Delete        | 0x02         | (none)               |
//! | Delegate      | 0x03         | (none)               |
//! | Admin         | 0x04         | (none)               |
//! | Custom(s)     | 0x05         | length-prefixed UTF-8|
//!
//! ### HashAlg encoding (for ContentId inside ResourceId)
//!
//! | Variant   | Byte |
//! |-----------|------|
//! | Blake3    | 0x00 |
//! | Sha2_256  | 0x01 |

use muspell_proto::{
    Action, ActionSet, Capability, HashAlg, Namespace, ResourceId, Timestamp,
};

// ── Domain separators ─────────────────────────────────────────────────────────

pub(crate) const DOMAIN_CAPABILITY:      &[u8] = b"muspell-capability-v0\0";
pub(crate) const DOMAIN_NAMESPACE:       &[u8] = b"muspell-namespace-v0\0";
pub(crate) const DOMAIN_FRAME_AUTH:      &[u8] = b"muspell-frame-auth-v0\0";
pub(crate) const DOMAIN_BINDING:         &[u8] = b"muspell-identity-binding-v0\0";

// ── CanonicalEncoder ──────────────────────────────────────────────────────────

/// A write-only byte accumulator for constructing canonical signing payloads.
///
/// All methods append to the internal buffer in a deterministic order.
/// The caller is responsible for calling methods in the correct order
/// as defined by the format specification above.
#[derive(Default)]
pub(crate) struct CanonicalEncoder {
    buf: Vec<u8>,
}

impl CanonicalEncoder {
    /// Create a new encoder, pre-populating with the domain separator.
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut enc = Self { buf: Vec::with_capacity(256) };
        enc.buf.extend_from_slice(domain);
        enc
    }

    /// Consume the encoder, returning the accumulated bytes.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.buf
    }

    // ── Primitive writers ─────────────────────────────────────────────────────

    pub(crate) fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub(crate) fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn write_i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn write_u128_le(&mut self, v: u128) {
        // FrameId stores u128 little-endian; use same byte order here
        // so the encoding matches the in-memory representation.
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a fixed-length byte array (no length prefix).
    pub(crate) fn write_fixed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Write a variable-length byte slice: u32-BE length, then bytes.
    pub(crate) fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    /// Write a UTF-8 string: u32-BE length, then bytes.
    pub(crate) fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    // ── Option writers ────────────────────────────────────────────────────────

    /// Write an `Option<Timestamp>`.
    ///
    /// None → 0x00; Some(t) → 0x01 + i64-BE secs + u32-BE nanos.
    pub(crate) fn write_opt_timestamp(&mut self, ts: Option<Timestamp>) {
        match ts {
            None => self.write_u8(0x00),
            Some(t) => {
                self.write_u8(0x01);
                self.write_i64(t.secs);
                self.write_u32(t.nanos);
            }
        }
    }

    // ── Domain-type writers ───────────────────────────────────────────────────

    /// Write a `ResourceId`.
    pub(crate) fn write_resource_id(&mut self, r: &ResourceId) {
        match r {
            ResourceId::Content(cid) => {
                self.write_u8(0x00);
                // HashAlg discriminant
                let alg_byte = match cid.alg {
                    HashAlg::Blake3   => 0x00u8,
                    HashAlg::Sha2_256 => 0x01u8,
                    #[allow(unreachable_patterns)]
                    _                 => 0xffu8,
                };
                self.write_u8(alg_byte);
                self.write_fixed(&cid.digest);
            }
            ResourceId::Node(nid) => {
                self.write_u8(0x01);
                self.write_fixed(nid.as_bytes());
            }
            ResourceId::Namespace(ns) => {
                self.write_u8(0x02);
                self.write_fixed(ns.as_bytes());
            }
            ResourceId::Wildcard => {
                self.write_u8(0x03);
            }
            ResourceId::Custom(s) => {
                self.write_u8(0x04);
                self.write_str(s);
            }
            #[allow(unreachable_patterns)]
            _ => {
                // Unknown future variant — write a sentinel that will
                // not collide with any defined discriminant.
                self.write_u8(0xff);
            }
        }
    }

    /// Write an `ActionSet`.
    ///
    /// BTreeSet iterates in sorted order, so output is always deterministic.
    pub(crate) fn write_action_set(&mut self, set: &ActionSet) {
        // Write count first so readers know how many actions to expect.
        self.write_u32(set.len() as u32);
        for action in set.iter() {
            self.write_action(action);
        }
    }

    /// Write a single `Action`.
    fn write_action(&mut self, action: &Action) {
        match action {
            Action::Read     => self.write_u8(0x00),
            Action::Write    => self.write_u8(0x01),
            Action::Delete   => self.write_u8(0x02),
            Action::Delegate => self.write_u8(0x03),
            Action::Admin    => self.write_u8(0x04),
            Action::Custom(s) => {
                self.write_u8(0x05);
                self.write_str(s);
            }
            #[allow(unreachable_patterns)]
            _ => self.write_u8(0xff),
        }
    }
}

// ── Capability signable bytes ─────────────────────────────────────────────────

/// Produce the canonical signing bytes for a [`Capability`].
///
/// ## Field order
///
/// 1. Domain separator
/// 2. `issuer` — 32 bytes
/// 3. `subject` — 32 bytes
/// 4. `resource` — encoded per ResourceId spec
/// 5. `actions` — encoded per ActionSet spec
/// 6. `not_before` — Option<Timestamp>
/// 7. `expiry` — Option<Timestamp>
/// 8. `proof_ref` — 0x00 if None; 0x01 + 32-byte Blake3 of parent's
///    signable bytes if Some
///
/// The `id` and `signature` fields are explicitly excluded.
pub(crate) fn capability_signable_bytes(cap: &Capability) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new(DOMAIN_CAPABILITY);

    enc.write_fixed(cap.issuer.as_bytes());
    enc.write_fixed(cap.subject.as_bytes());
    enc.write_resource_id(&cap.resource);
    enc.write_action_set(&cap.actions);
    enc.write_opt_timestamp(cap.not_before);
    enc.write_opt_timestamp(cap.expiry);

    // Proof reference: hash of the parent's own signable bytes.
    // Using blake3 as a hash chain — each link commits to its parent
    // without needing to embed the full proof inline in the signing payload.
    match &cap.proof {
        None => enc.write_u8(0x00),
        Some(parent) => {
            enc.write_u8(0x01);
            let parent_bytes = capability_signable_bytes(parent);
            let parent_hash  = blake3::hash(&parent_bytes);
            enc.write_fixed(parent_hash.as_bytes());
        }
    }

    enc.finish()
}

// ── Namespace signable bytes ──────────────────────────────────────────────────

/// Produce the canonical signing bytes for a [`Namespace`].
///
/// ## Field order
///
/// 1. Domain separator
/// 2. `id` — 32 bytes
/// 3. `owner` — 32 bytes
/// 4. `version` — u64 BE
/// 5. `created_at` — i64 secs BE + u32 nanos BE
/// 6. `updated_at` — i64 secs BE + u32 nanos BE
/// 7. `ttl_secs` — u32 BE
/// 8. `record_count` — u32 BE (number of records, including tombstones)
/// 9. For each record in original order:
///    - key: length-prefixed UTF-8
///    - value_hash: Blake3 of the record value's canonical bytes (see below)
///    - sequence: u64 BE
///    - ttl_secs: Option (0x00 or 0x01 + u32 BE)
///    - created_at: i64 BE + u32 BE nanos
///
/// The `name` (petname) and `signature` fields are explicitly excluded —
/// the petname is a display hint and must not affect the cryptographic identity.
///
/// Record values are hashed individually so the signing payload is
/// O(records) not O(records × value_size).
pub(crate) fn namespace_signable_bytes(ns: &Namespace) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new(DOMAIN_NAMESPACE);

    enc.write_fixed(ns.id.as_bytes());
    enc.write_fixed(ns.owner.as_bytes());
    enc.write_u64(ns.version);
    enc.write_i64(ns.created_at.secs);
    enc.write_u32(ns.created_at.nanos);
    enc.write_i64(ns.updated_at.secs);
    enc.write_u32(ns.updated_at.nanos);
    enc.write_u32(ns.ttl_secs);
    enc.write_u32(ns.records.len() as u32);

    for record in &ns.records {
        enc.write_str(record.key.as_str());

        // Hash the record value to keep payload size bounded.
        let value_hash = record_value_hash(&record.value);
        enc.write_fixed(&value_hash);

        enc.write_u64(record.sequence);

        // ttl_secs override
        match record.ttl_secs {
            None    => enc.write_u8(0x00),
            Some(t) => { enc.write_u8(0x01); enc.write_u32(t); }
        }

        enc.write_i64(record.created_at.secs);
        enc.write_u32(record.created_at.nanos);
    }

    enc.finish()
}

/// Compute the Blake3 hash of a record value's canonical representation.
///
/// Each variant gets a 1-byte discriminant followed by its content bytes.
fn record_value_hash(value: &muspell_proto::RecordValue) -> [u8; 32] {
    use muspell_proto::RecordValue;

    let mut enc = CanonicalEncoder::new(b"muspell-record-value-v0\0");
    match value {
        RecordValue::Content(cid) => {
            enc.write_u8(0x00);
            let alg = match cid.alg {
                HashAlg::Blake3   => 0x00u8,
                HashAlg::Sha2_256 => 0x01u8,
                #[allow(unreachable_patterns)]
                _                 => 0xffu8,
            };
            enc.write_u8(alg);
            enc.write_fixed(&cid.digest);
        }
        RecordValue::Node(nid) => {
            enc.write_u8(0x01);
            enc.write_fixed(nid.as_bytes());
        }
        RecordValue::Did(did) => {
            enc.write_u8(0x02);
            enc.write_fixed(did.as_bytes());
        }
        RecordValue::Namespace(ns) => {
            enc.write_u8(0x03);
            enc.write_fixed(ns.as_bytes());
        }
        RecordValue::Text(s) => {
            enc.write_u8(0x04);
            enc.write_str(s);
        }
        RecordValue::CapabilityGrant(cap) => {
            enc.write_u8(0x05);
            // Hash the capability's own signable bytes.
            let cap_bytes = capability_signable_bytes(cap);
            enc.write_fixed(blake3::hash(&cap_bytes).as_bytes());
        }
        RecordValue::Delegate { to, namespace } => {
            enc.write_u8(0x06);
            enc.write_fixed(to.as_bytes());
            enc.write_fixed(namespace.as_bytes());
        }
        RecordValue::Tombstone => {
            enc.write_u8(0x07);
        }
        RecordValue::Custom { namespace, data } => {
            enc.write_u8(0x08);
            enc.write_str(namespace);
            enc.write_bytes(data.as_ref());
        }
        #[allow(unreachable_patterns)]
        _ => { enc.write_u8(0xff); }
    }

    *blake3::hash(&enc.finish()).as_bytes()
}

// ── FrameAuth signable bytes ──────────────────────────────────────────────────

/// Produce the canonical signing bytes for a `FrameAuth`.
///
/// ## Field order
///
/// 1. Domain separator
/// 2. `frame_id` — 16 bytes little-endian u128 (matches FrameId storage)
/// 3. `body_hash` — 32 bytes Blake3 of the serialised frame body
/// 4. `bearer` — 32 bytes DID
///
/// Signing these three fields together binds the authorization to:
/// - This specific frame (by ID)
/// - This specific content (by body hash)
/// - This specific bearer (by DID)
///
/// Preventing: replay, substitution, and bearer impersonation.
pub(crate) fn frame_auth_signable_bytes(
    frame_id:  u128,
    body_hash: &[u8; 32],
    bearer:    &muspell_proto::Did,
) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new(DOMAIN_FRAME_AUTH);
    enc.write_u128_le(frame_id);
    enc.write_fixed(body_hash);
    enc.write_fixed(bearer.as_bytes());
    enc.finish()
}

// ── IdentityBinding signable bytes ────────────────────────────────────────────

/// Produce the canonical signing bytes for an [`IdentityBinding`].
///
/// ## Field order
///
/// 1. Domain separator
/// 2. `did` — 32 bytes
/// 3. `node_id` — 32 bytes
/// 4. `valid_from` — i64 BE secs + u32 BE nanos
/// 5. `valid_until` — Option<Timestamp>
///
/// Signed by the DID's private key. The transport layer verifies this
/// binding during the Hello/HelloAck handshake.
pub(crate) fn binding_signable_bytes(
    did:         &muspell_proto::Did,
    node_id:     &muspell_proto::NodeId,
    valid_from:  Timestamp,
    valid_until: Option<Timestamp>,
) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new(DOMAIN_BINDING);
    enc.write_fixed(did.as_bytes());
    enc.write_fixed(node_id.as_bytes());
    enc.write_i64(valid_from.secs);
    enc.write_u32(valid_from.nanos);
    enc.write_opt_timestamp(valid_until);
    enc.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{
        Action, ActionSet, Capability, ContentId, Did, NamespaceId, NodeId, ResourceId,
        Timestamp,
    };

    fn did(b: u8) -> Did       { Did::from_bytes([b; 32]) }
    fn nid(b: u8) -> NodeId    { NodeId::from_bytes([b; 32]) }
    fn t(s: i64) -> Timestamp  { Timestamp::from_secs(s) }

    // ── CanonicalEncoder primitives ───────────────────────────────────────────

    #[test]
    fn encoder_write_u32_big_endian() {
        let mut enc = CanonicalEncoder::new(b"");
        enc.write_u32(0x0102_0304u32);
        assert_eq!(enc.finish(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn encoder_write_bytes_length_prefixed() {
        let mut enc = CanonicalEncoder::new(b"");
        enc.write_bytes(b"hi");
        let out = enc.finish();
        // 4-byte big-endian length = 2, then "hi"
        assert_eq!(&out[..4], &[0, 0, 0, 2]);
        assert_eq!(&out[4..], b"hi");
    }

    #[test]
    fn encoder_opt_timestamp_none() {
        let mut enc = CanonicalEncoder::new(b"");
        enc.write_opt_timestamp(None);
        assert_eq!(enc.finish(), vec![0x00]);
    }

    #[test]
    fn encoder_opt_timestamp_some() {
        let mut enc = CanonicalEncoder::new(b"");
        enc.write_opt_timestamp(Some(t(1000)));
        let out = enc.finish();
        assert_eq!(out[0], 0x01);
        // 8 bytes for secs = 1000
        assert_eq!(&out[1..9], &1000i64.to_be_bytes());
        // 4 bytes for nanos = 0
        assert_eq!(&out[9..13], &[0, 0, 0, 0]);
    }

    // ── ResourceId encoding ───────────────────────────────────────────────────

    #[test]
    fn resource_id_wildcard_encodes_as_single_byte() {
        let mut enc = CanonicalEncoder::new(b"");
        enc.write_resource_id(&ResourceId::Wildcard);
        assert_eq!(enc.finish(), vec![0x03]);
    }

    #[test]
    fn resource_id_node_encodes_correctly() {
        let node = nid(7);
        let mut enc = CanonicalEncoder::new(b"");
        enc.write_resource_id(&ResourceId::Node(node));
        let out = enc.finish();
        assert_eq!(out[0], 0x01);
        assert_eq!(&out[1..33], &[7u8; 32]);
    }

    #[test]
    fn resource_id_content_encodes_correctly() {
        let cid = ContentId::blake3(b"test");
        let mut enc = CanonicalEncoder::new(b"");
        enc.write_resource_id(&ResourceId::Content(cid));
        let out = enc.finish();
        assert_eq!(out[0], 0x00); // Content discriminant
        assert_eq!(out[1], 0x00); // Blake3 alg byte
        assert_eq!(&out[2..34], &cid.digest);
    }

    // ── Determinism checks ────────────────────────────────────────────────────

    #[test]
    fn capability_signable_bytes_is_deterministic() {
        let cap = Capability::root(
            did(1), did(2),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        let a = capability_signable_bytes(&cap);
        let b = capability_signable_bytes(&cap);
        assert_eq!(a, b);
    }

    #[test]
    fn capability_signable_bytes_differs_by_issuer() {
        let cap_a = Capability::root(did(1), did(2), ResourceId::Wildcard, ActionSet::admin());
        let cap_b = Capability::root(did(9), did(2), ResourceId::Wildcard, ActionSet::admin());
        assert_ne!(
            capability_signable_bytes(&cap_a),
            capability_signable_bytes(&cap_b),
        );
    }

    #[test]
    fn capability_signable_bytes_differs_by_resource() {
        let cap_a = Capability::root(did(1), did(2), ResourceId::Wildcard, ActionSet::admin());
        let cap_b = Capability::root(
            did(1), did(2),
            ResourceId::Node(nid(3)),
            ActionSet::admin(),
        );
        assert_ne!(
            capability_signable_bytes(&cap_a),
            capability_signable_bytes(&cap_b),
        );
    }

    #[test]
    fn capability_signable_bytes_differs_by_proof_presence() {
        let root = Capability::root(
            did(1), did(2),
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );
        let delegated = Capability::delegate(
            root.clone(), did(2), did(3),
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None, None,
        ).unwrap();

        assert_ne!(
            capability_signable_bytes(&root),
            capability_signable_bytes(&delegated),
        );
    }

    #[test]
    fn namespace_signable_bytes_is_deterministic() {
        let owner = did(1);
        let id    = NamespaceId::derive(&owner, "blog");
        let ns    = muspell_proto::Namespace::new(id, owner, t(1000));
        let a = namespace_signable_bytes(&ns);
        let b = namespace_signable_bytes(&ns);
        assert_eq!(a, b);
    }

    #[test]
    fn namespace_signable_bytes_differs_by_version() {
        let owner = did(1);
        let id    = NamespaceId::derive(&owner, "blog");
        let mut ns_a = muspell_proto::Namespace::new(id, owner, t(1000));
        let mut ns_b = muspell_proto::Namespace::new(id, owner, t(1000));
        ns_b.version = 2;
        assert_ne!(namespace_signable_bytes(&ns_a), namespace_signable_bytes(&ns_b));
        // Sanity: same version is same bytes
        ns_a.version = 2;
        assert_eq!(namespace_signable_bytes(&ns_a), namespace_signable_bytes(&ns_b));
    }

    #[test]
    fn frame_auth_signable_bytes_is_deterministic() {
        let bearer = did(5);
        let a = frame_auth_signable_bytes(42u128, &[0u8; 32], &bearer);
        let b = frame_auth_signable_bytes(42u128, &[0u8; 32], &bearer);
        assert_eq!(a, b);
    }

    #[test]
    fn frame_auth_signable_bytes_differs_by_frame_id() {
        let bearer = did(5);
        let a = frame_auth_signable_bytes(1u128, &[0u8; 32], &bearer);
        let b = frame_auth_signable_bytes(2u128, &[0u8; 32], &bearer);
        assert_ne!(a, b);
    }

    #[test]
    fn frame_auth_signable_bytes_differs_by_body_hash() {
        let bearer = did(5);
        let a = frame_auth_signable_bytes(1u128, &[0u8; 32], &bearer);
        let b = frame_auth_signable_bytes(1u128, &[1u8; 32], &bearer);
        assert_ne!(a, b);
    }

    #[test]
    fn binding_signable_bytes_is_deterministic() {
        let d  = did(1);
        let n  = nid(2);
        let a  = binding_signable_bytes(&d, &n, t(1000), None);
        let b  = binding_signable_bytes(&d, &n, t(1000), None);
        assert_eq!(a, b);
    }

    #[test]
    fn domain_separators_all_differ() {
        // No two domain separators should share a prefix with another.
        let seps = [
            DOMAIN_CAPABILITY,
            DOMAIN_NAMESPACE,
            DOMAIN_FRAME_AUTH,
            DOMAIN_BINDING,
        ];
        for i in 0..seps.len() {
            for j in 0..seps.len() {
                if i != j {
                    assert_ne!(seps[i], seps[j], "Domain separators {i} and {j} are equal");
                    // Neither should be a prefix of the other (up to null terminator).
                    assert!(
                        !seps[i].starts_with(&seps[j][..seps[j].len()-1]),
                        "Domain separator {i} is a prefix of {j}"
                    );
                }
            }
        }
    }
}
