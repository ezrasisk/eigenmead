//! On-wire message types for the Muspell protocol.
//!
//! ## Architecture
//!
//! Every byte transmitted between Muspell nodes is a [`Frame`]. The frame
//! envelope carries routing and tracing metadata; the [`FrameBody`] carries
//! the semantic payload.
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────┐
//!  │  Frame                                                  │
//!  │  ├── version    : ProtocolVersion  (compatibility gate) │
//!  │  ├── id         : FrameId          (unique per sender)  │
//!  │  ├── causation  : Option<FrameId>  (tracing chain)      │
//!  │  ├── timestamp  : Timestamp        (wall clock)         │
//!  │  ├── auth       : Option<FrameAuth>(capability token)   │
//!  │  └── body       : FrameBody        (the payload)        │
//!  └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Stream assignment
//!
//! QUIC gives us independent, multiplexed streams. Each frame type belongs
//! on a specific logical channel. Use [`Frame::stream_channel`] to derive
//! the correct channel from a frame — never store it in the frame itself
//! (that would allow frame-stream mismatch).
//!
//! | Channel          | Frames                                              |
//! |------------------|-----------------------------------------------------|
//! | `Control`        | Hello, HelloAck, Ping, Pong, Error, Goodbye         |
//! | `Discovery`      | Announce, Query, QueryResponse                      |
//! | `Data`           | Put, Get, GetResponse, Delete                       |
//! | `Message`        | Message, MessageAck                                 |
//! | `Stream`         | StreamOpen, StreamData, StreamClose                 |
//! | `Extension`      | Extension                                           |
//!
//! ## Forward compatibility
//!
//! All open enums (`FrameBody`, `ErrorCode`, `QueryKind`, …) are
//! `#[non_exhaustive]`. A well-behaved node that receives an unknown variant
//! MUST NOT hard-fail. The correct responses are:
//! - Unknown `FrameBody` variant → send `Error { code: UnknownFrameType, fatal: false }`
//! - Unknown enum variant inside a known frame → ignore the frame, log a warning
//!
//! ## Per-frame authorization
//!
//! The `auth` field attaches a [`Capability`] token to a specific frame.
//! This enables relay nodes to forward frames they cannot themselves
//! authorize, and allows fine-grained per-operation auditing. A node that
//! requires authorization for an operation MUST validate `auth` before acting.

use crate::capability::Capability;
use crate::types::{
    Bytes, ContentId, Did, FrameId, MimeType, NamespaceId, NodeId, ProtocolVersion,
    Signature, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ── NodeCapabilities ─────────────────────────────────────────────────────────

/// The set of protocol capabilities a node advertises in its [`HelloFrame`].
///
/// This is **not** the same as [`Capability`] (authorization tokens). This
/// type describes what *roles* and *features* a node is able to serve —
/// what it has implemented and is currently willing to perform.
///
/// ## Role descriptions
///
/// | Role      | Meaning                                                    |
/// |-----------|------------------------------------------------------------|
/// | `relay`   | Forwards frames for peers that cannot reach each other    |
/// | `store`   | Persists and serves content blobs by `ContentId`          |
/// | `index`   | Answers `Query` frames; maintains a routing table         |
/// | `gateway` | Bridges Muspell to external protocols (HTTP, IPFS, …)     |
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct NodeCapabilities {
    /// This node will relay frames for other peers.
    pub relay: bool,
    /// This node stores and serves content blobs.
    pub store: bool,
    /// This node answers discovery queries.
    pub index: bool,
    /// This node bridges to external protocols.
    pub gateway: bool,
    /// Application- or deployment-specific capability tags.
    /// Format: `"namespace/tag"` e.g. `"muspell/canary"`, `"app/beta"`.
    pub custom: BTreeSet<String>,
}

impl NodeCapabilities {
    /// A minimal node: no special roles, no custom tags.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// A full-featured node advertising every standard role.
    #[must_use]
    pub fn full() -> Self {
        Self {
            relay:   true,
            store:   true,
            index:   true,
            gateway: true,
            custom:  BTreeSet::new(),
        }
    }

    /// Returns `true` if `self` advertises every capability in `required`.
    /// Custom tags are checked for subset membership.
    #[must_use]
    pub fn satisfies(&self, required: &NodeCapabilities) -> bool {
        (!required.relay   || self.relay)
            && (!required.store   || self.store)
            && (!required.index   || self.index)
            && (!required.gateway || self.gateway)
            && required.custom.iter().all(|t| self.custom.contains(t))
    }

    /// Return a new `NodeCapabilities` that is the union of `self` and `other`.
    #[must_use]
    pub fn union(&self, other: &NodeCapabilities) -> NodeCapabilities {
        NodeCapabilities {
            relay:   self.relay   || other.relay,
            store:   self.store   || other.store,
            index:   self.index   || other.index,
            gateway: self.gateway || other.gateway,
            custom:  self.custom.union(&other.custom).cloned().collect(),
        }
    }
}

impl fmt::Display for NodeCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tags: Vec<&str> = Vec::new();
        if self.relay   { tags.push("relay");   }
        if self.store   { tags.push("store");   }
        if self.index   { tags.push("index");   }
        if self.gateway { tags.push("gateway"); }
        let custom: Vec<&str> = self.custom.iter().map(String::as_str).collect();
        write!(f, "[{}]", [tags, custom].concat().join(", "))
    }
}

// ── StreamChannel ─────────────────────────────────────────────────────────────

/// The logical QUIC stream channel a [`Frame`] belongs to.
///
/// Derived from the [`FrameBody`] variant — never stored in the frame.
/// The transport layer uses this to route frames to the correct stream.
///
/// Each channel maps to a different QUIC stream lifecycle:
/// - `Control` — long-lived bidi stream; one per connection
/// - `Discovery` / `Message` — uni-directional; fire and (optionally) forget
/// - `Data` — bidi streams opened on demand, one per request/response pair
/// - `Stream` — bidi or uni; application-defined lifetime
/// - `Extension` — determined by the extension namespace
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub enum StreamChannel {
    /// Connection lifecycle: handshake, keepalive, errors, teardown.
    Control,
    /// Peer discovery, routing announcements, topology queries.
    Discovery,
    /// Content put/get, content deletion.
    Data,
    /// Addressed messages between DIDs (E2E encrypted).
    Message,
    /// Arbitrary named application streams.
    Stream,
    /// Namespace-scoped protocol extensions.
    Extension,
}

impl fmt::Display for StreamChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamChannel::Control   => write!(f, "control"),
            StreamChannel::Discovery => write!(f, "discovery"),
            StreamChannel::Data      => write!(f, "data"),
            StreamChannel::Message   => write!(f, "message"),
            StreamChannel::Stream    => write!(f, "stream"),
            StreamChannel::Extension => write!(f, "extension"),
        }
    }
}

// ── ByteRange ────────────────────────────────────────────────────────────────

/// A half-open byte range `[start, end)` for partial content requests.
///
/// Analogous to HTTP `Range: bytes=start-end`, but with explicit semantics:
/// - `end: None` means "to the end of the content"
/// - `start == 0` with `end: None` requests the full content (prefer `Get`
///   without a range for this; `ByteRange` is for partial fetches only)
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ByteRange {
    /// First byte to return (inclusive, zero-indexed).
    pub start: u64,
    /// One past the last byte to return. `None` means "to end of content".
    pub end: Option<u64>,
}

impl ByteRange {
    /// Construct a range from `start` to the end of the content.
    #[must_use]
    pub fn from(start: u64) -> Self {
        Self { start, end: None }
    }

    /// Construct an explicit `[start, end)` range.
    ///
    /// # Panics (debug only)
    /// Panics if `end <= start`.
    #[must_use]
    pub fn slice(start: u64, end: u64) -> Self {
        debug_assert!(end > start, "ByteRange end must be > start");
        Self { start, end: Some(end) }
    }

    /// The number of bytes in this range, or `None` if open-ended.
    #[must_use]
    pub fn len(&self) -> Option<u64> {
        self.end.map(|e| e.saturating_sub(self.start))
    }

    /// Returns `true` if this is a zero-length range.
    /// Always `false` for open-ended ranges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len().map_or(false, |l| l == 0)
    }
}

impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.end {
            Some(e) => write!(f, "bytes={}-{}", self.start, e.saturating_sub(1)),
            None    => write!(f, "bytes={}-",   self.start),
        }
    }
}

// ── ErrorCode ────────────────────────────────────────────────────────────────

/// Typed error codes for [`ErrorFrame`].
///
/// Grouped into categories by prefix convention:
/// - Protocol errors (wire / handshake level)
/// - Auth errors (capability validation failures)
/// - Resource errors (content / namespace operations)
/// - Rate / quota errors
/// - General errors
///
/// `#[non_exhaustive]` — new codes may be added in minor version bumps.
/// Receivers of an unknown code MUST treat it as `InternalError`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum ErrorCode {
    // ── Protocol ─────────────────────────────────────────────────────────────
    /// The peer's `major` protocol version differs from ours.
    VersionMismatch,
    /// A received frame could not be decoded.
    MalformedFrame,
    /// A frame type that is not valid on this stream channel was received.
    WrongChannel,
    /// A frame type this node does not recognise was received.
    UnknownFrameType,
    /// A required field was absent or zero-valued.
    MissingField,

    // ── Auth ─────────────────────────────────────────────────────────────────
    /// The attached capability has expired.
    CapabilityExpired,
    /// The capability chain is structurally invalid.
    CapabilityInvalid,
    /// The capability does not cover the requested action or resource.
    CapabilityInsufficient,
    /// Authorization is required but no `auth` field was present.
    AuthRequired,

    // ── Resource ─────────────────────────────────────────────────────────────
    /// The requested content or namespace does not exist on this node.
    NotFound,
    /// The resource already exists and the operation would overwrite it.
    AlreadyExists,
    /// The payload exceeds the node's configured maximum.
    TooLarge,
    /// The content hash in a `Put` did not match the received payload.
    HashMismatch,

    // ── Rate / quota ─────────────────────────────────────────────────────────
    /// The sender has exceeded the rate limit; retry after the indicated delay.
    RateLimited,
    /// A storage or bandwidth quota has been reached.
    QuotaExceeded,

    // ── General ──────────────────────────────────────────────────────────────
    /// An unexpected internal error occurred. The peer should not retry
    /// immediately.
    InternalError,
    /// An application-defined error code. The numeric value and its meaning
    /// are namespace-specific.
    Custom(u32),
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch       => write!(f, "version_mismatch"),
            Self::MalformedFrame        => write!(f, "malformed_frame"),
            Self::WrongChannel          => write!(f, "wrong_channel"),
            Self::UnknownFrameType      => write!(f, "unknown_frame_type"),
            Self::MissingField          => write!(f, "missing_field"),
            Self::CapabilityExpired     => write!(f, "capability_expired"),
            Self::CapabilityInvalid     => write!(f, "capability_invalid"),
            Self::CapabilityInsufficient=> write!(f, "capability_insufficient"),
            Self::AuthRequired          => write!(f, "auth_required"),
            Self::NotFound              => write!(f, "not_found"),
            Self::AlreadyExists         => write!(f, "already_exists"),
            Self::TooLarge              => write!(f, "too_large"),
            Self::HashMismatch          => write!(f, "hash_mismatch"),
            Self::RateLimited           => write!(f, "rate_limited"),
            Self::QuotaExceeded         => write!(f, "quota_exceeded"),
            Self::InternalError         => write!(f, "internal_error"),
            Self::Custom(n)             => write!(f, "custom:{n}"),
        }
    }
}

// ── FrameAuth ────────────────────────────────────────────────────────────────

/// Per-frame capability authorization.
///
/// Attaching `FrameAuth` to a frame asserts: "I (`bearer`) have authority
/// to perform this operation, as proven by this `capability` chain."
///
/// ## Anti-replay
///
/// The `nonce` field MUST equal the `id` of the enclosing [`Frame`].
/// A receiver MUST reject any `FrameAuth` whose nonce does not match the
/// frame's `id`. This binds the authorization to exactly one frame and
/// prevents captured (Frame, Auth) pairs from being replayed.
///
/// ## Signature scope
///
/// The `frame_signature` covers the canonical CBOR encoding of:
/// `(frame.id ‖ frame.body-hash ‖ bearer)`, signed by the bearer's key.
/// It proves the bearer intentionally authorized *this specific frame*,
/// not just any frame bearing this capability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct FrameAuth {
    /// The DID asserting authority for this frame.
    pub bearer: Did,
    /// The capability chain proving the bearer has permission.
    pub capability: Capability,
    /// MUST equal the `id` of the enclosing `Frame`. Anti-replay.
    pub nonce: FrameId,
    /// Ed25519 signature by `bearer` over `(frame.id ‖ frame.body-hash ‖ bearer)`.
    /// `None` before signing — a `FrameAuth` without a `frame_signature`
    /// MUST be rejected.
    pub frame_signature: Option<Signature>,
}

impl FrameAuth {
    /// Returns `true` if the `nonce` matches the given `frame_id`.
    /// A receiver MUST call this before accepting the auth.
    #[must_use]
    pub fn nonce_valid(&self, frame_id: &FrameId) -> bool {
        &self.nonce == frame_id
    }

    /// Returns `true` if the `frame_signature` is present.
    /// An unsigned `FrameAuth` MUST be rejected.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.frame_signature.is_some()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Sub-frame structs — one per FrameBody variant
// ═════════════════════════════════════════════════════════════════════════════

// ── Handshake ────────────────────────────────────────────────────────────────

/// Sent immediately after the QUIC/TLS handshake succeeds.
///
/// The first frame on the control stream, in both directions. Nodes
/// MUST NOT send any other frame before `Hello` is acknowledged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct HelloFrame {
    /// The sender's ephemeral network identity.
    pub node_id: NodeId,
    /// The stable DID this node is currently bound to, if any.
    /// `None` for anonymous/ephemeral nodes.
    pub did: Option<Did>,
    /// Which protocol roles this node is prepared to serve.
    pub capabilities: NodeCapabilities,
    /// Human-readable software version string.
    /// Format: `"muspell-daemon/0.1.0 (linux/aarch64)"`.
    /// Optional — receivers MUST NOT require it.
    pub user_agent: Option<String>,
}

/// Acknowledges a received [`HelloFrame`] and completes the handshake.
///
/// After `HelloAck` is exchanged in both directions, the connection is
/// fully established and any frame type may be sent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct HelloAckFrame {
    /// The responder's ephemeral network identity.
    pub node_id: NodeId,
    /// The stable DID this node is currently bound to, if any.
    pub did: Option<Did>,
    /// The agreed protocol version (must satisfy both peers' compatibility).
    pub negotiated_version: ProtocolVersion,
    /// The subset of the peer's advertised capabilities this node accepts.
    pub accepted_capabilities: NodeCapabilities,
    /// Optional greeting or warning message for display in logs / UI.
    pub motd: Option<String>,
}

// ── Discovery ────────────────────────────────────────────────────────────────

/// Broadcast by a node to announce its presence and what it serves.
///
/// Sent on connect and periodically thereafter. Index nodes aggregate
/// these and answer [`QueryFrame`]s on behalf of the network.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct AnnounceFrame {
    /// The announcing node's identity.
    pub node_id: NodeId,
    /// The DID this node is bound to, if any.
    pub did: Option<Did>,
    /// Namespaces this node serves (acts as authority for).
    pub namespaces: Vec<NamespaceId>,
    /// A sample of content IDs held by this node.
    /// Not exhaustive — a gossip hint, not a full index.
    pub content_sample: Vec<ContentId>,
    /// How long (in seconds) this announcement should be considered valid.
    /// After `ttl_secs`, recipients should re-query rather than rely on
    /// cached data.
    pub ttl_secs: u32,
}

/// What kind of thing a [`QueryFrame`] is searching for.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum QueryKind {
    /// Find nodes that hold a specific content blob.
    ContentById(ContentId),
    /// Find nodes bound to a specific DID.
    NodesByDid(Did),
    /// Find the node(s) serving a specific namespace.
    NamespaceById(NamespaceId),
    /// Find nodes advertising a specific capability tag.
    NodesByCapabilityTag(String),
}

/// A question sent to an index node or broadcast to the local peer set.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct QueryFrame {
    /// What this query is looking for.
    pub kind: QueryKind,
    /// The maximum number of results the querier wants.
    /// `None` means "as many as you have".
    pub limit: Option<u32>,
}

/// A single result item in a [`QueryResponseFrame`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum QueryResult {
    /// A node that satisfies the query.
    Node(NodeId),
    /// A content ID that satisfies the query.
    Content(ContentId),
    /// A namespace that satisfies the query.
    Namespace(NamespaceId),
}

/// The response to a [`QueryFrame`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct QueryResponseFrame {
    /// The `id` of the [`QueryFrame`] this responds to.
    pub query_id: FrameId,
    /// The results found.
    pub results: Vec<QueryResult>,
    /// If `true`, there are more results available. The querier may
    /// send another `QueryFrame` with an increased `limit` or an
    /// offset (future extension) to retrieve them.
    pub has_more: bool,
}

// ── Data ─────────────────────────────────────────────────────────────────────

/// Push a content blob to a peer.
///
/// If the content fits in one frame (`chunked == false`), `payload` holds
/// the full blob. If `chunked == true`, `payload` is the first chunk and
/// subsequent chunks arrive as [`StreamDataFrame`]s on a stream keyed
/// by this frame's `id`.
///
/// The receiver MUST verify `content_id` against the reassembled payload
/// before storing or forwarding it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PutFrame {
    /// The expected content address. Receiver verifies after reassembly.
    pub content_id: ContentId,
    /// MIME type of the content.
    pub mime: MimeType,
    /// Total size of the content in bytes (across all chunks if chunked).
    pub total_size: u64,
    /// Payload bytes. Full content if `chunked == false`; first chunk otherwise.
    pub payload: Bytes,
    /// If `true`, additional [`StreamDataFrame`]s follow on a stream
    /// keyed by this frame's `id`.
    pub chunked: bool,
}

/// Request a content blob from a peer by its [`ContentId`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct GetFrame {
    /// The content address to fetch.
    pub content_id: ContentId,
    /// Optional byte range for partial fetches.
    /// `None` requests the full content.
    pub byte_range: Option<ByteRange>,
}

/// The result payload inside a [`GetResponseFrame`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum GetResult {
    /// Content was found. If `chunked`, additional [`StreamDataFrame`]s follow.
    Found {
        /// Verified content address.
        content_id: ContentId,
        /// MIME type.
        mime: MimeType,
        /// Total size across all chunks.
        total_size: u64,
        /// Full payload (or first chunk if `chunked`).
        payload: Bytes,
        /// If `true`, additional chunks follow on a stream keyed by
        /// the enclosing `Frame`'s `id`.
        chunked: bool,
    },
    /// The content is not held by this node.
    NotFound,
    /// The requester's capability does not cover this content.
    Denied,
    /// The node holds the content but cannot serve it right now.
    Unavailable { retry_after_secs: Option<u32> },
}

/// Response to a [`GetFrame`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct GetResponseFrame {
    /// The `id` of the [`GetFrame`] this responds to.
    pub request_id: FrameId,
    /// The result.
    pub result: GetResult,
}

/// Request deletion of a content blob from a peer's store.
///
/// Requires a `FrameAuth` with `Action::Delete` over the target
/// `ResourceId::Content(content_id)`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DeleteFrame {
    /// The content to delete.
    pub content_id: ContentId,
}

/// Acknowledgement of a [`DeleteFrame`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DeleteAckFrame {
    /// The `id` of the [`DeleteFrame`] this responds to.
    pub request_id: FrameId,
    /// `true` if the content was found and deleted; `false` if not found.
    pub deleted: bool,
}

// ── Messaging ────────────────────────────────────────────────────────────────

/// Delivery status of a sent [`MessageFrame`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum MessageStatus {
    /// The message was delivered to a live connection of the recipient.
    Delivered,
    /// The recipient is offline; the message is queued for later delivery.
    Queued,
    /// The recipient actively rejected the message.
    Rejected,
    /// The relay/target node does not know the recipient's current location.
    Unknown,
}

/// An end-to-end encrypted message addressed to a [`Did`].
///
/// The `encrypted_payload` is opaque to relay nodes — only the holder of
/// the recipient DID's private key can decrypt it. Key exchange and
/// encryption are handled by `muspell-identity`; this type holds the
/// ciphertext and routing metadata only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct MessageFrame {
    /// The intended recipient's stable identity.
    pub to: Did,
    /// The sender's stable identity (authenticated by `FrameAuth`).
    pub from: Did,
    /// Opaque ciphertext. Only `to` can decrypt this.
    pub encrypted_payload: Bytes,
    /// Wall-clock time at which the sender created this message.
    pub sent_at: Timestamp,
    /// Stable message ID for deduplication and acknowledgement correlation.
    /// The sender generates this; relay nodes preserve it unchanged.
    pub message_id: FrameId,
}

/// Acknowledgement of a [`MessageFrame`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct MessageAckFrame {
    /// The `message_id` of the [`MessageFrame`] being acknowledged.
    pub message_id: FrameId,
    /// Delivery status as reported by the relay or recipient node.
    pub status: MessageStatus,
}

// ── Application streams ───────────────────────────────────────────────────────

/// The direction a logical stream flows.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum StreamKind {
    /// Data flows only from opener to peer.
    Unidirectional,
    /// Data flows in both directions.
    Bidirectional,
}

/// Open a named logical sub-stream within the connection.
///
/// Logical streams are identified by a [`FrameId`] chosen by the opener.
/// Subsequent [`StreamDataFrame`]s and [`StreamCloseFrame`]s reference
/// this ID. The `name` is a semantic hint for logging and routing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct StreamOpenFrame {
    /// Opener-assigned ID. Unique within this connection.
    pub stream_id: FrameId,
    /// Semantic name for this stream.
    /// Convention: `"<purpose>/<identifier>"` e.g. `"sync/ns-abc"`, `"log/1"`.
    pub name: String,
    /// Whether this stream is bidirectional.
    pub kind: StreamKind,
}

/// A chunk of data on an open logical stream.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct StreamDataFrame {
    /// The stream this chunk belongs to (matches a prior [`StreamOpenFrame`]).
    pub stream_id: FrameId,
    /// Monotonically increasing sequence number (zero-indexed).
    /// Receivers MUST reassemble in sequence order.
    pub sequence: u64,
    /// The chunk payload.
    pub data: Bytes,
    /// If `true`, this is the final chunk. The logical stream ends here.
    pub is_last: bool,
}

/// Close a logical stream.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct StreamCloseFrame {
    /// The stream to close (matches a prior [`StreamOpenFrame`]).
    pub stream_id: FrameId,
    /// Human-readable reason, if any. For logs only.
    pub reason: Option<String>,
}

// ── Control ───────────────────────────────────────────────────────────────────

/// Round-trip latency probe.
///
/// The receiver MUST respond with a [`PongFrame`] echoing the `nonce`
/// and both timestamps as quickly as possible.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PingFrame {
    /// Random value chosen by the sender. Echoed in [`PongFrame`].
    pub nonce: u64,
    /// Wall-clock time when this `Ping` was sent. Included to allow
    /// clock-skew estimation independent of RTT.
    pub sent_at: Timestamp,
}

/// Response to a [`PingFrame`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PongFrame {
    /// Echo of [`PingFrame::nonce`]. Correlates response to request.
    pub nonce: u64,
    /// Echo of [`PingFrame::sent_at`]. Allows the original sender to
    /// compute RTT without shared state.
    pub ping_sent_at: Timestamp,
    /// Wall-clock time when this `Pong` was sent. Allows one-way
    /// latency estimation when combined with `ping_sent_at`.
    pub pong_sent_at: Timestamp,
}

impl PongFrame {
    /// Compute the approximate round-trip time in nanoseconds.
    ///
    /// Requires the caller to supply `received_at` (wall-clock time at
    /// which the `Pong` arrived). Returns `None` if `received_at` is
    /// earlier than `ping_sent_at` (clock skew / misconfiguration).
    #[must_use]
    pub fn rtt_nanos(&self, received_at: Timestamp) -> Option<u128> {
        let sent  = self.ping_sent_at.as_nanos();
        let recv  = received_at.as_nanos();
        recv.checked_sub(sent)
    }
}

/// A protocol-level error.
///
/// Application errors should be carried in domain-specific frame fields
/// (e.g. [`GetResult::Denied`]). `ErrorFrame` is reserved for errors that
/// relate to the frame exchange protocol itself.
///
/// If `fatal` is `true`, the sender is about to close the connection and
/// the receiver SHOULD NOT attempt to send further frames.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ErrorFrame {
    /// The error category.
    pub code: ErrorCode,
    /// Human-readable description. For logs/diagnostics only; not
    /// parsed programmatically.
    pub message: String,
    /// The `id` of the frame that caused this error, if applicable.
    pub related_frame: Option<FrameId>,
    /// If `true`, the sender considers the connection unrecoverable
    /// and will close it after sending this frame.
    pub fatal: bool,
}

impl ErrorFrame {
    /// Construct a fatal error frame.
    #[must_use]
    pub fn fatal(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            related_frame: None,
            fatal: true,
        }
    }

    /// Construct a non-fatal (recoverable) error frame.
    #[must_use]
    pub fn recoverable(
        code: ErrorCode,
        message: impl Into<String>,
        related_frame: Option<FrameId>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            related_frame,
            fatal: false,
        }
    }
}

/// Graceful connection teardown.
///
/// Sent by either peer before closing the QUIC connection.
/// The receiver SHOULD acknowledge by sending its own `Goodbye` before
/// closing, but MUST NOT block on this.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct GoodbyeFrame {
    /// Human-readable reason for closing. For logs only.
    pub reason: String,
    /// Advisory hint: the sender suggests the receiver should not
    /// attempt to reconnect before this many seconds have elapsed.
    /// `None` means "reconnect whenever you like".
    pub reconnect_after_secs: Option<u32>,
}

// ── Extension ────────────────────────────────────────────────────────────────

/// A namespace-scoped extension frame.
///
/// The escape hatch for protocol growth without breaking old nodes.
///
/// A node that receives an `ExtensionFrame` with an unknown `namespace`
/// MUST forward it (if it is a relay) or silently discard it (if it is
/// the final recipient). It MUST NOT return an error.
///
/// ## Namespace conventions
///
/// | Pattern                  | Use                                        |
/// |--------------------------|--------------------------------------------|
/// | `muspell/<name>`         | Official Muspell protocol extensions       |
/// | `<reverse-domain>/<name>`| Application-specific (`"io.myapp/hello"`)  |
/// | `experimental/<name>`    | Unstable / draft extensions                |
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ExtensionFrame {
    /// Namespace that owns this extension.
    pub namespace: String,
    /// Message type discriminator within the namespace.
    pub kind: String,
    /// Raw payload. Interpretation is namespace-defined.
    pub payload: Bytes,
}

// ═════════════════════════════════════════════════════════════════════════════
// FrameBody — the discriminated union of all message types
// ═════════════════════════════════════════════════════════════════════════════

/// The payload of a [`Frame`] — what this message actually *is*.
///
/// `#[non_exhaustive]` ensures that adding a new variant in a future
/// minor version does not break existing match arms in downstream crates.
/// All match arms on `FrameBody` MUST include a `_ => { /* ignore */ }`
/// arm or delegate to a handler that logs and discards unknown variants.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum FrameBody {
    // ── Handshake ────────────────────────────────────────────────────────────
    /// Initial greeting. First frame on the control stream.
    Hello(HelloFrame),
    /// Handshake acknowledgement. Completes connection establishment.
    HelloAck(HelloAckFrame),

    // ── Discovery ────────────────────────────────────────────────────────────
    /// Presence announcement: "I exist and I serve X".
    Announce(AnnounceFrame),
    /// Routing query: "Who has X?"
    Query(QueryFrame),
    /// Response to a routing query.
    QueryResponse(QueryResponseFrame),

    // ── Data ─────────────────────────────────────────────────────────────────
    /// Push a content blob to a peer.
    Put(PutFrame),
    /// Request a content blob by address.
    Get(GetFrame),
    /// Response to a content request.
    GetResponse(GetResponseFrame),
    /// Request deletion of a content blob.
    Delete(DeleteFrame),
    /// Acknowledgement of a delete request.
    DeleteAck(DeleteAckFrame),

    // ── Messaging ────────────────────────────────────────────────────────────
    /// E2E encrypted message addressed to a DID.
    Message(MessageFrame),
    /// Delivery acknowledgement for a message.
    MessageAck(MessageAckFrame),

    // ── Application streams ───────────────────────────────────────────────────
    /// Open a named logical sub-stream.
    StreamOpen(StreamOpenFrame),
    /// A chunk of data on a logical sub-stream.
    StreamData(StreamDataFrame),
    /// Close a logical sub-stream.
    StreamClose(StreamCloseFrame),

    // ── Control ──────────────────────────────────────────────────────────────
    /// Latency probe.
    Ping(PingFrame),
    /// Latency probe response.
    Pong(PongFrame),
    /// Protocol-level error.
    Error(ErrorFrame),
    /// Graceful connection teardown.
    Goodbye(GoodbyeFrame),

    // ── Extension ────────────────────────────────────────────────────────────
    /// Namespace-scoped extension frame.
    Extension(ExtensionFrame),
}

impl FrameBody {
    /// Return the [`StreamChannel`] this frame body should be sent on.
    ///
    /// This is a pure classification — no stored state is consulted.
    /// The transport layer calls this to route the frame to the correct
    /// QUIC stream.
    #[must_use]
    pub fn stream_channel(&self) -> StreamChannel {
        match self {
            FrameBody::Hello(_)
            | FrameBody::HelloAck(_)
            | FrameBody::Ping(_)
            | FrameBody::Pong(_)
            | FrameBody::Error(_)
            | FrameBody::Goodbye(_) => StreamChannel::Control,

            FrameBody::Announce(_)
            | FrameBody::Query(_)
            | FrameBody::QueryResponse(_) => StreamChannel::Discovery,

            FrameBody::Put(_)
            | FrameBody::Get(_)
            | FrameBody::GetResponse(_)
            | FrameBody::Delete(_)
            | FrameBody::DeleteAck(_) => StreamChannel::Data,

            FrameBody::Message(_)
            | FrameBody::MessageAck(_) => StreamChannel::Message,

            FrameBody::StreamOpen(_)
            | FrameBody::StreamData(_)
            | FrameBody::StreamClose(_) => StreamChannel::Stream,

            FrameBody::Extension(_) => StreamChannel::Extension,

            // Safety net for future variants added before a match arm is:
            #[allow(unreachable_patterns)]
            _ => StreamChannel::Extension,
        }
    }

    /// Returns `true` if this frame kind expects a response from the peer.
    ///
    /// Used by the transport layer to decide whether to open a bidi stream
    /// or a uni-directional stream, and to set up correlation tracking.
    #[must_use]
    pub fn expects_response(&self) -> bool {
        matches!(
            self,
            FrameBody::Hello(_)
                | FrameBody::Get(_)
                | FrameBody::Put(_)
                | FrameBody::Delete(_)
                | FrameBody::Query(_)
                | FrameBody::Message(_)
                | FrameBody::Ping(_)
        )
    }

    /// Returns `true` if this frame is a response to a prior request.
    ///
    /// Response frames carry the originating frame's `id` in a `request_id`
    /// or `query_id` field so the transport can match them to open requests.
    #[must_use]
    pub fn is_response(&self) -> bool {
        matches!(
            self,
            FrameBody::HelloAck(_)
                | FrameBody::GetResponse(_)
                | FrameBody::DeleteAck(_)
                | FrameBody::QueryResponse(_)
                | FrameBody::MessageAck(_)
                | FrameBody::Pong(_)
        )
    }

    /// Returns the name of this frame body variant. Useful in logs.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        match self {
            FrameBody::Hello(_)         => "Hello",
            FrameBody::HelloAck(_)      => "HelloAck",
            FrameBody::Announce(_)      => "Announce",
            FrameBody::Query(_)         => "Query",
            FrameBody::QueryResponse(_) => "QueryResponse",
            FrameBody::Put(_)           => "Put",
            FrameBody::Get(_)           => "Get",
            FrameBody::GetResponse(_)   => "GetResponse",
            FrameBody::Delete(_)        => "Delete",
            FrameBody::DeleteAck(_)     => "DeleteAck",
            FrameBody::Message(_)       => "Message",
            FrameBody::MessageAck(_)    => "MessageAck",
            FrameBody::StreamOpen(_)    => "StreamOpen",
            FrameBody::StreamData(_)    => "StreamData",
            FrameBody::StreamClose(_)   => "StreamClose",
            FrameBody::Ping(_)          => "Ping",
            FrameBody::Pong(_)          => "Pong",
            FrameBody::Error(_)         => "Error",
            FrameBody::Goodbye(_)       => "Goodbye",
            FrameBody::Extension(_)     => "Extension",
            #[allow(unreachable_patterns)]
            _                           => "Unknown",
        }
    }
}

impl fmt::Display for FrameBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FrameBody::{}", self.variant_name())
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Frame — the outermost envelope
// ═════════════════════════════════════════════════════════════════════════════

/// The outermost envelope for every Muspell wire message.
///
/// Every byte sent between nodes is a `Frame`. The envelope carries
/// metadata needed for compatibility checking, distributed tracing,
/// and per-frame authorization. The [`FrameBody`] carries the payload.
///
/// ## Construction
///
/// Two constructors are provided:
///
/// - [`Frame::new`] — always available; takes explicit `id` and `timestamp`.
///   Prefer this in tests and in code that manages its own clock/ID source.
/// - [`Frame::create`] — available with `rand` + `clock` features (default);
///   generates a random `id` and uses the system clock for `timestamp`.
///
/// ## Builder methods
///
/// ```rust
/// # use muspell_proto::frame::{Frame, FrameBody, PingFrame};
/// # use muspell_proto::{FrameId, Timestamp};
/// let frame = Frame::new(
///     FrameId::from_u128(1),
///     Timestamp::ZERO,
///     FrameBody::Ping(PingFrame { nonce: 42, sent_at: Timestamp::ZERO }),
/// ).with_causation(FrameId::from_u128(0));
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Frame {
    /// The protocol version of the sender.
    /// Receivers MUST check `major` compatibility before processing.
    pub version: ProtocolVersion,
    /// Unique identifier for this frame, chosen by the sender.
    /// Used for response correlation and distributed tracing.
    pub id: FrameId,
    /// The `id` of the frame that caused this one to be sent, if any.
    /// Builds a causal chain for distributed tracing.
    /// Response frames set this to the `id` of their request.
    pub causation: Option<FrameId>,
    /// Wall-clock time at which the sender created this frame.
    pub timestamp: Timestamp,
    /// Optional per-frame capability authorization.
    /// MUST be present for operations that require it; absent for
    /// unauthenticated frames (Hello, Ping, Announce, etc.).
    pub auth: Option<FrameAuth>,
    /// The payload.
    pub body: FrameBody,
}

impl Frame {
    /// Construct a frame with an explicit `id` and `timestamp`.
    ///
    /// Always available — no feature flags required. Prefer this in
    /// tests and in code that controls its own ID and clock sources.
    #[must_use]
    pub fn new(id: FrameId, timestamp: Timestamp, body: FrameBody) -> Self {
        Self {
            version:   ProtocolVersion::CURRENT,
            id,
            causation: None,
            timestamp,
            auth:      None,
            body,
        }
    }

    /// Construct a frame with a random `id` and current wall-clock `timestamp`.
    ///
    /// Available only when both `rand` and `clock` features are enabled
    /// (they are by default). Returns `None` if the system clock is
    /// before the Unix epoch (misconfigured system).
    #[cfg(all(feature = "rand", feature = "clock"))]
    #[must_use]
    pub fn create(body: FrameBody) -> Option<Self> {
        let ts = Timestamp::now()?;
        Some(Self::new(FrameId::random(), ts, body))
    }

    // ── Builder methods ───────────────────────────────────────────────────────

    /// Set the `causation` field (which frame triggered this one).
    #[must_use]
    pub fn with_causation(mut self, id: FrameId) -> Self {
        self.causation = Some(id);
        self
    }

    /// Attach per-frame capability authorization.
    #[must_use]
    pub fn with_auth(mut self, auth: FrameAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Override the protocol version (for testing compatibility logic).
    #[must_use]
    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = version;
        self
    }

    // ── Classification ────────────────────────────────────────────────────────

    /// The logical QUIC stream channel this frame should be sent on.
    #[must_use]
    pub fn stream_channel(&self) -> StreamChannel {
        self.body.stream_channel()
    }

    /// Returns `true` if this frame expects a response from the peer.
    #[must_use]
    pub fn expects_response(&self) -> bool {
        self.body.expects_response()
    }

    /// Returns `true` if this frame is a response to a prior request.
    #[must_use]
    pub fn is_response(&self) -> bool {
        self.body.is_response()
    }

    /// Returns `true` if `self.version` is wire-compatible with `peer_version`.
    #[must_use]
    pub fn is_compatible_with(&self, peer_version: ProtocolVersion) -> bool {
        self.version.is_compatible_with(peer_version)
    }

    /// Returns `true` if this frame carries per-frame authorization.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_some()
    }

    /// The name of this frame's body variant. Useful in logs.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        self.body.variant_name()
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Frame[{} id={} v={}]",
            self.body.variant_name(),
            self.id,
            self.version,
        )
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{ActionSet, Capability, ResourceId};
    use crate::types::{ContentId, Did, FrameId, NamespaceId, NodeId, Signature, Timestamp};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn nid(byte: u8) -> NodeId { NodeId::from_bytes([byte; 32]) }
    fn did(byte: u8) -> Did    { Did::from_bytes([byte; 32]) }
    fn t(secs: i64) -> Timestamp { Timestamp::from_secs(secs) }
    fn fid(v: u128) -> FrameId { FrameId::from_u128(v) }
    fn fake_sig() -> Signature { Signature::from_bytes([0xaau8; 64]) }

    fn hello_body() -> FrameBody {
        FrameBody::Hello(HelloFrame {
            node_id:      nid(1),
            did:          Some(did(1)),
            capabilities: NodeCapabilities::none(),
            user_agent:   Some("muspell-daemon/test".into()),
        })
    }

    fn ping_body() -> FrameBody {
        FrameBody::Ping(PingFrame {
            nonce:   99,
            sent_at: t(1000),
        })
    }

    fn get_body() -> FrameBody {
        FrameBody::Get(GetFrame {
            content_id: ContentId::blake3(b"hello"),
            byte_range:  None,
        })
    }

    // ── NodeCapabilities ─────────────────────────────────────────────────────

    #[test]
    fn node_caps_satisfies_subset() {
        let full  = NodeCapabilities::full();
        let relay = NodeCapabilities { relay: true, ..NodeCapabilities::none() };
        assert!(full.satisfies(&relay));
    }

    #[test]
    fn node_caps_does_not_satisfy_superset() {
        let relay  = NodeCapabilities { relay: true,  ..NodeCapabilities::none() };
        let full   = NodeCapabilities::full();
        assert!(!relay.satisfies(&full));
    }

    #[test]
    fn node_caps_satisfies_none() {
        let any  = NodeCapabilities::full();
        let none = NodeCapabilities::none();
        assert!(any.satisfies(&none));
    }

    #[test]
    fn node_caps_union_merges_flags() {
        let a = NodeCapabilities { relay: true,  ..NodeCapabilities::none() };
        let b = NodeCapabilities { store: true,  ..NodeCapabilities::none() };
        let u = a.union(&b);
        assert!(u.relay);
        assert!(u.store);
        assert!(!u.index);
    }

    #[test]
    fn node_caps_union_merges_custom_tags() {
        let mut a = NodeCapabilities::none();
        a.custom.insert("muspell/canary".into());
        let mut b = NodeCapabilities::none();
        b.custom.insert("muspell/beta".into());
        let u = a.union(&b);
        assert!(u.custom.contains("muspell/canary"));
        assert!(u.custom.contains("muspell/beta"));
    }

    #[test]
    fn node_caps_satisfies_custom_tag() {
        let mut full = NodeCapabilities::full();
        full.custom.insert("io.app/feature-x".into());
        let mut req = NodeCapabilities::none();
        req.custom.insert("io.app/feature-x".into());
        assert!(full.satisfies(&req));
    }

    #[test]
    fn node_caps_fails_missing_custom_tag() {
        let full = NodeCapabilities::full();
        let mut req = NodeCapabilities::none();
        req.custom.insert("io.app/missing".into());
        assert!(!full.satisfies(&req));
    }

    // ── ByteRange ─────────────────────────────────────────────────────────────

    #[test]
    fn byte_range_len_slice() {
        let r = ByteRange::slice(10, 20);
        assert_eq!(r.len(), Some(10));
        assert!(!r.is_empty());
    }

    #[test]
    fn byte_range_len_open() {
        let r = ByteRange::from(100);
        assert_eq!(r.len(), None);
        assert!(!r.is_empty());
    }

    #[test]
    fn byte_range_display() {
        assert_eq!(ByteRange::slice(0, 100).to_string(), "bytes=0-99");
        assert_eq!(ByteRange::from(50).to_string(), "bytes=50-");
    }

    // ── ErrorFrame ────────────────────────────────────────────────────────────

    #[test]
    fn error_frame_fatal_constructor() {
        let e = ErrorFrame::fatal(ErrorCode::VersionMismatch, "bad version");
        assert!(e.fatal);
        assert_eq!(e.code, ErrorCode::VersionMismatch);
        assert!(e.related_frame.is_none());
    }

    #[test]
    fn error_frame_recoverable_constructor() {
        let related = fid(42);
        let e = ErrorFrame::recoverable(
            ErrorCode::NotFound,
            "not here",
            Some(related),
        );
        assert!(!e.fatal);
        assert_eq!(e.related_frame, Some(related));
    }

    // ── PongFrame::rtt_nanos ──────────────────────────────────────────────────

    #[test]
    fn pong_rtt_nanos_basic() {
        let pong = PongFrame {
            nonce:        1,
            ping_sent_at: Timestamp::new(1000, 0),
            pong_sent_at: Timestamp::new(1000, 500_000),
        };
        let received_at = Timestamp::new(1000, 1_000_000); // 1ms after ping
        assert_eq!(pong.rtt_nanos(received_at), Some(1_000_000));
    }

    #[test]
    fn pong_rtt_nanos_returns_none_on_clock_skew() {
        let pong = PongFrame {
            nonce:        1,
            ping_sent_at: Timestamp::new(2000, 0),
            pong_sent_at: Timestamp::new(2000, 0),
        };
        // received_at is BEFORE ping_sent_at — clock skew
        let received_at = Timestamp::new(1999, 0);
        assert_eq!(pong.rtt_nanos(received_at), None);
    }

    // ── FrameAuth ─────────────────────────────────────────────────────────────

    #[test]
    fn frame_auth_nonce_valid() {
        let frame_id = fid(0xdeadbeef);
        let auth = FrameAuth {
            bearer:          did(1),
            capability:      Capability::root(
                did(1), did(1),
                ResourceId::Wildcard,
                ActionSet::admin(),
            ),
            nonce:           frame_id,
            frame_signature: Some(fake_sig()),
        };
        assert!(auth.nonce_valid(&frame_id));
        assert!(!auth.nonce_valid(&fid(0)));
    }

    #[test]
    fn frame_auth_unsigned_is_not_signed() {
        let auth = FrameAuth {
            bearer:          did(1),
            capability:      Capability::root(
                did(1), did(1),
                ResourceId::Wildcard,
                ActionSet::admin(),
            ),
            nonce:           fid(1),
            frame_signature: None,
        };
        assert!(!auth.is_signed());
    }

    // ── Frame::new ────────────────────────────────────────────────────────────

    #[test]
    fn frame_new_sets_current_version() {
        let f = Frame::new(fid(1), t(0), ping_body());
        assert_eq!(f.version, ProtocolVersion::CURRENT);
    }

    #[test]
    fn frame_new_no_causation_by_default() {
        let f = Frame::new(fid(1), t(0), ping_body());
        assert!(f.causation.is_none());
    }

    #[test]
    fn frame_with_causation() {
        let cause = fid(99);
        let f = Frame::new(fid(1), t(0), ping_body()).with_causation(cause);
        assert_eq!(f.causation, Some(cause));
    }

    #[test]
    fn frame_with_auth() {
        let frame_id = fid(42);
        let auth = FrameAuth {
            bearer:          did(1),
            capability:      Capability::root(
                did(1), did(1),
                ResourceId::Wildcard,
                ActionSet::admin(),
            ),
            nonce:           frame_id,
            frame_signature: Some(fake_sig()),
        };
        let f = Frame::new(frame_id, t(0), get_body()).with_auth(auth);
        assert!(f.is_authenticated());
    }

    #[test]
    fn frame_is_not_authenticated_by_default() {
        let f = Frame::new(fid(1), t(0), ping_body());
        assert!(!f.is_authenticated());
    }

    // ── Frame::create (rand + clock features) ────────────────────────────────

    #[cfg(all(feature = "rand", feature = "clock"))]
    #[test]
    fn frame_create_produces_nonzero_timestamp() {
        let f = Frame::create(ping_body()).expect("clock should work");
        assert!(f.timestamp.secs > 0);
    }

    #[cfg(all(feature = "rand", feature = "clock"))]
    #[test]
    fn frame_create_produces_unique_ids() {
        let a = Frame::create(ping_body()).unwrap();
        let b = Frame::create(ping_body()).unwrap();
        assert_ne!(a.id, b.id);
    }

    // ── StreamChannel classification ──────────────────────────────────────────

    #[test]
    fn stream_channel_hello_is_control() {
        let f = Frame::new(fid(1), t(0), hello_body());
        assert_eq!(f.stream_channel(), StreamChannel::Control);
    }

    #[test]
    fn stream_channel_ping_is_control() {
        let f = Frame::new(fid(1), t(0), ping_body());
        assert_eq!(f.stream_channel(), StreamChannel::Control);
    }

    #[test]
    fn stream_channel_get_is_data() {
        let f = Frame::new(fid(1), t(0), get_body());
        assert_eq!(f.stream_channel(), StreamChannel::Data);
    }

    #[test]
    fn stream_channel_query_is_discovery() {
        let body = FrameBody::Query(QueryFrame {
            kind:  QueryKind::NamespaceById(
                NamespaceId::derive(&did(1), "test")
            ),
            limit: None,
        });
        let f = Frame::new(fid(1), t(0), body);
        assert_eq!(f.stream_channel(), StreamChannel::Discovery);
    }

    #[test]
    fn stream_channel_message_is_message() {
        let body = FrameBody::Message(MessageFrame {
            to:                did(2),
            from:              did(1),
            encrypted_payload: Bytes::from_slice(b"ciphertext"),
            sent_at:           t(1000),
            message_id:        fid(7),
        });
        let f = Frame::new(fid(1), t(0), body);
        assert_eq!(f.stream_channel(), StreamChannel::Message);
    }

    #[test]
    fn stream_channel_stream_open_is_stream() {
        let body = FrameBody::StreamOpen(StreamOpenFrame {
            stream_id: fid(10),
            name:      "sync/abc".into(),
            kind:      StreamKind::Bidirectional,
        });
        let f = Frame::new(fid(1), t(0), body);
        assert_eq!(f.stream_channel(), StreamChannel::Stream);
    }

    #[test]
    fn stream_channel_extension_is_extension() {
        let body = FrameBody::Extension(ExtensionFrame {
            namespace: "io.example".into(),
            kind:      "custom".into(),
            payload:   Bytes::from_slice(b"data"),
        });
        let f = Frame::new(fid(1), t(0), body);
        assert_eq!(f.stream_channel(), StreamChannel::Extension);
    }

    // ── expects_response / is_response ───────────────────────────────────────

    #[test]
    fn hello_expects_response() {
        let f = Frame::new(fid(1), t(0), hello_body());
        assert!(f.expects_response());
        assert!(!f.is_response());
    }

    #[test]
    fn hello_ack_is_response() {
        let body = FrameBody::HelloAck(HelloAckFrame {
            node_id:               nid(2),
            did:                   None,
            negotiated_version:    ProtocolVersion::CURRENT,
            accepted_capabilities: NodeCapabilities::none(),
            motd:                  None,
        });
        let f = Frame::new(fid(2), t(0), body).with_causation(fid(1));
        assert!(f.is_response());
        assert!(!f.expects_response());
    }

    #[test]
    fn ping_expects_response() {
        let f = Frame::new(fid(1), t(0), ping_body());
        assert!(f.expects_response());
    }

    #[test]
    fn pong_is_response() {
        let body = FrameBody::Pong(PongFrame {
            nonce:        99,
            ping_sent_at: t(1000),
            pong_sent_at: t(1001),
        });
        let f = Frame::new(fid(2), t(0), body).with_causation(fid(1));
        assert!(f.is_response());
        assert!(!f.expects_response());
    }

    #[test]
    fn announce_neither_expects_nor_is_response() {
        let body = FrameBody::Announce(AnnounceFrame {
            node_id:        nid(1),
            did:            None,
            namespaces:     vec![],
            content_sample: vec![],
            ttl_secs:       300,
        });
        let f = Frame::new(fid(1), t(0), body);
        assert!(!f.expects_response());
        assert!(!f.is_response());
    }

    #[test]
    fn goodbye_neither_expects_nor_is_response() {
        let body = FrameBody::Goodbye(GoodbyeFrame {
            reason:                "shutdown".into(),
            reconnect_after_secs:  Some(60),
        });
        let f = Frame::new(fid(1), t(0), body);
        assert!(!f.expects_response());
        assert!(!f.is_response());
    }

    // ── variant_name ─────────────────────────────────────────────────────────

    #[test]
    fn variant_names_are_correct() {
        let cases: &[(&str, FrameBody)] = &[
            ("Hello",    hello_body()),
            ("Ping",     ping_body()),
            ("Get",      get_body()),
            ("Goodbye",  FrameBody::Goodbye(GoodbyeFrame {
                reason: "bye".into(),
                reconnect_after_secs: None,
            })),
            ("Extension", FrameBody::Extension(ExtensionFrame {
                namespace: "x".into(),
                kind:      "y".into(),
                payload:   Bytes::default(),
            })),
        ];
        for (expected, body) in cases {
            let f = Frame::new(fid(1), t(0), body.clone());
            assert_eq!(f.variant_name(), *expected, "failed for {expected}");
        }
    }

    // ── version compatibility ─────────────────────────────────────────────────

    #[test]
    fn frame_compatible_with_same_major() {
        let f = Frame::new(fid(1), t(0), ping_body());
        let peer = ProtocolVersion { major: 0, minor: 9 }; // same major, higher minor
        assert!(f.is_compatible_with(peer));
    }

    #[test]
    fn frame_incompatible_with_different_major() {
        let f = Frame::new(fid(1), t(0), ping_body());
        let peer = ProtocolVersion { major: 1, minor: 0 };
        assert!(!f.is_compatible_with(peer));
    }

    // ── Display / Debug ───────────────────────────────────────────────────────

    #[test]
    fn frame_display_contains_variant_name() {
        let f = Frame::new(fid(1), t(0), ping_body());
        let s = f.to_string();
        assert!(s.contains("Ping"), "Display should contain 'Ping', got: {s}");
    }

    #[test]
    fn error_code_display() {
        assert_eq!(ErrorCode::VersionMismatch.to_string(),        "version_mismatch");
        assert_eq!(ErrorCode::CapabilityExpired.to_string(),      "capability_expired");
        assert_eq!(ErrorCode::Custom(42).to_string(),             "custom:42");
        assert_eq!(ErrorCode::HashMismatch.to_string(),           "hash_mismatch");
    }

    // ── GetResult variants ────────────────────────────────────────────────────

    #[test]
    fn get_result_found_carries_content() {
        let cid  = ContentId::blake3(b"data");
        let data = Bytes::from_slice(b"data");
        let r = GetResult::Found {
            content_id: cid,
            mime:       MimeType::new("application/octet-stream"),
            total_size: 4,
            payload:    data.clone(),
            chunked:    false,
        };
        if let GetResult::Found { payload, chunked, .. } = r {
            assert_eq!(payload, data);
            assert!(!chunked);
        } else {
            panic!("expected Found");
        }
    }

    // ── StreamDataFrame sequencing ────────────────────────────────────────────

    #[test]
    fn stream_data_is_last_flag() {
        let stream_id = fid(10);
        let chunk1 = StreamDataFrame {
            stream_id,
            sequence: 0,
            data:     Bytes::from_slice(b"chunk1"),
            is_last:  false,
        };
        let chunk2 = StreamDataFrame {
            stream_id,
            sequence: 1,
            data:     Bytes::from_slice(b"chunk2"),
            is_last:  true,
        };
        assert!(!chunk1.is_last);
        assert!(chunk2.is_last);
        assert_eq!(chunk2.sequence, chunk1.sequence + 1);
    }

    // ── Full round-trip structural check (all major variants) ─────────────────

    #[test]
    fn all_control_frames_are_on_control_channel() {
        let frames: Vec<FrameBody> = vec![
            hello_body(),
            FrameBody::HelloAck(HelloAckFrame {
                node_id:               nid(2),
                did:                   None,
                negotiated_version:    ProtocolVersion::CURRENT,
                accepted_capabilities: NodeCapabilities::none(),
                motd:                  None,
            }),
            ping_body(),
            FrameBody::Pong(PongFrame {
                nonce: 1, ping_sent_at: t(0), pong_sent_at: t(1),
            }),
            FrameBody::Error(ErrorFrame::fatal(ErrorCode::InternalError, "oops")),
            FrameBody::Goodbye(GoodbyeFrame {
                reason: "bye".into(), reconnect_after_secs: None,
            }),
        ];
        for body in frames {
            assert_eq!(
                body.stream_channel(),
                StreamChannel::Control,
                "{} should be on Control channel",
                body.variant_name()
            );
        }
    }

    #[test]
    fn all_data_frames_are_on_data_channel() {
        let cid = ContentId::blake3(b"x");
        let frames: Vec<FrameBody> = vec![
            FrameBody::Put(PutFrame {
                content_id: cid,
                mime:       MimeType::new("application/octet-stream"),
                total_size: 1,
                payload:    Bytes::from_slice(b"x"),
                chunked:    false,
            }),
            get_body(),
            FrameBody::GetResponse(GetResponseFrame {
                request_id: fid(1),
                result:     GetResult::NotFound,
            }),
            FrameBody::Delete(DeleteFrame { content_id: cid }),
            FrameBody::DeleteAck(DeleteAckFrame { request_id: fid(1), deleted: true }),
        ];
        for body in frames {
            assert_eq!(
                body.stream_channel(),
                StreamChannel::Data,
                "{} should be on Data channel",
                body.variant_name()
            );
        }
    }
}
