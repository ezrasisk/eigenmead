//! # muspell-transport
//!
//! QUIC stream muxing, framing codec, and connection lifecycle for the
//! Muspell decentralised network.
//!
//! ## Role in the stack
//!
//! ```text
//! muspell-proto       ← wire types (Frame, FrameBody, …)
//! muspell-identity    ← Ed25519 signing / verification
//!        │
//!        ▼
//! muspell-transport   ← YOU ARE HERE
//!        │              iroh QUIC endpoint + ALPN registration
//!        │              length-prefixed CBOR codec
//!        │              Hello/HelloAck handshake + binding verification
//!        │              MuspellConnection: typed send/recv, keepalive, recv_loop
//!        ▼
//! muspell-rpc / muspell-pubsub / muspell-node
//! ```
//!
//! ## Iroh isolation
//!
//! `iroh` is imported **only** in this crate. All layers above use
//! `muspell_proto::NodeId` and `muspell_proto::Did` exclusively.
//! The `convert` module is the single seam where iroh ↔ proto types
//! cross.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use muspell_transport::{MuspellEndpoint, TransportConfig};
//! use muspell_identity::{DidKeypair, NodeKeypair};
//!
//! // Listener
//! let listener = MuspellEndpoint::builder()
//!     .with_node_keypair(NodeKeypair::generate())
//!     .with_did_keypair(DidKeypair::generate())
//!     .bind()
//!     .await?;
//!
//! // Connector
//! let connector = MuspellEndpoint::builder()
//!     .with_node_keypair(NodeKeypair::generate())
//!     .bind()
//!     .await?;
//!
//! let mut conn = connector.connect(listener.node_id()).await?;
//!
//! // Send a frame
//! conn.ping().await?;
//!
//! // Accept a connection on the listener
//! if let Some(Ok(mut peer)) = listener.accept().await {
//!     peer.recv_loop(|frame| async move {
//!         println!("received: {}", frame.variant_name());
//!         Ok(())
//!     }).await?;
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod codec;
pub mod config;
pub mod conn;
pub mod endpoint;
pub mod error;
pub mod handshake;

pub(crate) mod convert;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use config::{TransportConfig, ALPN};
pub use conn::MuspellConnection;
pub use endpoint::{MuspellEndpoint, MuspellEndpointBuilder};
pub use error::{TransportError, TransportResult};
pub use handshake::PeerInfo;
