//! # muspell-identity
//!
//! Key management, signing, verification, and alias registry for the
//! Muspell decentralised network.
//!
//! ## Role in the stack
//!
//! ```text
//! muspell-proto      ← pure data types (Did, Signature, Capability, …)
//!       │
//!       ▼
//! muspell-identity   ← YOU ARE HERE
//!       │              Ed25519 keypairs, canonical signing bytes,
//!       │              sign_*/verify_* for all proto types,
//!       │              IdentityBinding, AliasRegistry
//!       ▼
//! muspell-transport  ← uses identity to verify handshakes and frame auth
//! ```
//!
//! ## Design principles
//!
//! - **Single crypto seam** — `ed25519-dalek` is imported only here.
//!   Every other crate holds `Signature([u8; 64])` as raw bytes.
//! - **Fail fast, fail typed** — errors distinguish crypto failures
//!   (tampered data) from structural failures (misconfigured callers)
//!   from time failures (expired tokens). Each has a different response.
//! - **No I/O** — this crate does not touch the filesystem, network, or
//!   clock. Persistence and time are the caller's responsibility.
//!
//! ## Typical usage
//!
//! ### Generate and sign a capability
//!
//! ```rust,ignore
//! use muspell_identity::{DidKeypair, sign_capability, verify_capability_chain};
//! use muspell_proto::{Capability, ActionSet, ResourceId, Timestamp};
//!
//! let alice = DidKeypair::generate();
//! let bob   = DidKeypair::generate();
//!
//! let mut cap = Capability::root(
//!     alice.did(), bob.did(),
//!     ResourceId::Wildcard,
//!     ActionSet::admin(),
//! );
//! sign_capability(&alice, &mut cap)?;
//! verify_capability_chain(&cap, Timestamp::now().unwrap())?;
//! ```
//!
//! ### Sign a namespace
//!
//! ```rust,ignore
//! use muspell_identity::{DidKeypair, sign_namespace, verify_namespace};
//! use muspell_proto::{Namespace, NamespaceId, Timestamp};
//!
//! let owner = DidKeypair::generate();
//! let ns_id = NamespaceId::derive(&owner.did(), "blog");
//! let now   = Timestamp::now().unwrap();
//!
//! let mut ns = Namespace::new(ns_id, owner.did(), now);
//! sign_namespace(&owner, &mut ns)?;
//! verify_namespace(&ns)?;
//! ```
//!
//! ### Sign an identity binding (handshake)
//!
//! ```rust,ignore
//! use muspell_identity::{DidKeypair, NodeKeypair, sign_binding, verify_binding};
//! use muspell_proto::Timestamp;
//!
//! let did_kp  = DidKeypair::generate();
//! let node_kp = NodeKeypair::generate();
//! let now     = Timestamp::now().unwrap();
//! let expiry  = Timestamp::from_secs(now.secs + 86_400);
//!
//! let binding = sign_binding(&did_kp, &node_kp, now, Some(expiry))?;
//! verify_binding(&binding, now)?;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod alias;
pub mod binding;
pub mod error;
pub mod keypair;
pub mod signing;
pub mod verify;

// canonical is internal — pub(crate) only
pub(crate) mod canonical;

// ── Re-exports ────────────────────────────────────────────────────────────────

// Error types
pub use error::{IdentityError, IdentityResult};

// Keypairs
pub use keypair::{DidKeypair, NodeKeypair};

// Binding
pub use binding::IdentityBinding;

// Signing
pub use signing::{
    compute_body_hash,
    sign_binding,
    sign_capability,
    sign_frame_auth,
    sign_namespace,
};

// Verification
pub use verify::{
    verify_binding,
    verify_capability_chain,
    verify_frame_auth,
    verify_frame_auth_at,
    verify_namespace,
};

// Alias registry
pub use alias::{AliasEntry, AliasRegistry};
