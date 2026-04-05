//! Capability-based authorization for the Muspell network.
//!
//! ## The core idea
//!
//! Web2 authorization asks: *"Is this user logged in to a server that trusts them?"*  
//! Muspell authorization asks: *"Does this bearer hold a cryptographic proof of permission?"*
//!
//! A [`Capability`] is a signed, time-bounded, delegatable authorization token.
//! No server is consulted at verification time. Any node that can verify an
//! Ed25519 signature and read a [`Did`] can enforce authorization.
//!
//! ## Mental model
//!
//! Think of a capability like a signed permission slip:
//!
//! > "I, Alice (`issuer`), grant Bob (`subject`) the right to `Write` to my
//! > namespace `ns:foo` (`resource`) until midnight (`expiry`).  
//! > My authority to grant this derives from this attached token (`proof`)."
//!
//! Bob can further delegate a **subset** of this to Carol (attenuation). Carol
//! cannot gain permissions Bob doesn't have. The chain is self-verifying: each
//! link is signed by the issuer named in the link above it.
//!
//! ## What this file owns
//!
//! - Type definitions: [`Capability`], [`ResourceId`], [`ActionSet`], [`Action`]
//! - Structural validation: time bounds, attenuation, chain integrity
//! - **Not** cryptographic signature verification — that lives in `muspell-identity`
//!   which can depend on a crypto crate. This file stays pure-data.
//!
//! ## UCAN alignment
//!
//! This design is deliberately compatible with the spirit of
//! [UCAN](https://ucan.xyz/) (User Controlled Authorization Networks) while
//! being simpler and Muspell-native. Future versions may add full UCAN
//! serialization interop.

use crate::types::{ContentId, Did, NamespaceId, NodeId, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ── Action ───────────────────────────────────────────────────────────────────

/// A single permitted operation on a resource.
///
/// Actions form a loose hierarchy:
///
/// ```text
/// Admin  ⊇  { Read, Write, Delete, Delegate }
/// Delegate   allows issuing sub-capabilities
/// Write      implies the ability to read (enforced by convention, not this type)
/// ```
///
/// `#[non_exhaustive]` allows new variants to be added in minor version bumps.
/// Unknown actions received from a peer MUST be treated as opaque, not rejected —
/// a future peer may have been granted a permission this node doesn't recognise.
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug,
)]
#[non_exhaustive]
pub enum Action {
    /// Read / fetch content or metadata.
    Read,
    /// Create or update content.
    Write,
    /// Permanently remove content or records.
    Delete,
    /// Issue sub-capabilities (delegate to others).
    /// A bearer without `Delegate` cannot produce valid capability chains.
    Delegate,
    /// Full control — equivalent to all standard actions combined.
    /// Prefer granting specific actions over `Admin` wherever possible.
    Admin,
    /// An application- or namespace-specific action.
    /// The string SHOULD be namespaced: `"muspell/relay"`, `"app/publish"`.
    Custom(String),
}

impl Action {
    /// Returns `true` if this action is subsumed by `other`.
    ///
    /// `Admin` subsumes every other action. All other actions subsume only
    /// themselves. `Custom` actions are only equal to themselves.
    #[must_use]
    pub fn is_subsumed_by(&self, other: &Action) -> bool {
        match other {
            Action::Admin => true, // Admin covers everything
            _ => self == other,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Read         => write!(f, "read"),
            Action::Write        => write!(f, "write"),
            Action::Delete       => write!(f, "delete"),
            Action::Delegate     => write!(f, "delegate"),
            Action::Admin        => write!(f, "admin"),
            Action::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

// ── ActionSet ────────────────────────────────────────────────────────────────

/// An ordered, deduplicated set of [`Action`]s.
///
/// The `BTreeSet` backing guarantees stable serialization order, which is
/// critical for deterministic content addressing (CBOR canonicalization).
///
/// ## Attenuation invariant
///
/// When delegating, the granted `ActionSet` MUST be a subset of the issuer's
/// own `ActionSet`. [`ActionSet::is_attenuated_by`] enforces this.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ActionSet(pub BTreeSet<Action>);

impl ActionSet {
    /// Construct an empty set.
    #[must_use]
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Construct from an iterator of actions.
    #[must_use]
    pub fn from_actions(actions: impl IntoIterator<Item = Action>) -> Self {
        Self(actions.into_iter().collect())
    }

    /// Convenience: a single-action set.
    #[must_use]
    pub fn single(action: Action) -> Self {
        let mut s = BTreeSet::new();
        s.insert(action);
        Self(s)
    }

    /// Full admin rights — use sparingly.
    #[must_use]
    pub fn admin() -> Self {
        Self::single(Action::Admin)
    }

    /// Returns `true` if `self` is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of distinct actions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if this set contains `action`, respecting `Admin`
    /// subsumption: an `Admin` set grants every action.
    #[must_use]
    pub fn permits(&self, action: &Action) -> bool {
        if self.0.contains(&Action::Admin) {
            return true;
        }
        // Check direct membership and subsumption
        self.0.iter().any(|a| action.is_subsumed_by(a))
    }

    /// Returns `true` if every action in `self` is permitted by `authority`.
    ///
    /// Used to enforce the attenuation invariant: a delegated capability's
    /// action set must be fully covered by the issuer's action set.
    #[must_use]
    pub fn is_attenuated_by(&self, authority: &ActionSet) -> bool {
        self.0.iter().all(|a| authority.permits(a))
    }

    /// Returns a new `ActionSet` containing only actions permitted by both
    /// `self` and `other` (set intersection, respecting `Admin` subsumption).
    #[must_use]
    pub fn intersect(&self, other: &ActionSet) -> ActionSet {
        // If other is Admin, the full self is returned.
        if other.0.contains(&Action::Admin) {
            return self.clone();
        }
        ActionSet(
            self.0
                .iter()
                .filter(|a| other.permits(a))
                .cloned()
                .collect(),
        )
    }

    /// Iterate over the contained actions.
    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.0.iter()
    }
}

impl fmt::Debug for ActionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActionSet{{")?;
        for (i, a) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{a}")?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for ActionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// ── ResourceId ───────────────────────────────────────────────────────────────

/// The resource a [`Capability`] governs.
///
/// A capability without a resource is meaningless — this type makes the
/// scope of authorization explicit and machine-verifiable.
///
/// ## Specificity ordering (most → least)
///
/// `Content` > `Node` > `Namespace` > `Wildcard`
///
/// When checking whether a capability covers a request, a more specific
/// `ResourceId` covers a less specific one only if they refer to the same
/// entity. A `Wildcard` covers everything. Intermediate nodes should
/// never silently upgrade specificity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub enum ResourceId {
    /// A specific immutable datum, addressed by content hash.
    /// The tightest possible scope — grants access to exactly one blob.
    Content(ContentId),

    /// A specific live node, addressed by its ephemeral public key.
    /// Used for node-management operations (relay, shutdown, diagnostics).
    Node(NodeId),

    /// A namespace and everything within it.
    /// Equivalent to "this domain and all its records."
    Namespace(NamespaceId),

    /// Every resource accessible to the issuer.
    /// Only a root key should issue `Wildcard` capabilities.
    Wildcard,

    /// An application- or namespace-scoped resource not covered above.
    /// The string SHOULD be a URI or URN: `"muspell:relay:pool:eu-west"`.
    Custom(String),
}

impl ResourceId {
    /// Returns `true` if `self` is covered by `authority`.
    ///
    /// A `Wildcard` authority covers everything. Otherwise exact equality
    /// is required — there is no implicit namespace ⊇ content rule at
    /// this layer (that is a policy decision for higher layers).
    #[must_use]
    pub fn is_covered_by(&self, authority: &ResourceId) -> bool {
        match authority {
            ResourceId::Wildcard => true,
            other               => self == other,
        }
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceId::Content(cid)   => write!(f, "content:{cid}"),
            ResourceId::Node(nid)      => write!(f, "{nid}"),
            ResourceId::Namespace(ns)  => write!(f, "{ns}"),
            ResourceId::Wildcard       => write!(f, "resource:*"),
            ResourceId::Custom(s)      => write!(f, "custom:{s}"),
        }
    }
}

// ── CapabilityId ─────────────────────────────────────────────────────────────

/// A stable, content-derived identifier for a [`Capability`].
///
/// Derived by hashing the canonical serialization of the capability's
/// fields (excluding the signature and the `id` field itself). Two
/// logically identical capabilities always have the same `CapabilityId`.
///
/// Used for:
/// - Revocation lists (block a capability by ID without storing the full token)  
/// - Deduplication in gossip and caches  
/// - The `proof` reference in delegation chains (avoids deep nesting)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CapabilityId(pub [u8; 32]);

impl CapabilityId {
    /// Derive from the canonical byte representation of a capability's
    /// signable fields. The caller (typically `muspell-identity`) supplies
    /// the pre-hashed bytes.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Return the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityId({})", bs58::encode(&self.0).into_string())
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cap:{}", bs58::encode(&self.0).into_string())
    }
}

// ── Capability ───────────────────────────────────────────────────────────────

/// A signed, time-bounded, delegatable authorization token.
///
/// ## Lifecycle
///
/// ```text
/// Root keypair issues Capability { proof: None }   ← root / self-signed
///        │
///        └─▶ Alice attenuates → Capability { proof: Some(root_cap) }
///                   │
///                   └─▶ Bob attenuates → Capability { proof: Some(alice_cap) }
/// ```
///
/// Each level can only grant a **subset** of what the level above granted
/// (attenuation invariant). Any node can verify the full chain structurally
/// without network access, and cryptographically once it has the public keys.
///
/// ## Proof storage
///
/// The `proof` field carries the **full parent capability inline**.  
/// For long chains this may be verbose; future versions may introduce
/// `proof_ref: CapabilityId` for by-reference delegation (where the
/// referenced capability is fetched from the content-addressed store).
///
/// ## Signature scope
///
/// The `signature` covers all fields **except** `signature` itself,
/// serialized as canonical DAG-CBOR. The signing DID is `issuer`.
/// Signature verification is implemented in `muspell-identity`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Capability {
    /// Stable identifier derived from this capability's signable content.
    /// May be `None` before the capability has been signed and committed.
    pub id: Option<CapabilityId>,

    /// The DID that grants this capability. Must hold (or be delegated)
    /// the actions over the resource. Signs this struct.
    pub issuer: Did,

    /// The DID that receives this capability. The bearer of the private
    /// key corresponding to this DID is authorized to use it.
    pub subject: Did,

    /// The resource this capability governs.
    pub resource: ResourceId,

    /// The set of actions the subject is permitted to perform.
    /// MUST be a subset of the issuer's own capability over this resource.
    pub actions: ActionSet,

    /// The earliest time this capability is valid (inclusive).
    /// `None` means valid from the beginning of time.
    pub not_before: Option<Timestamp>,

    /// The expiry time of this capability (exclusive).
    /// `None` means the capability never expires. Prefer explicit expiries
    /// for all delegated capabilities — unbounded tokens are a liability.
    pub expiry: Option<Timestamp>,

    /// The parent capability this one was derived from.
    /// `None` indicates a root capability — issued by the resource owner
    /// directly from their root keypair.
    ///
    /// When `proof` is `Some`, the issuer of `self` MUST be the `subject`
    /// of `proof`. This is the chain-of-custody invariant.
    pub proof: Option<Box<Capability>>,

    /// Ed25519 signature by `issuer` over the canonical encoding of all
    /// other fields. `None` before signing; a capability without a
    /// signature is a draft and MUST NOT be accepted by any node.
    pub signature: Option<Signature>,
}

impl Capability {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Begin building a root capability (no parent proof).
    ///
    /// The caller must set `signature` before transmitting.
    #[must_use]
    pub fn root(
        issuer: Did,
        subject: Did,
        resource: ResourceId,
        actions: ActionSet,
    ) -> Self {
        Self {
            id:         None,
            issuer,
            subject,
            resource,
            actions,
            not_before: None,
            expiry:     None,
            proof:      None,
            signature:  None,
        }
    }

    /// Begin building a delegated capability derived from `parent`.
    ///
    /// Validates the attenuation invariant immediately:
    /// - `actions` must be a subset of `parent.actions`
    /// - `resource` must be covered by `parent.resource`
    /// - If `parent.expiry` is set, `expiry` must not extend beyond it
    /// - `issuer` of this capability must equal `subject` of parent
    ///
    /// Returns `Err(AttenuationError)` if any invariant is violated.
    /// The caller must set `signature` before transmitting.
    pub fn delegate(
        parent: Capability,
        issuer: Did,
        subject: Did,
        resource: ResourceId,
        actions: ActionSet,
        not_before: Option<Timestamp>,
        expiry: Option<Timestamp>,
    ) -> Result<Self, AttenuationError> {
        // The issuer of a delegated capability must be the subject of the
        // parent — they are the one who received authority and is now
        // passing it on.
        if issuer != parent.subject {
            return Err(AttenuationError::IssuerNotParentSubject {
                expected: parent.subject,
                got:      issuer,
            });
        }

        // The issuer must have been granted Delegate rights.
        if !parent.actions.permits(&Action::Delegate)
            && !parent.actions.permits(&Action::Admin)
        {
            return Err(AttenuationError::DelegateActionNotGranted);
        }

        // Actions must be a subset of what the parent granted.
        if !actions.is_attenuated_by(&parent.actions) {
            return Err(AttenuationError::ActionsExceedParent {
                requested: actions.clone(),
                available: parent.actions.clone(),
            });
        }

        // Resource must be covered by the parent's resource.
        if !resource.is_covered_by(&parent.resource) {
            return Err(AttenuationError::ResourceNotCoveredByParent {
                requested: resource.clone(),
                available: parent.resource.clone(),
            });
        }

        // Expiry must not extend beyond the parent's expiry.
        if let Some(parent_exp) = parent.expiry {
            if let Some(child_exp) = expiry {
                if child_exp > parent_exp {
                    return Err(AttenuationError::ExpiryExceedsParent {
                        requested: child_exp,
                        available: parent_exp,
                    });
                }
            } else {
                // Child has no expiry but parent does — child would
                // outlive parent, which violates attenuation.
                return Err(AttenuationError::ExpiryExceedsParent {
                    requested: Timestamp::MAX,
                    available: parent_exp,
                });
            }
        }

        Ok(Self {
            id:         None,
            issuer,
            subject,
            resource,
            actions,
            not_before,
            expiry,
            proof:      Some(Box::new(parent)),
            signature:  None,
        })
    }

    // ── Time queries ─────────────────────────────────────────────────────────

    /// Returns `true` if this capability has expired at `at`.
    #[must_use]
    pub fn is_expired(&self, at: Timestamp) -> bool {
        self.expiry.map_or(false, |exp| at >= exp)
    }

    /// Returns `true` if this capability is not yet valid at `at`.
    #[must_use]
    pub fn is_premature(&self, at: Timestamp) -> bool {
        self.not_before.map_or(false, |nb| at < nb)
    }

    /// Returns `true` if this capability is temporally active at `at`:
    /// not expired and not premature.
    #[must_use]
    pub fn is_active(&self, at: Timestamp) -> bool {
        !self.is_expired(at) && !self.is_premature(at)
    }

    // ── Permission queries ────────────────────────────────────────────────────

    /// Returns `true` if this capability permits `action` on `resource`
    /// at time `at`.
    ///
    /// This is a structural check only — it does not verify signatures.
    /// Call `muspell_identity::verify_capability_chain` for full verification.
    #[must_use]
    pub fn permits(&self, resource: &ResourceId, action: &Action, at: Timestamp) -> bool {
        self.is_active(at)
            && resource.is_covered_by(&self.resource)
            && self.actions.permits(action)
    }

    // ── Chain introspection ───────────────────────────────────────────────────

    /// Returns the depth of the delegation chain.
    /// A root capability (no proof) has depth 0.
    /// Each delegation adds 1.
    #[must_use]
    pub fn chain_depth(&self) -> usize {
        match &self.proof {
            None        => 0,
            Some(proof) => 1 + proof.chain_depth(),
        }
    }

    /// Returns `true` if this is a root capability (no proof chain).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.proof.is_none()
    }

    /// Walk the chain and return all capabilities from root to self,
    /// inclusive, ordered root-first.
    #[must_use]
    pub fn chain(&self) -> Vec<&Capability> {
        let mut links = Vec::with_capacity(self.chain_depth() + 1);
        self.collect_chain(&mut links);
        links.reverse();
        links
    }

    fn collect_chain<'a>(&'a self, acc: &mut Vec<&'a Capability>) {
        acc.push(self);
        if let Some(proof) = &self.proof {
            proof.collect_chain(acc);
        }
    }

    /// Returns the root capability at the base of the delegation chain.
    #[must_use]
    pub fn root_capability(&self) -> &Capability {
        match &self.proof {
            None        => self,
            Some(proof) => proof.root_capability(),
        }
    }

    // ── Structural validation ─────────────────────────────────────────────────

    /// Validate the structural integrity of the capability and its full
    /// proof chain without performing cryptographic signature verification.
    ///
    /// Checks:
    /// - Each link's `issuer` equals the parent's `subject` (custody chain)
    /// - Each link's `actions` ⊆ parent's `actions`
    /// - Each link's `resource` is covered by the parent's `resource`
    /// - Each link's `expiry` does not exceed the parent's `expiry`
    /// - No link is missing a signature (all fields are `Some`)
    /// - Chain depth does not exceed [`MAX_CHAIN_DEPTH`]
    ///
    /// For full verification (including signature checks), use
    /// `muspell_identity::verify_capability_chain`.
    pub fn validate_structure(&self) -> Result<(), CapabilityError> {
        self.validate_recursive(0)
    }

    fn validate_recursive(&self, depth: usize) -> Result<(), CapabilityError> {
        if depth > MAX_CHAIN_DEPTH {
            return Err(CapabilityError::ChainTooDeep { depth });
        }

        if self.signature.is_none() {
            return Err(CapabilityError::MissingSignature {
                depth,
                issuer: self.issuer,
            });
        }

        if self.actions.is_empty() {
            return Err(CapabilityError::EmptyActionSet { depth });
        }

        if let Some(parent) = &self.proof {
            // Chain-of-custody: issuer must be parent's subject.
            if self.issuer != parent.subject {
                return Err(CapabilityError::CustodyBreak {
                    depth,
                    expected_issuer: parent.subject,
                    actual_issuer:   self.issuer,
                });
            }

            // Attenuation: actions must be subset of parent.
            if !self.actions.is_attenuated_by(&parent.actions) {
                return Err(CapabilityError::ActionsExceedParent {
                    depth,
                    child:  self.actions.clone(),
                    parent: parent.actions.clone(),
                });
            }

            // Attenuation: resource must be covered by parent.
            if !self.resource.is_covered_by(&parent.resource) {
                return Err(CapabilityError::ResourceNotCovered {
                    depth,
                    child:  self.resource.clone(),
                    parent: parent.resource.clone(),
                });
            }

            // Attenuation: expiry must not exceed parent's expiry.
            if let Some(parent_exp) = parent.expiry {
                match self.expiry {
                    None => {
                        return Err(CapabilityError::ExpiryExceedsParent {
                            depth,
                            child_expiry:  None,
                            parent_expiry: parent_exp,
                        });
                    }
                    Some(child_exp) if child_exp > parent_exp => {
                        return Err(CapabilityError::ExpiryExceedsParent {
                            depth,
                            child_expiry:  Some(child_exp),
                            parent_expiry: parent_exp,
                        });
                    }
                    _ => {}
                }
            }

            // Recurse into parent.
            parent.validate_recursive(depth + 1)?;
        }

        Ok(())
    }
}

/// Maximum allowed delegation chain depth.
///
/// Prevents pathological inputs (e.g. deeply nested chains used as a DoS
/// vector). Chosen conservatively — real-world chains are rarely > 3 deep.
pub const MAX_CHAIN_DEPTH: usize = 16;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors produced when constructing a delegated [`Capability`].
///
/// These are programmer-facing errors caught at delegation time,
/// not wire errors from malformed peer data.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AttenuationError {
    /// The issuer of the new capability is not the subject of the parent.
    IssuerNotParentSubject { 
    /// The DID that was expected to be the issuer based on the parent capability.
        expected: Did,
    /// The actual DID found as the issuer in the child capability.
        got: Did 
    },
    /// The issuer's capability does not include the `Delegate` action.
    DelegateActionNotGranted,
    /// The requested actions exceed what the parent capability grants.
    ActionsExceedParent {
    /// The set of actions requested in the child capability.
        requested: ActionSet,
    /// The set of actions actually available in the parent capability.
        available: ActionSet,
    },
    /// The requested resource is not covered by the parent's resource.
    ResourceNotCoveredByParent {
    /// The ResourceId requested in the child capability.
        requested: ResourceId,
    /// The ResourceId actually available in the parent capability.
        available: ResourceId,
    },
    /// The requested expiry extends beyond the parent's expiry.
    ExpiryExceedsParent {
    /// The expiration timestamp requested for the child.
        requested: Timestamp,
    /// The expiration timestamp available from the parent.
        available: Timestamp,
    },
}

impl fmt::Display for AttenuationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IssuerNotParentSubject { expected, got } => write!(
                f,
                "delegation issuer mismatch: expected {expected}, got {got}"
            ),
            Self::DelegateActionNotGranted => write!(
                f,
                "parent capability does not include the `delegate` action"
            ),
            Self::ActionsExceedParent { requested, available } => write!(
                f,
                "requested actions {requested} exceed parent's {available}"
            ),
            Self::ResourceNotCoveredByParent { requested, available } => write!(
                f,
                "resource {requested} is not covered by parent resource {available}"
            ),
            Self::ExpiryExceedsParent { requested, available } => write!(
                f,
                "expiry {requested} exceeds parent expiry {available}"
            ),
        }
    }
}

impl std::error::Error for AttenuationError {}

/// Errors produced during structural validation of a [`Capability`] chain.
///
/// These may originate from malformed peer data and should be treated as
/// untrusted-input errors, not programmer errors.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CapabilityError {
    /// The chain exceeds [`MAX_CHAIN_DEPTH`].
    ChainTooDeep { 
    /// The depth level where the chain became too deep.
      depth: usize },
    /// A link in the chain has no signature.
    MissingSignature { 
    /// The depth level where the signature was found missing.
      depth: usize,
    /// The DID of the issuer whose signature is missing.
      issuer: Did },
    /// A link has an empty action set (meaningless capability).
    EmptyActionSet { 
    /// The depth level where an empty action set was encountered.
      depth: usize },
    /// The chain-of-custody is broken: issuer ≠ parent's subject.
    CustodyBreak {
    /// The depth level where the chain of custody was broken.
        depth:           usize,
    /// The DID that was expected to sign this link.
        expected_issuer: Did,
    /// The DID that actually signed (or attempted to sign) this link.
        actual_issuer:   Did,
    },
    /// A child's actions exceed the parent's.
    ActionsExceedParent {
    /// The depth level where the action attenuation was violated.
        depth:  usize,
    /// The action set in the child capability.
        child:  ActionSet,
    /// The action set in the parent capability.
        parent: ActionSet,
    },
    /// A child's resource is not covered by the parent's.
    ResourceNotCovered {
    /// The depth level where the expiry time was violated.
        depth:  usize,
    /// The resource requested in the child capability.
        child:  ResourceId,
    /// The resource granted in the parent capability.
        parent: ResourceId,
    },
    /// A child's expiry extends beyond the parent's.
    ExpiryExceedsParent {
    /// The depth level where the expiry time was violated.
        depth:         usize,
     /// The expiry timestamp of the child capability (if any).
        child_expiry:  Option<Timestamp>,
    /// The expiry timestamp of the parent capability.
        parent_expiry: Timestamp,
    },
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainTooDeep { depth } =>
                write!(f, "chain exceeds maximum depth {MAX_CHAIN_DEPTH} (got {depth})"),
            Self::MissingSignature { depth, issuer } =>
                write!(f, "link at depth {depth} from {issuer} has no signature"),
            Self::EmptyActionSet { depth } =>
                write!(f, "link at depth {depth} has an empty action set"),
            Self::CustodyBreak { depth, expected_issuer, actual_issuer } =>
                write!(f, "custody break at depth {depth}: expected issuer {expected_issuer}, got {actual_issuer}"),
            Self::ActionsExceedParent { depth, child, parent } =>
                write!(f, "actions at depth {depth} ({child}) exceed parent ({parent})"),
            Self::ResourceNotCovered { depth, child, parent } =>
                write!(f, "resource at depth {depth} ({child}) not covered by parent ({parent})"),
            Self::ExpiryExceedsParent { depth, child_expiry, parent_expiry } =>
                write!(f, "expiry at depth {depth} ({child_expiry:?}) exceeds parent ({parent_expiry})"),
        }
    }
}

impl std::error::Error for CapabilityError {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentId, NamespaceId, Signature, Timestamp};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn did(byte: u8) -> Did {
        Did::from_bytes([byte; 32])
    }

    fn fake_sig() -> Signature {
        Signature::from_bytes([0xffu8; 64])
    }

    fn signed(mut cap: Capability) -> Capability {
        cap.signature = Some(fake_sig());
        cap
    }

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn ns(byte: u8) -> ResourceId {
        let owner = did(byte);
        ResourceId::Namespace(NamespaceId::derive(&owner, "test"))
    }

    fn root_cap(
        issuer: Did,
        subject: Did,
        resource: ResourceId,
        actions: ActionSet,
    ) -> Capability {
        signed(Capability::root(issuer, subject, resource, actions))
    }

    // ── Action ────────────────────────────────────────────────────────────────

    #[test]
    fn action_admin_subsumes_all() {
        let admin = Action::Admin;
        for a in [
            Action::Read,
            Action::Write,
            Action::Delete,
            Action::Delegate,
            Action::Custom("x".into()),
        ] {
            assert!(a.is_subsumed_by(&admin), "{a} should be subsumed by Admin");
        }
    }

    #[test]
    fn action_non_admin_only_subsumes_self() {
        assert!(Action::Read.is_subsumed_by(&Action::Read));
        assert!(!Action::Read.is_subsumed_by(&Action::Write));
        assert!(!Action::Write.is_subsumed_by(&Action::Read));
    }

    #[test]
    fn action_custom_equality() {
        let a = Action::Custom("foo".into());
        let b = Action::Custom("foo".into());
        let c = Action::Custom("bar".into());
        assert!(a.is_subsumed_by(&b));
        assert!(!a.is_subsumed_by(&c));
    }

    // ── ActionSet ─────────────────────────────────────────────────────────────

    #[test]
    fn action_set_permits_direct_member() {
        let set = ActionSet::from_actions([Action::Read, Action::Write]);
        assert!(set.permits(&Action::Read));
        assert!(set.permits(&Action::Write));
        assert!(!set.permits(&Action::Delete));
    }

    #[test]
    fn action_set_admin_permits_everything() {
        let set = ActionSet::admin();
        assert!(set.permits(&Action::Read));
        assert!(set.permits(&Action::Delete));
        assert!(set.permits(&Action::Custom("anything".into())));
    }

    #[test]
    fn action_set_is_attenuated_by_superset() {
        let parent = ActionSet::from_actions([Action::Read, Action::Write, Action::Delete]);
        let child  = ActionSet::from_actions([Action::Read]);
        assert!(child.is_attenuated_by(&parent));
    }

    #[test]
    fn action_set_is_not_attenuated_by_subset() {
        let parent = ActionSet::from_actions([Action::Read]);
        let child  = ActionSet::from_actions([Action::Read, Action::Write]);
        assert!(!child.is_attenuated_by(&parent));
    }

    #[test]
    fn action_set_intersect_basic() {
        let a = ActionSet::from_actions([Action::Read, Action::Write]);
        let b = ActionSet::from_actions([Action::Write, Action::Delete]);
        let c = a.intersect(&b);
        assert!(c.permits(&Action::Write));
        assert!(!c.permits(&Action::Read));
        assert!(!c.permits(&Action::Delete));
    }

    #[test]
    fn action_set_intersect_with_admin() {
        let a     = ActionSet::from_actions([Action::Read, Action::Write]);
        let admin = ActionSet::admin();
        // Admin intersected with anything returns the non-admin set.
        let result = a.intersect(&admin);
        assert!(result.permits(&Action::Read));
        assert!(result.permits(&Action::Write));
    }

    // ── ResourceId ───────────────────────────────────────────────────────────

    #[test]
    fn resource_wildcard_covers_everything() {
        let wc = ResourceId::Wildcard;
        assert!(ResourceId::Content(ContentId::blake3(b"x")).is_covered_by(&wc));
        assert!(ns(1).is_covered_by(&wc));
        assert!(ResourceId::Wildcard.is_covered_by(&wc));
    }

    #[test]
    fn resource_exact_covers_itself() {
        let cid = ContentId::blake3(b"hello");
        let r   = ResourceId::Content(cid);
        assert!(r.is_covered_by(&r.clone()));
    }

    #[test]
    fn resource_namespace_does_not_cover_content() {
        // Policy decision: namespace ⊇ content is for higher layers.
        let r_content = ResourceId::Content(ContentId::blake3(b"x"));
        let r_ns      = ns(1);
        assert!(!r_content.is_covered_by(&r_ns));
    }

    // ── Capability::root ──────────────────────────────────────────────────────

    #[test]
    fn root_cap_is_root() {
        let cap = root_cap(
            did(1), did(2),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        assert!(cap.is_root());
        assert_eq!(cap.chain_depth(), 0);
    }

    #[test]
    fn root_cap_permits_correct_action() {
        let cap = root_cap(
            did(1), did(2),
            ns(1),
            ActionSet::from_actions([Action::Read]),
        );
        assert!(cap.permits(&ns(1), &Action::Read, t(1000)));
        assert!(!cap.permits(&ns(1), &Action::Write, t(1000)));
    }

    // ── Capability::is_active ─────────────────────────────────────────────────

    #[test]
    fn cap_not_expired_without_expiry() {
        let cap = root_cap(did(1), did(2), ResourceId::Wildcard, ActionSet::admin());
        assert!(!cap.is_expired(t(999_999_999)));
    }

    #[test]
    fn cap_expired_at_or_after_expiry() {
        let mut cap = Capability::root(
            did(1), did(2),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        cap.expiry    = Some(t(1000));
        cap.signature = Some(fake_sig());
        assert!(!cap.is_expired(t(999)));
        assert!(cap.is_expired(t(1000)));  // exclusive upper bound
        assert!(cap.is_expired(t(1001)));
    }

    #[test]
    fn cap_premature_before_not_before() {
        let mut cap = Capability::root(
            did(1), did(2),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        cap.not_before = Some(t(500));
        cap.signature  = Some(fake_sig());
        assert!(cap.is_premature(t(499)));
        assert!(!cap.is_premature(t(500)));
        assert!(!cap.is_premature(t(501)));
    }

    // ── Capability::delegate (success) ────────────────────────────────────────

    #[test]
    fn delegate_success_simple() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        let parent = root_cap(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Write, Action::Delegate]),
        );

        let child = Capability::delegate(
            parent,
            bob,   // bob is the issuer (he was parent's subject)
            carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None,
            None,
        );
        assert!(child.is_ok(), "delegation should succeed: {child:?}");
        let child = child.unwrap();
        assert_eq!(child.chain_depth(), 1);
        assert!(!child.is_root());
    }

    #[test]
    fn delegate_success_attenuated_resource() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);
        let specific_ns = ns(42);

        let parent = root_cap(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );

        let child = Capability::delegate(
            parent,
            bob,
            carol,
            specific_ns,   // narrower resource — valid attenuation
            ActionSet::single(Action::Read),
            None,
            None,
        );
        assert!(child.is_ok());
    }

    #[test]
    fn delegate_success_with_expiry_within_parent() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        let mut parent = Capability::root(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );
        parent.expiry    = Some(t(2000));
        parent.signature = Some(fake_sig());

        let child = Capability::delegate(
            parent,
            bob,
            carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None,
            Some(t(1000)),   // child expires before parent — valid
        );
        assert!(child.is_ok());
    }

    // ── Capability::delegate (failures) ──────────────────────────────────────

    #[test]
    fn delegate_fails_wrong_issuer() {
        let alice   = did(1);
        let bob     = did(2);
        let carol   = did(3);
        let mallory = did(9);

        let parent = root_cap(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );

        let result = Capability::delegate(
            parent,
            mallory,  // NOT bob — wrong issuer
            carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None,
            None,
        );
        assert!(matches!(result, Err(AttenuationError::IssuerNotParentSubject { .. })));
    }

    #[test]
    fn delegate_fails_actions_exceed_parent() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        let parent = root_cap(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );

        let result = Capability::delegate(
            parent,
            bob,
            carol,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delete]),  // Delete not in parent
            None,
            None,
        );
        assert!(matches!(result, Err(AttenuationError::ActionsExceedParent { .. })));
    }

    #[test]
    fn delegate_fails_resource_not_covered() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        let specific_resource = ns(5);
        let other_resource    = ns(6);

        let parent = root_cap(
            alice, bob,
            specific_resource,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );

        let result = Capability::delegate(
            parent,
            bob,
            carol,
            other_resource,  // different namespace — not covered
            ActionSet::single(Action::Read),
            None,
            None,
        );
        assert!(matches!(result, Err(AttenuationError::ResourceNotCoveredByParent { .. })));
    }

    #[test]
    fn delegate_fails_expiry_exceeds_parent() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        let mut parent = Capability::root(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );
        parent.expiry    = Some(t(1000));
        parent.signature = Some(fake_sig());

        let result = Capability::delegate(
            parent,
            bob,
            carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None,
            Some(t(2000)),  // beyond parent expiry
        );
        assert!(matches!(result, Err(AttenuationError::ExpiryExceedsParent { .. })));
    }

    #[test]
    fn delegate_fails_no_delegate_action_in_parent() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        // Parent grants Read only — no Delegate, no Admin.
        let parent = root_cap(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
        );

        let result = Capability::delegate(
            parent,
            bob,
            carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None,
            None,
        );
        assert!(matches!(result, Err(AttenuationError::DelegateActionNotGranted)));
    }

    // ── validate_structure ────────────────────────────────────────────────────

    #[test]
    fn validate_root_cap_passes() {
        let cap = root_cap(did(1), did(2), ResourceId::Wildcard, ActionSet::admin());
        assert!(cap.validate_structure().is_ok());
    }

    #[test]
    fn validate_fails_missing_signature() {
        let cap = Capability::root(
            did(1), did(2),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        // signature is None
        let err = cap.validate_structure().unwrap_err();
        assert!(matches!(err, CapabilityError::MissingSignature { .. }));
    }

    #[test]
    fn validate_fails_empty_action_set() {
        let mut cap = Capability::root(
            did(1), did(2),
            ResourceId::Wildcard,
            ActionSet::empty(),
        );
        cap.signature = Some(fake_sig());
        let err = cap.validate_structure().unwrap_err();
        assert!(matches!(err, CapabilityError::EmptyActionSet { .. }));
    }

    #[test]
    fn validate_two_link_chain_passes() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        let parent = root_cap(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );

        let mut child = Capability::delegate(
            parent,
            bob, carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None, None,
        ).unwrap();
        child.signature = Some(fake_sig());

        assert!(child.validate_structure().is_ok());
        assert_eq!(child.chain_depth(), 1);
        assert_eq!(child.chain().len(), 2);
    }

    #[test]
    fn validate_chain_lists_root_first() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        let parent = root_cap(
            alice, bob,
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );

        let mut child = Capability::delegate(
            parent.clone(),
            bob, carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None, None,
        ).unwrap();
        child.signature = Some(fake_sig());

        let chain = child.chain();
        // chain[0] should be the root (alice→bob)
        assert_eq!(chain[0].issuer, alice);
        assert_eq!(chain[0].subject, bob);
        // chain[1] should be the child (bob→carol)
        assert_eq!(chain[1].issuer, bob);
        assert_eq!(chain[1].subject, carol);
    }

    #[test]
    fn root_capability_at_base_of_chain() {
        let alice = did(1);
        let bob   = did(2);
        let carol = did(3);

        let parent = root_cap(alice, bob, ResourceId::Wildcard, ActionSet::admin());
        let mut child = Capability::delegate(
            parent,
            bob, carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None, None,
        ).unwrap();
        child.signature = Some(fake_sig());

        let root = child.root_capability();
        assert_eq!(root.issuer,  alice);
        assert_eq!(root.subject, bob);
        assert!(root.is_root());
    }
}
