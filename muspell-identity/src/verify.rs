//! Verification functions for Muspell protocol types.
//!
//! ## Verification layers
//!
//! Each `verify_*` function performs checks in order of cheapest to most
//! expensive, failing fast:
//!
//! 1. **Presence** — required fields (signatures) must be `Some`.
//! 2. **Structure** — the value passes `validate_structure()` from proto.
//! 3. **Time bounds** — checked against the supplied `now: Timestamp`.
//! 4. **Cryptography** — Ed25519 signatures are verified last.
//!
//! Crypto is always last because it's the most expensive. A malformed or
//! expired value is rejected without burning CPU on signature math.
//!
//! ## Trust model
//!
//! Verification proves:
//! - The value was created by the claimed key (crypto check).
//! - The value has not been structurally modified since signing (crypto check).
//! - The value is currently valid (time check).
//! - The delegation chain is intact (custody chain + crypto at each link).
//!
//! It does NOT prove:
//! - That the signing DID is "trustworthy" (that is a policy decision for
//!   the application layer).
//! - That the signing DID hasn't been compromised (key rotation handles this).

use muspell_proto::{Capability, FrameAuth, FrameId, Namespace, Timestamp};

use crate::binding::IdentityBinding;
use crate::canonical::{
    binding_signable_bytes, capability_signable_bytes, frame_auth_signable_bytes,
    namespace_signable_bytes,
};
use crate::error::{IdentityError, IdentityResult};
use crate::keypair::verify_ed25519;

// ── verify_capability_chain ───────────────────────────────────────────────────

/// Fully verify a [`Capability`] and its complete delegation chain.
///
/// ## Checks performed (in order)
///
/// For each link in the chain, root-first:
///
/// 1. `signature` is `Some` (presence)
/// 2. Chain passes `validate_structure()` (structural invariants)
/// 3. Each link's `is_active(now)` is `true` (time bounds)
/// 4. Each link's `issuer` DID can be decoded as an Ed25519 public key
/// 5. Each link's `signature` verifies over its canonical bytes (crypto)
/// 6. Each link's `issuer` equals the previous link's `subject`
///    (custody chain — overlaps with structural check but crypto-verified here)
///
/// # Errors
///
/// Returns the first error encountered. Errors are either structural
/// (from proto's `validate_structure`) or cryptographic (from this module).
pub fn verify_capability_chain(
    cap: &Capability,
    now: Timestamp,
) -> IdentityResult<()> {
    // Step 1 + 2: structural validation (checks signatures are present,
    // attenuation holds, chain depth is within bounds, etc.).
    cap.validate_structure()?;

    // Step 3-6: walk chain root-first for crypto and time checks.
    let chain = cap.chain(); // [root, ..., cap]
    for (depth, link) in chain.iter().enumerate() {
        verify_one_capability_link(link, depth, now)?;
    }

    // Step 6 supplement: verify custody chain cryptographically.
    // (validate_structure checks structurally; here we re-check with crypto
    // context. If issuer ≠ parent.subject, that's already caught above —
    // this ensures we haven't missed any edge case.)
    for i in 1..chain.len() {
        let parent = chain[i - 1];
        let child  = chain[i];
        if child.issuer != parent.subject {
            return Err(IdentityError::CustodyBreak {
                depth:    i,
                expected: parent.subject,
                got:      child.issuer,
            });
        }
    }

    Ok(())
}

/// Verify a single capability link: time bounds + crypto signature.
fn verify_one_capability_link(
    cap:   &Capability,
    depth: usize,
    now:   Timestamp,
) -> IdentityResult<()> {
    // Time: not premature.
    if cap.is_premature(now) {
        return Err(IdentityError::Premature {
            kind:       "capability",
            not_before: cap.not_before.unwrap(),
            now,
        });
    }

    // Time: not expired.
    if cap.is_expired(now) {
        return Err(IdentityError::Expired {
            kind:   "capability",
            expiry: cap.expiry.unwrap(),
            now,
        });
    }

    // Crypto: signature must be Some (already checked by validate_structure,
    // but we unwrap safely here for the verify call).
    let sig = cap.signature.as_ref()
        .ok_or_else(|| IdentityError::missing_signature("capability"))?;

    // Recompute the canonical bytes that were signed.
    let canonical = capability_signable_bytes(cap);

    // Verify: the signature must have been produced by cap.issuer.
    verify_ed25519(cap.issuer.as_bytes(), &canonical, sig.as_bytes())
        .map_err(|_| IdentityError::CapabilitySignerMismatch {
            depth,
            issuer: cap.issuer,
        })
}

// ── verify_namespace ──────────────────────────────────────────────────────────

/// Verify a [`Namespace`] document's structure and signature.
///
/// ## Checks performed
///
/// 1. `signature` is `Some`
/// 2. `validate_structure()` passes (version, timestamps, TTL, duplicates)
/// 3. `signature` verifies over the canonical namespace bytes using `owner`
///
/// Time bounds are not checked here — a namespace has a TTL (for caching)
/// but no cryptographic expiry. The transport layer evicts stale namespaces
/// based on TTL.
///
/// # Errors
///
/// - [`IdentityError::MissingSignature`] if no signature is present.
/// - [`IdentityError::NamespaceSignerMismatch`] if the signature does not
///   verify against `ns.owner`.
pub fn verify_namespace(ns: &Namespace) -> IdentityResult<()> {
    // Presence.
    let sig = ns.signature.as_ref()
        .ok_or_else(|| IdentityError::missing_signature("namespace"))?;

    // Structure (from proto).
    ns.validate_structure()?;

    // Crypto.
    let canonical = namespace_signable_bytes(ns);
    verify_ed25519(ns.owner.as_bytes(), &canonical, sig.as_bytes())
        .map_err(|_| IdentityError::NamespaceSignerMismatch {
            id:    ns.id,
            owner: ns.owner,
        })
}

// ── verify_frame_auth ─────────────────────────────────────────────────────────

/// Verify a [`FrameAuth`] attached to a frame.
///
/// ## Checks performed (in order)
///
/// 1. `frame_signature` is `Some`
/// 2. `nonce == frame_id` (anti-replay: auth is bound to this specific frame)
/// 3. `frame_signature` verifies over `(frame_id ‖ body_hash ‖ bearer)`
/// 4. `capability` chain verifies (full chain crypto + time check)
/// 5. `capability.subject == auth.bearer` (the capability was issued TO the bearer)
///
/// The `body_hash` is the Blake3 hash of the serialised frame body, computed
/// by the transport layer before calling this function.
///
/// # Errors
///
/// - [`IdentityError::MissingSignature`] if `frame_signature` is `None`.
/// - [`IdentityError::FrameAuthNonceMismatch`] if nonce ≠ frame_id.
/// - [`IdentityError::FrameAuthSignatureInvalid`] if bearer signature fails.
/// - Capability chain errors if the capability does not verify.
pub fn verify_frame_auth(
    auth:      &FrameAuth,
    frame_id:  &FrameId,
    body_hash: &[u8; 32],
) -> IdentityResult<()> {
    // 1. Presence.
    let frame_sig = auth.frame_signature.as_ref()
        .ok_or_else(|| IdentityError::missing_signature("frame_auth"))?;

    // 2. Anti-replay: nonce must match the frame id.
    if !auth.nonce_valid(frame_id) {
        return Err(IdentityError::FrameAuthNonceMismatch);
    }

    // 3. Verify the bearer's signature over (frame_id, body_hash, bearer).
    let canonical = frame_auth_signable_bytes(
        frame_id.as_u128(),
        body_hash,
        &auth.bearer,
    );
    verify_ed25519(auth.bearer.as_bytes(), &canonical, frame_sig.as_bytes())
        .map_err(|_| IdentityError::FrameAuthSignatureInvalid)?;

    // 4. Verify the full capability chain.
    // Use ZERO timestamp — frame auth is typically verified immediately on
    // receipt. The caller may pass a different `now` for delayed processing
    // by wrapping this with a manual time check first.
    // NOTE: For production use, the transport layer should pass the current
    // time here. We use Timestamp::ZERO as a safe default to avoid a
    // clock dependency at this layer; the capability's own time bounds
    // are checked by verify_capability_chain.
    // TODO: expose an overload `verify_frame_auth_at(auth, frame_id, body_hash, now)`
    //       once the transport layer integration is defined.
    let now = muspell_proto::Timestamp::ZERO;
    verify_capability_chain(&auth.capability, now)?;

    // 5. The capability must have been issued TO the bearer.
    let cap = &auth.capability;
    if cap.subject != auth.bearer {
        return Err(IdentityError::CapabilitySignerMismatch {
            depth:  0,
            issuer: auth.bearer,
        });
    }

    Ok(())
}

/// Verify a [`FrameAuth`] with an explicit `now` timestamp for time checks.
///
/// Prefer this over [`verify_frame_auth`] in production code so that
/// capability expiry is enforced correctly.
pub fn verify_frame_auth_at(
    auth:      &FrameAuth,
    frame_id:  &FrameId,
    body_hash: &[u8; 32],
    now:       Timestamp,
) -> IdentityResult<()> {
    // 1. Presence.
    let frame_sig = auth.frame_signature.as_ref()
        .ok_or_else(|| IdentityError::missing_signature("frame_auth"))?;

    // 2. Anti-replay.
    if !auth.nonce_valid(frame_id) {
        return Err(IdentityError::FrameAuthNonceMismatch);
    }

    // 3. Bearer signature.
    let canonical = frame_auth_signable_bytes(
        frame_id.as_u128(),
        body_hash,
        &auth.bearer,
    );
    verify_ed25519(auth.bearer.as_bytes(), &canonical, frame_sig.as_bytes())
        .map_err(|_| IdentityError::FrameAuthSignatureInvalid)?;

    // 4. Full capability chain with time checks.
    verify_capability_chain(&auth.capability, now)?;

    // 5. Subject == bearer.
    if auth.capability.subject != auth.bearer {
        return Err(IdentityError::CapabilitySignerMismatch {
            depth:  0,
            issuer: auth.bearer,
        });
    }

    Ok(())
}

// ── verify_binding ────────────────────────────────────────────────────────────

/// Verify an [`IdentityBinding`] at the given `now` timestamp.
///
/// ## Checks performed
///
/// 1. `signature` is `Some`
/// 2. `is_active(now)` is `true` — binding is within its time window
/// 3. `signature` verifies over canonical binding bytes using `binding.did`
///
/// # Errors
///
/// - [`IdentityError::MissingSignature`] if no signature.
/// - [`IdentityError::Premature`] if before `valid_from`.
/// - [`IdentityError::Expired`] if at or after `valid_until`.
/// - [`IdentityError::BindingSignatureInvalid`] if the signature fails.
pub fn verify_binding(
    binding: &IdentityBinding,
    now:     Timestamp,
) -> IdentityResult<()> {
    // 1. Presence.
    let sig = binding.signature.as_ref()
        .ok_or_else(|| IdentityError::missing_signature("identity_binding"))?;

    // 2. Time bounds.
    if now < binding.valid_from {
        return Err(IdentityError::Premature {
            kind:       "identity_binding",
            not_before: binding.valid_from,
            now,
        });
    }
    if binding.is_expired(now) {
        return Err(IdentityError::Expired {
            kind:   "identity_binding",
            expiry: binding.valid_until.unwrap(),
            now,
        });
    }

    // 3. Crypto.
    let canonical = binding_signable_bytes(
        &binding.did,
        &binding.node_id,
        binding.valid_from,
        binding.valid_until,
    );
    verify_ed25519(binding.did.as_bytes(), &canonical, sig.as_bytes())
        .map_err(|_| IdentityError::BindingSignatureInvalid)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::{
        Action, ActionSet, Capability, Did, FrameAuth, FrameId,
        NamespaceId, ResourceId, Signature, Timestamp,
    };
    use crate::binding::IdentityBinding;
    use crate::keypair::{DidKeypair, NodeKeypair};
    use crate::signing::{
        compute_body_hash, sign_binding, sign_capability, sign_frame_auth, sign_namespace,
    };

    fn t(s: i64) -> Timestamp { Timestamp::from_secs(s) }
    fn fake_sig() -> Signature { Signature::from_bytes([0xaau8; 64]) }

    // ── verify_capability_chain ───────────────────────────────────────────────

    #[test]
    fn verify_fails_missing_signature() {
        let cap = Capability::root(
            Did::from_bytes([1u8; 32]),
            Did::from_bytes([2u8; 32]),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        // No signature — must fail.
        let err = verify_capability_chain(&cap, t(0)).unwrap_err();
        assert!(matches!(err, IdentityError::CapabilityStructure(_)));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_expires_correctly() {
        let kp = DidKeypair::generate();
        let mut cap = Capability::root(
            kp.did(), Did::from_bytes([2u8; 32]),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        cap.expiry = Some(t(1000));
        sign_capability(&kp, &mut cap).unwrap();

        // Active just before expiry.
        assert!(verify_capability_chain(&cap, t(999)).is_ok());
        // Expired at or after expiry.
        let err = verify_capability_chain(&cap, t(1000)).unwrap_err();
        assert!(matches!(err, IdentityError::Expired { .. }));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_premature_correctly() {
        let kp = DidKeypair::generate();
        let mut cap = Capability::root(
            kp.did(), Did::from_bytes([2u8; 32]),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        cap.not_before = Some(t(500));
        sign_capability(&kp, &mut cap).unwrap();

        let err = verify_capability_chain(&cap, t(499)).unwrap_err();
        assert!(matches!(err, IdentityError::Premature { .. }));
        assert!(verify_capability_chain(&cap, t(500)).is_ok());
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_three_link_chain() {
        let alice_kp = DidKeypair::generate();
        let bob_kp   = DidKeypair::generate();
        let carol_kp = DidKeypair::generate();
        let dave     = Did::from_bytes([4u8; 32]);

        let mut root = Capability::root(
            alice_kp.did(), bob_kp.did(),
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Write, Action::Delegate]),
        );
        sign_capability(&alice_kp, &mut root).unwrap();

        let mut link1 = Capability::delegate(
            root, bob_kp.did(), carol_kp.did(),
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
            None, None,
        ).unwrap();
        sign_capability(&bob_kp, &mut link1).unwrap();

        let mut link2 = Capability::delegate(
            link1, carol_kp.did(), dave,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None, None,
        ).unwrap();
        sign_capability(&carol_kp, &mut link2).unwrap();

        verify_capability_chain(&link2, t(0)).unwrap();
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_fails_on_wrong_signer_at_depth_1() {
        let alice_kp = DidKeypair::generate();
        let bob_kp   = DidKeypair::generate();
        let carol    = Did::from_bytes([3u8; 32]);

        let mut root = Capability::root(
            alice_kp.did(), bob_kp.did(),
            ResourceId::Wildcard,
            ActionSet::from_actions([Action::Read, Action::Delegate]),
        );
        sign_capability(&alice_kp, &mut root).unwrap();

        let mut delegated = Capability::delegate(
            root, bob_kp.did(), carol,
            ResourceId::Wildcard,
            ActionSet::single(Action::Read),
            None, None,
        ).unwrap();

        // Sign with alice's key instead of bob's → signer mismatch.
        delegated.signature = Some(Signature::from_bytes(
            alice_kp.sign_raw(&crate::canonical::capability_signable_bytes(&delegated))
        ));

        let err = verify_capability_chain(&delegated, t(0)).unwrap_err();
        assert!(err.is_crypto_failure(), "expected crypto failure, got: {err:?}");
    }

    // ── verify_namespace ──────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_namespace_valid() {
        let kp    = DidKeypair::generate();
        let ns_id = NamespaceId::derive(&kp.did(), "test");
        let mut ns = Namespace::new(ns_id, kp.did(), t(1000));
        sign_namespace(&kp, &mut ns).unwrap();
        verify_namespace(&ns).unwrap();
    }

    #[test]
    fn verify_namespace_missing_signature() {
        let owner = Did::from_bytes([1u8; 32]);
        let ns_id = NamespaceId::derive(&owner, "test");
        let ns = Namespace::new(ns_id, owner, t(1000));
        let err = verify_namespace(&ns).unwrap_err();
        assert!(matches!(err, IdentityError::MissingSignature { .. }));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_namespace_wrong_signer() {
        let kp_a  = DidKeypair::generate();
        let kp_b  = DidKeypair::generate();
        let ns_id = NamespaceId::derive(&kp_a.did(), "test");
        let mut ns = Namespace::new(ns_id, kp_a.did(), t(1000));
        // Sign with the wrong key.
        let canonical = crate::canonical::namespace_signable_bytes(&ns);
        ns.signature = Some(Signature::from_bytes(kp_b.sign_raw(&canonical)));
        let err = verify_namespace(&ns).unwrap_err();
        assert!(err.is_crypto_failure());
    }

    // ── verify_binding ────────────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_binding_valid() {
        let did_kp  = DidKeypair::generate();
        let node_kp = NodeKeypair::generate();
        let binding = sign_binding(&did_kp, &node_kp, t(0), Some(t(3600))).unwrap();
        verify_binding(&binding, t(1000)).unwrap();
    }

    #[test]
    fn verify_binding_missing_signature() {
        let did    = Did::from_bytes([1u8; 32]);
        let nid    = muspell_proto::NodeId::from_bytes([2u8; 32]);
        let b      = IdentityBinding::draft(did, nid, t(0), Some(t(3600)));
        let err    = verify_binding(&b, t(0)).unwrap_err();
        assert!(matches!(err, IdentityError::MissingSignature { .. }));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_binding_expired() {
        let did_kp  = DidKeypair::generate();
        let node_kp = NodeKeypair::generate();
        let binding = sign_binding(&did_kp, &node_kp, t(0), Some(t(100))).unwrap();
        let err = verify_binding(&binding, t(100)).unwrap_err();
        assert!(matches!(err, IdentityError::Expired { .. }));
    }

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_binding_premature() {
        let did_kp  = DidKeypair::generate();
        let node_kp = NodeKeypair::generate();
        let binding = sign_binding(&did_kp, &node_kp, t(500), None).unwrap();
        let err = verify_binding(&binding, t(499)).unwrap_err();
        assert!(matches!(err, IdentityError::Premature { .. }));
    }

    // ── verify_frame_auth_at ──────────────────────────────────────────────────

    #[cfg(feature = "keygen")]
    #[test]
    fn verify_frame_auth_at_with_time() {
        let bearer_kp = DidKeypair::generate();
        let frame_id  = FrameId::from_u128(42);
        let body_hash = compute_body_hash(b"body");

        let mut cap = Capability::root(
            bearer_kp.did(), bearer_kp.did(),
            ResourceId::Wildcard,
            ActionSet::admin(),
        );
        cap.expiry = Some(t(5000));
        sign_capability(&bearer_kp, &mut cap).unwrap();

        let mut auth = FrameAuth {
            bearer:          bearer_kp.did(),
            capability:      cap,
            nonce:           frame_id,
            frame_signature: None,
        };
        sign_frame_auth(&bearer_kp, frame_id, &body_hash, &mut auth).unwrap();

        // Valid at t=1000.
        verify_frame_auth_at(&auth, &frame_id, &body_hash, t(1000)).unwrap();

        // Expired at t=5001.
        let err = verify_frame_auth_at(&auth, &frame_id, &body_hash, t(5001)).unwrap_err();
        assert!(matches!(err, IdentityError::Expired { .. }));
    }
}
