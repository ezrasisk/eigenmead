//! `RpcDispatcher` — the receive-side routing loop.
//!
//! ## Responsibility
//!
//! The dispatcher reads incoming frames from the transport layer and
//! routes each one to the correct destination:
//!
//! ```text
//! incoming frame
//!     │
//!     ├─ frame.causation is Some(id)   → pending.resolve(id, frame)
//!     │                                  (delivers to a waiting RpcClient::call)
//!     │
//!     └─ frame.causation is None
//!         ├─ frame.expects_response()   → router.route(frame)
//!         │                               (dispatches to RequestHandler)
//!         └─ otherwise                  → router.route(frame)
//!                                         (forwarded to unsolicited channel)
//! ```
//!
//! Ping/Pong/Goodbye and other lifecycle frames are NOT handled here —
//! they are handled at the transport layer (`MuspellConnection::recv_loop`)
//! before frames reach the RPC layer. By the time a frame reaches the
//! dispatcher, it is guaranteed to be an application-layer frame.
//!
//! ## Integration with the transport layer
//!
//! The dispatcher runs inside `MuspellConnection::recv_loop`'s handler
//! closure, or as a standalone task reading from an `mpsc::Receiver<Frame>`.
//! Both patterns are supported.

use std::sync::Arc;

use muspell_proto::Frame;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::pending::PendingRequests;
use crate::router::RpcRouter;

// ── RpcDispatcher ─────────────────────────────────────────────────────────────

/// The receive-side routing component of the RPC layer.
///
/// Constructed by `RpcLayer::new`. Run by calling `run(incoming)` in a
/// spawned task.
pub struct RpcDispatcher {
    pending: Arc<PendingRequests>,
    router:  Arc<RpcRouter>,
}

impl RpcDispatcher {
    /// Construct. Prefer `RpcLayer::new`.
    #[must_use]
    pub(crate) fn new(pending: Arc<PendingRequests>, router: Arc<RpcRouter>) -> Self {
        Self { pending, router }
    }

    /// Run the dispatch loop until `incoming` is closed.
    ///
    /// This method should be called in a dedicated `tokio::spawn` task.
    /// It drives all request routing and response delivery for the connection.
    ///
    /// ## Termination
    ///
    /// The loop exits cleanly when `incoming` is closed (i.e. the transport
    /// task has stopped sending frames). Any in-flight `RpcClient::call`
    /// futures waiting on a response will receive `RpcError::ChannelClosed`
    /// when the `PendingGuard` receiver sees the sender dropped.
    pub async fn run(self, mut incoming: mpsc::Receiver<Frame>) {
        debug!("dispatch: loop started");
        while let Some(frame) = incoming.recv().await {
            self.dispatch_one(frame).await;
        }
        debug!("dispatch: incoming channel closed, loop exiting");
    }

    /// Dispatch a single frame. Exposed for integration with other recv loops
    /// (e.g. as a handler in `MuspellConnection::recv_loop`).
    pub async fn dispatch_one(&self, frame: Frame) {
        if let Some(causation_id) = frame.causation {
            // This is a response to a prior request.
            debug!(
                "dispatch: response {} causation={:032x}",
                frame.variant_name(),
                causation_id.as_u128()
            );
            let delivered = self.pending.resolve(causation_id, frame).await;
            if !delivered {
                warn!(
                    "dispatch: response with causation={:032x} had no waiting caller",
                    causation_id.as_u128()
                );
            }
        } else {
            // This is a new request or unsolicited frame.
            debug!(
                "dispatch: request/unsolicited {} id={:032x}",
                frame.variant_name(),
                frame.id.as_u128()
            );
            self.router.route(frame).await;
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{NullHandler, RpcRouter, make_get_response};
    use muspell_proto::{
        ContentId, Frame, FrameBody, FrameId, GetFrame, GetResponseFrame,
        GetResult, Timestamp, AnnounceFrame, NodeId,
    };
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn fid(v: u128) -> FrameId { FrameId::from_u128(v) }
    fn t(s: i64)   -> Timestamp { Timestamp::from_secs(s) }

    fn make_dispatcher() -> (
        RpcDispatcher,
        mpsc::Receiver<Frame>,  // outgoing responses
        mpsc::Receiver<Frame>,  // unsolicited frames
    ) {
        let pending          = Arc::new(PendingRequests::new());
        let (out_tx, out_rx) = mpsc::channel(32);
        let (uns_tx, uns_rx) = mpsc::channel(32);
        let router   = Arc::new(RpcRouter::new(Arc::new(NullHandler), out_tx, uns_tx));
        let dispatch = RpcDispatcher::new(pending, router);
        (dispatch, out_rx, uns_rx)
    }

    fn make_dispatcher_with_pending() -> (
        RpcDispatcher,
        Arc<PendingRequests>,
        mpsc::Receiver<Frame>,
        mpsc::Receiver<Frame>,
    ) {
        let pending          = Arc::new(PendingRequests::new());
        let (out_tx, out_rx) = mpsc::channel(32);
        let (uns_tx, uns_rx) = mpsc::channel(32);
        let router   = Arc::new(RpcRouter::new(Arc::new(NullHandler), out_tx, uns_tx));
        let dispatch = RpcDispatcher::new(pending.clone(), router);
        (dispatch, pending, out_rx, uns_rx)
    }

    // ── Response routing via causation ────────────────────────────────────────

    #[tokio::test]
    async fn response_with_causation_resolves_pending() {
        let (dispatch, pending, _out, _uns) = make_dispatcher_with_pending();
        let req_id = fid(1);

        // Register a pending entry.
        let rx = pending.register(req_id).await;

        // Simulate a response arriving with causation = req_id.
        let response = make_get_response(req_id, GetResult::NotFound);
        dispatch.dispatch_one(response.clone()).await;

        // The pending future should receive the response.
        let received = rx.await.expect("should receive the frame");
        assert_eq!(received.causation, Some(req_id));
        assert!(matches!(received.body, FrameBody::GetResponse(_)));
    }

    #[tokio::test]
    async fn response_with_unknown_causation_logs_warning() {
        // This should not panic — just warn and discard.
        let (dispatch, _out, _uns) = make_dispatcher();
        let orphan_response = make_get_response(fid(999), GetResult::NotFound);
        // causation = fid(999), nothing registered for it
        dispatch.dispatch_one(orphan_response).await; // must not panic
    }

    // ── Request routing to router ─────────────────────────────────────────────

    #[tokio::test]
    async fn request_without_causation_goes_to_router() {
        let (dispatch, mut out, _uns) = make_dispatcher();
        let id = fid(50);
        let frame = Frame::new(id, t(0), FrameBody::Get(GetFrame {
            content_id: ContentId::blake3(b"test"),
            byte_range: None,
        }));
        // No causation → goes to router (NullHandler) → sends ErrorFrame back.
        dispatch.dispatch_one(frame).await;
        let response = out.recv().await.expect("router should send a response");
        assert_eq!(response.causation, Some(id));
        // NullHandler returns an error frame.
        assert!(matches!(response.body, FrameBody::Error(_)));
    }

    // ── Unsolicited frame forwarding ──────────────────────────────────────────

    #[tokio::test]
    async fn unsolicited_announce_forwarded_to_channel() {
        let (dispatch, _out, mut uns) = make_dispatcher();
        let id = fid(60);
        let frame = Frame::new(id, t(0), FrameBody::Announce(AnnounceFrame {
            node_id:        NodeId::from_bytes([5u8; 32]),
            did:            None,
            namespaces:     vec![],
            content_sample: vec![],
            ttl_secs:       300,
        }));
        dispatch.dispatch_one(frame).await;
        let received = uns.recv().await.expect("unsolicited frame forwarded");
        assert!(matches!(received.body, FrameBody::Announce(_)));
    }

    // ── Run loop ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn run_loop_processes_frames_until_channel_closes() {
        let (dispatch, pending, mut out, _uns) = make_dispatcher_with_pending();
        let (in_tx, in_rx) = mpsc::channel::<Frame>(16);

        // Spawn the dispatch loop.
        tokio::spawn(dispatch.run(in_rx));

        // Send a response frame through the loop.
        let req_id   = fid(100);
        let rx       = pending.register(req_id).await;
        let response = make_get_response(req_id, GetResult::NotFound);
        in_tx.send(response).await.unwrap();

        // The pending receiver should get the frame.
        let received = rx.await.expect("received through run loop");
        assert_eq!(received.causation, Some(req_id));

        // Close the channel — loop exits cleanly.
        drop(in_tx);
        // Give the loop task a moment to notice the close.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let _ = out; // suppress warning
    }

    #[tokio::test]
    async fn run_loop_handles_multiple_frames_in_order() {
        let (dispatch, pending, _out, _uns) = make_dispatcher_with_pending();
        let (in_tx, in_rx) = mpsc::channel::<Frame>(16);
        tokio::spawn(dispatch.run(in_rx));

        let ids: Vec<FrameId> = (0..5).map(|i| fid(i as u128)).collect();
        let mut receivers = Vec::new();
        for &id in &ids {
            receivers.push(pending.register(id).await);
        }

        for &id in &ids {
            let response = make_get_response(id, GetResult::NotFound);
            in_tx.send(response).await.unwrap();
        }

        for (i, rx) in receivers.into_iter().enumerate() {
            let frame = rx.await.expect("all responses delivered");
            assert_eq!(frame.causation, Some(ids[i]));
        }
    }
}
