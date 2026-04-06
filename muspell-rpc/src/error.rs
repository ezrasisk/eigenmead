//! Errors produced by `muspell-rpc` operations.

use muspell_proto::ErrorCode;
use muspell_transport::TransportError;
use std::{fmt, time::Duration};

/// The unified error type for all `muspell-rpc` operations.
///
/// ## Categories and how to handle them
///
/// | Variant         | Cause                                 | Response             |
/// |-----------------|---------------------------------------|----------------------|
/// | `Timeout`       | Peer too slow / unreachable           | Retry with backoff   |
/// | `Transport`     | Wire-level encode/decode/I/O error    | Close connection     |
/// | `PeerError`     | Peer returned an `ErrorFrame`         | Inspect `code`       |
/// | `ChannelClosed` | Transport task exited                 | Reconnect            |
/// | `Cancelled`     | Caller dropped the future             | No action needed     |
/// | `NoHandler`     | Server received an unhandled req type | Peer needs updating  |
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// The peer did not respond within the configured timeout.
    ///
    /// The in-flight entry is cleaned up automatically; the caller may retry.
    #[error("RPC timeout for {request} after {after:.1?}")]
    Timeout {
        /// The name of the request that timed out (e.g. `"Get"`, `"Put"`).
        request: &'static str,
        /// How long we waited before giving up.
        after:   Duration,
    },

    /// The underlying transport reported an error.
    ///
    /// This usually means the frame could not be encoded/sent, or the
    /// connection was lost. The connection should be closed.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// The remote peer responded with an `ErrorFrame`.
    ///
    /// The peer explicitly signalled a problem with the request.
    /// Inspect `code` to determine whether to retry, report to the user, etc.
    #[error("peer error [{code}]: {message}")]
    PeerError {
        /// The typed error code from the peer's `ErrorFrame`.
        code:    ErrorCode,
        /// The human-readable message from the peer's `ErrorFrame`.
        message: String,
        /// Whether the peer considers the connection unrecoverable.
        fatal:   bool,
    },

    /// The dispatch channel was closed unexpectedly.
    ///
    /// This means the transport task has exited. The `RpcClient` is no
    /// longer usable. Reconnect at the node layer.
    #[error("dispatch channel closed — transport has shut down")]
    ChannelClosed,

    /// The in-flight future was cancelled (dropped) before the response arrived.
    ///
    /// This is not an error from the network perspective — the request was
    /// sent and the peer may have processed it. Callers that need to know the
    /// outcome must not drop the future.
    #[error("request was cancelled before a response arrived")]
    Cancelled,

    /// The server received a request for which no handler is registered.
    ///
    /// Returned by `RpcRouter` when a frame type is not handled. The router
    /// automatically sends an `ErrorFrame` back to the peer.
    #[error("no handler registered for frame type {frame_type}")]
    NoHandler { frame_type: &'static str },
}

impl RpcError {
    /// Returns `true` if retrying this request after a backoff may succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }

    /// Returns `true` if the connection should be closed after this error.
    #[must_use]
    pub fn is_connection_fatal(&self) -> bool {
        match self {
            Self::Transport(e)           => !e.is_transient(),
            Self::PeerError { fatal, .. } => *fatal,
            Self::ChannelClosed          => true,
            _                            => false,
        }
    }

    /// Convenience constructor for `PeerError`.
    #[must_use]
    pub fn peer(code: ErrorCode, message: impl Into<String>, fatal: bool) -> Self {
        Self::PeerError { code, message: message.into(), fatal }
    }
}

/// Short-hand `Result` alias for RPC operations.
pub type RpcResult<T> = Result<T, RpcError>;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use muspell_proto::ErrorCode;
    use std::time::Duration;

    #[test]
    fn timeout_is_retryable() {
        let e = RpcError::Timeout { request: "Get", after: Duration::from_secs(5) };
        assert!(e.is_retryable());
        assert!(!e.is_connection_fatal());
    }

    #[test]
    fn channel_closed_is_fatal() {
        let e = RpcError::ChannelClosed;
        assert!(!e.is_retryable());
        assert!(e.is_connection_fatal());
    }

    #[test]
    fn cancelled_is_neither_retryable_nor_fatal() {
        let e = RpcError::Cancelled;
        assert!(!e.is_retryable());
        assert!(!e.is_connection_fatal());
    }

    #[test]
    fn peer_error_fatal_flag_propagates() {
        let fatal = RpcError::peer(ErrorCode::InternalError, "oops", true);
        assert!(fatal.is_connection_fatal());

        let recoverable = RpcError::peer(ErrorCode::NotFound, "nope", false);
        assert!(!recoverable.is_connection_fatal());
    }

    #[test]
    fn error_display_contains_key_info() {
        let e = RpcError::Timeout { request: "Put", after: Duration::from_secs(30) };
        let s = e.to_string();
        assert!(s.contains("Put") && s.contains("timeout"));
    }
}
