//! Node configuration.

use muspell_proto::NodeCapabilities;
use muspell_rpc::RpcConfig;
use muspell_transport::TransportConfig;
use std::time::Duration;

/// Top-level configuration for a [`MuspellNode`].
///
/// Assembles sub-layer configs and node-specific settings.
/// Built via a fluent builder pattern — start with [`NodeConfig::new`].
///
/// [`MuspellNode`]: crate::MuspellNode
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Transport layer config (QUIC, handshake, keepalive, frame size).
    pub transport: TransportConfig,
    /// RPC layer config (call timeouts, max in-flight).
    pub rpc: RpcConfig,
    /// Capacity of per-topic pub/sub broadcast channels.
    pub pubsub_channel_capacity: usize,
    /// Capacity of per-peer incoming/outgoing `mpsc` channels.
    pub peer_channel_capacity: usize,
    /// Capacity of the unsolicited-frames channel forwarded from the
    /// RPC dispatcher to the pubsub router.
    pub unsolicited_channel_capacity: usize,
    /// Maximum number of concurrent inbound connections.
    /// Outbound connections are not limited here.
    pub max_inbound_connections: usize,
    /// Whether to automatically announce this node to connected peers
    /// after the handshake completes.
    pub auto_announce: bool,
    /// How long to wait for all in-flight requests to complete during
    /// a graceful shutdown before force-closing connections.
    pub shutdown_timeout: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            transport:                TransportConfig::default(),
            rpc:                      RpcConfig::default(),
            pubsub_channel_capacity:  256,
            peer_channel_capacity:    512,
            unsolicited_channel_capacity: 64,
            max_inbound_connections:  1024,
            auto_announce:            true,
            shutdown_timeout:         Duration::from_secs(5),
        }
    }
}

impl NodeConfig {
    /// Create a config with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the transport config entirely.
    #[must_use]
    pub fn with_transport(mut self, cfg: TransportConfig) -> Self {
        self.transport = cfg;
        self
    }

    /// Override the RPC config entirely.
    #[must_use]
    pub fn with_rpc(mut self, cfg: RpcConfig) -> Self {
        self.rpc = cfg;
        self
    }

    /// Set the local node capabilities advertised during the handshake.
    #[must_use]
    pub fn with_capabilities(mut self, caps: NodeCapabilities) -> Self {
        self.transport = self.transport.with_capabilities(caps);
        self
    }

    /// Set the user-agent string embedded in `Hello` frames.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.transport = self.transport.with_user_agent(ua);
        self
    }

    /// Set the pub/sub broadcast channel capacity.
    #[must_use]
    pub fn with_pubsub_capacity(mut self, capacity: usize) -> Self {
        self.pubsub_channel_capacity = capacity;
        self
    }

    /// Set the maximum number of inbound connections.
    #[must_use]
    pub fn with_max_inbound_connections(mut self, n: usize) -> Self {
        self.max_inbound_connections = n;
        self
    }

    /// Disable the automatic `Announce` frame sent after each handshake.
    #[must_use]
    pub fn without_auto_announce(mut self) -> Self {
        self.auto_announce = false;
        self
    }

    /// Override the graceful shutdown timeout.
    #[must_use]
    pub fn with_shutdown_timeout(mut self, d: Duration) -> Self {
        self.shutdown_timeout = d;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = NodeConfig::default();
        assert!(cfg.pubsub_channel_capacity > 0);
        assert!(cfg.max_inbound_connections > 0);
        assert!(cfg.auto_announce);
    }

    #[test]
    fn builder_chain() {
        let cfg = NodeConfig::new()
            .with_user_agent("muspell-test/0.1")
            .with_pubsub_capacity(128)
            .with_max_inbound_connections(16)
            .without_auto_announce();
        assert_eq!(cfg.pubsub_channel_capacity, 128);
        assert_eq!(cfg.max_inbound_connections, 16);
        assert!(!cfg.auto_announce);
    }
}
