//! `SubscriptionManager` — process-local broadcast fan-out per topic.
//!
//! ## Responsibility
//!
//! The manager owns a `tokio::sync::broadcast` channel for each active
//! topic. It is the **single point** where an incoming message on a topic
//! is broadcast to all local `Subscriber`s.
//!
//! It has no knowledge of the network — it only deals in `ReceivedMessage`
//! values. The `PubSubRouter` calls `manager.deliver()` when a message
//! arrives from the wire; the `Publisher` calls `manager.deliver()` when
//! a local publication does not need to go over the wire first.
//!
//! ## Subscriber lifecycle
//!
//! ```text
//! manager.subscribe(topic_id)  →  Subscriber (wraps broadcast::Receiver)
//!                                      │
//!                                      │ .recv().await  ← yields ReceivedMessage
//!                                      │
//!                                      │ drop Subscriber → receiver dropped;
//!                                      │   if last receiver, topic is cleaned up
//!                                      │   on next deliver() miss
//! ```
//!
//! ## Lagged subscribers
//!
//! `broadcast::Receiver` returns `RecvError::Lagged(n)` if the receiver
//! fell behind by more than `channel_capacity` messages. The `Subscriber`
//! wrapper converts this to `PubSubError::Decode` with a descriptive
//! message. Application code that cannot keep up should use a larger
//! `channel_capacity` or process messages in a spawned task.

use dashmap::DashMap;
use muspell_proto::NodeId;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::error::{PubSubError, PubSubResult};
use crate::message::ReceivedMessage;
use crate::topic::TopicId;

// ── SubscriptionManager ───────────────────────────────────────────────────────

/// Process-local pub/sub broker.
///
/// `Clone`-able and `Send + Sync` — share freely across tasks.
#[derive(Clone)]
pub struct SubscriptionManager {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    /// Per-topic broadcast senders.
    /// Key: `TopicId` as `[u8; 32]` (DashMap requires `Hash`).
    topics:   DashMap<[u8; 32], broadcast::Sender<ReceivedMessage>>,
    /// Capacity of each broadcast channel (messages buffered per topic
    /// before slow receivers start lagging).
    capacity: usize,
}

impl SubscriptionManager {
    /// Create a new manager.
    ///
    /// `channel_capacity` — number of messages buffered per topic before
    /// slow receivers begin to lag. Default: 256. For high-throughput
    /// topics, increase this; for memory-constrained environments, decrease.
    #[must_use]
    pub fn new(channel_capacity: usize) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                topics:   DashMap::new(),
                capacity: channel_capacity,
            }),
        }
    }

    /// Create with the default channel capacity of 256.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(256)
    }

    // ── Subscription ──────────────────────────────────────────────────────────

    /// Subscribe to a topic.
    ///
    /// If no broadcast channel exists for this topic yet, one is created.
    /// Returns a `Subscriber` that yields `ReceivedMessage`s as they arrive.
    ///
    /// The topic channel is kept alive as long as at least one `Subscriber`
    /// (or the sender entry in this manager) exists.
    #[must_use]
    pub fn subscribe(&self, topic_id: TopicId) -> Subscriber {
        let rx = self.get_or_create_sender(topic_id).subscribe();
        debug!("pubsub: new subscriber for {}", topic_id);
        Subscriber::new(topic_id, rx)
    }

    // ── Delivery ──────────────────────────────────────────────────────────────

    /// Deliver an incoming message to all local subscribers of its topic.
    ///
    /// If there are no local subscribers for this topic, returns
    /// `PubSubError::NoSubscribers` — this is informational, not fatal.
    ///
    /// If the broadcast channel reports that all receivers have lagged
    /// or disconnected, the topic entry is cleaned up.
    pub fn deliver(&self, msg: ReceivedMessage) -> PubSubResult<usize> {
        let key = *msg.topic().as_bytes();

        let sender = match self.inner.topics.get(&key) {
            Some(s) => s,
            None    => {
                return Err(PubSubError::NoSubscribers { topic_id: msg.topic() });
            }
        };

        match sender.send(msg.clone()) {
            Ok(n) => {
                debug!(
                    "pubsub: delivered to {} subscriber(s) on {}",
                    n, msg.topic()
                );
                Ok(n)
            }
            Err(_) => {
                // All receivers dropped — clean up the dead channel.
                drop(sender);
                self.inner.topics.remove(&key);
                warn!("pubsub: all subscribers dropped for {}", msg.topic());
                Err(PubSubError::TopicClosed { topic_id: msg.topic() })
            }
        }
    }

    // ── Inspection ────────────────────────────────────────────────────────────

    /// Number of currently active topics (with at least one subscriber or
    /// a pending channel).
    #[must_use]
    pub fn active_topic_count(&self) -> usize {
        self.inner.topics.len()
    }

    /// Number of active subscribers across all topics.
    #[must_use]
    pub fn total_subscriber_count(&self) -> usize {
        self.inner.topics
            .iter()
            .map(|e| e.value().receiver_count())
            .sum()
    }

    /// Returns `true` if there is at least one local subscriber for `topic_id`.
    #[must_use]
    pub fn has_subscribers(&self, topic_id: TopicId) -> bool {
        self.inner.topics
            .get(topic_id.as_bytes())
            .map(|s| s.receiver_count() > 0)
            .unwrap_or(false)
    }

    /// Remove all subscribers and channels for `topic_id`.
    ///
    /// Any existing `Subscriber` objects will receive `RecvError::Closed`
    /// on their next poll.
    pub fn close_topic(&self, topic_id: TopicId) {
        self.inner.topics.remove(topic_id.as_bytes());
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn get_or_create_sender(
        &self,
        topic_id: TopicId,
    ) -> broadcast::Sender<ReceivedMessage> {
        let key = *topic_id.as_bytes();
        // Fast path: topic already exists.
        if let Some(entry) = self.inner.topics.get(&key) {
            return entry.value().clone();
        }
        // Slow path: create the channel and insert atomically.
        let (tx, _rx) = broadcast::channel(self.inner.capacity);
        self.inner.topics
            .entry(key)
            .or_insert(tx)
            .clone()
    }
}

// ── Subscriber ────────────────────────────────────────────────────────────────

/// A handle to a topic subscription.
///
/// Yields `ReceivedMessage` values via `recv()`.
///
/// Dropping a `Subscriber` cancels the subscription. If the last subscriber
/// for a topic is dropped, the topic channel remains alive in the manager
/// until the next `deliver()` miss or an explicit `close_topic()`.
pub struct Subscriber {
    topic: TopicId,
    rx:    broadcast::Receiver<ReceivedMessage>,
}

impl Subscriber {
    fn new(topic: TopicId, rx: broadcast::Receiver<ReceivedMessage>) -> Self {
        Self { topic, rx }
    }

    /// The topic this subscriber is listening on.
    #[must_use]
    pub fn topic(&self) -> TopicId {
        self.topic
    }

    /// Receive the next message on this topic.
    ///
    /// Waits asynchronously until a message arrives.
    ///
    /// # Errors
    /// - `PubSubError::TopicClosed` if the broadcast sender was dropped
    ///   (topic closed by the manager or all publishers gone).
    /// - `PubSubError::Decode` if the subscriber lagged and messages were
    ///   skipped (includes the lag count in the message).
    pub async fn recv(&mut self) -> PubSubResult<ReceivedMessage> {
        use broadcast::error::RecvError;
        loop {
            match self.rx.recv().await {
                Ok(msg)                     => return Ok(msg),
                Err(RecvError::Closed)      => {
                    return Err(PubSubError::TopicClosed { topic_id: self.topic });
                }
                Err(RecvError::Lagged(n)) => {
                    // The subscriber fell behind. We skip the lost messages
                    // and log a warning, then retry so the caller always
                    // gets the next available message.
                    warn!(
                        "pubsub: subscriber on {} lagged by {} message(s); \
                         skipping to latest",
                        self.topic, n
                    );
                    // Loop: try to receive the next available message.
                }
            }
        }
    }

    /// Try to receive a message without blocking.
    ///
    /// Returns `Ok(None)` if no message is currently available.
    ///
    /// # Errors
    /// Same as `recv()`.
    pub fn try_recv(&mut self) -> PubSubResult<Option<ReceivedMessage>> {
        use broadcast::error::TryRecvError;
        match self.rx.try_recv() {
            Ok(msg)                      => Ok(Some(msg)),
            Err(TryRecvError::Empty)     => Ok(None),
            Err(TryRecvError::Closed)    => {
                Err(PubSubError::TopicClosed { topic_id: self.topic })
            }
            Err(TryRecvError::Lagged(n)) => {
                warn!("pubsub: try_recv lagged {} on {}", n, self.topic);
                Ok(None)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::PubSubMessage;
    use muspell_proto::{Bytes, FrameId, NodeId, Timestamp};

    fn topic(name: &str) -> TopicId {
        TopicId::from_name(name)
    }

    fn sender() -> NodeId { NodeId::from_bytes([9u8; 32]) }

    fn make_received(topic_id: TopicId, seq: u64) -> ReceivedMessage {
        ReceivedMessage {
            message:     PubSubMessage::new(
                topic_id, seq, sender(),
                Bytes::from_slice(b"payload"),
            ),
            received_at: Timestamp::ZERO,
            frame_id:    FrameId::from_u128(seq as u128),
        }
    }

    // ── subscribe + deliver ───────────────────────────────────────────────────

    #[tokio::test]
    async fn subscribe_then_deliver_receives_message() {
        let mgr = SubscriptionManager::with_defaults();
        let t   = topic("alpha");

        let mut sub = mgr.subscribe(t);
        let msg = make_received(t, 0);

        let n = mgr.deliver(msg.clone()).unwrap();
        assert_eq!(n, 1);

        let received = sub.recv().await.unwrap();
        assert_eq!(received.seq(), 0);
        assert_eq!(received.topic(), t);
    }

    #[tokio::test]
    async fn deliver_with_no_subscribers_returns_no_subscribers_error() {
        let mgr = SubscriptionManager::with_defaults();
        let t   = topic("empty");
        let msg = make_received(t, 0);

        let err = mgr.deliver(msg).unwrap_err();
        assert!(matches!(err, PubSubError::NoSubscribers { .. }));
    }

    #[tokio::test]
    async fn multiple_subscribers_all_receive() {
        let mgr = SubscriptionManager::with_defaults();
        let t   = topic("beta");

        let mut sub_a = mgr.subscribe(t);
        let mut sub_b = mgr.subscribe(t);
        let mut sub_c = mgr.subscribe(t);

        let msg = make_received(t, 1);
        let n = mgr.deliver(msg).unwrap();
        assert_eq!(n, 3);

        assert_eq!(sub_a.recv().await.unwrap().seq(), 1);
        assert_eq!(sub_b.recv().await.unwrap().seq(), 1);
        assert_eq!(sub_c.recv().await.unwrap().seq(), 1);
    }

    #[tokio::test]
    async fn independent_topics_do_not_cross() {
        let mgr = SubscriptionManager::with_defaults();
        let t1  = topic("gamma/1");
        let t2  = topic("gamma/2");

        let mut sub1 = mgr.subscribe(t1);
        let mut sub2 = mgr.subscribe(t2);

        // Deliver to t1 only.
        mgr.deliver(make_received(t1, 10)).unwrap();

        // sub1 gets it, sub2 should not.
        assert_eq!(sub1.recv().await.unwrap().seq(), 10);
        assert!(sub2.try_recv().unwrap().is_none());
    }

    // ── has_subscribers ───────────────────────────────────────────────────────

    #[test]
    fn has_subscribers_accurate() {
        let mgr = SubscriptionManager::with_defaults();
        let t   = topic("delta");
        assert!(!mgr.has_subscribers(t));
        let _sub = mgr.subscribe(t);
        assert!(mgr.has_subscribers(t));
    }

    // ── active_topic_count / total_subscriber_count ───────────────────────────

    #[test]
    fn counts_are_accurate() {
        let mgr = SubscriptionManager::with_defaults();
        assert_eq!(mgr.active_topic_count(), 0);
        assert_eq!(mgr.total_subscriber_count(), 0);

        let t1 = topic("count/a");
        let t2 = topic("count/b");

        let _sub_a1 = mgr.subscribe(t1);
        let _sub_a2 = mgr.subscribe(t1);
        let _sub_b1 = mgr.subscribe(t2);

        assert_eq!(mgr.active_topic_count(),    2);
        assert_eq!(mgr.total_subscriber_count(), 3);
    }

    // ── close_topic ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn close_topic_makes_subscriber_see_closed() {
        let mgr = SubscriptionManager::with_defaults();
        let t   = topic("epsilon");
        let mut sub = mgr.subscribe(t);

        mgr.close_topic(t);

        let err = sub.recv().await.unwrap_err();
        assert!(matches!(err, PubSubError::TopicClosed { .. }));
    }

    // ── try_recv ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn try_recv_returns_none_when_empty() {
        let mgr = SubscriptionManager::with_defaults();
        let t   = topic("zeta");
        let mut sub = mgr.subscribe(t);
        assert!(sub.try_recv().unwrap().is_none());
    }

    #[tokio::test]
    async fn try_recv_returns_message_when_available() {
        let mgr = SubscriptionManager::with_defaults();
        let t   = topic("eta");
        let mut sub = mgr.subscribe(t);

        mgr.deliver(make_received(t, 5)).unwrap();

        let msg = sub.try_recv().unwrap().unwrap();
        assert_eq!(msg.seq(), 5);
    }
}
