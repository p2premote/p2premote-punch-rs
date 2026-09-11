//! Rust port of easyp2p: gonc NAT-traversal engine used by the WGVPN FFI.

pub mod candidates;
pub mod crypto;
pub mod exchange;
pub mod lan;
pub mod mqtt_signal;
pub mod netx;
pub mod p2p;
pub mod punch_tcp;
pub mod punch_udp;
pub mod stun;
pub mod udp_tunnel;
pub mod wake;

#[cfg(test)]
mod live_tests;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DEFAULT_PUNCHING_SHORT_TTL: i32 = 5;
pub const DEFAULT_PUNCHING_RANDOM_PORT_COUNT: usize = 600;
pub const DEFAULT_TOPIC_EXCHANGE: &str = "nat-exchange/";

pub const DEFAULT_MQTT_BROKER_SERVERS: &[&str] = &[
    "tcp://broker.hivemq.com:1883",
    "tcp://broker.emqx.io:1883",
    "tcp://test.mosquitto.org:1883",
    "tcp://guest:guest@mqtt.gonc.cc:1883",
];

pub const TOPIC_DESC_SIGNAL: &str = "SG";

// ============ tunables (gonc package vars → env overrides) ============
//
// gonc exports STUNServers / MQTTBrokerServers / PunchingShortTTL /
// PunchingRandomPortCount / TopicExchange as package variables the CLI can
// override; the Rust equivalent is environment variables so the FFI JSON
// contract stays frozen.

/// UDP punch short TTL (PunchingShortTTL). Env: P2PREMOTE_PUNCH_SHORT_TTL.
pub fn punching_short_ttl() -> i32 {
    static VALUE: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("P2PREMOTE_PUNCH_SHORT_TTL")
            .ok()
            .and_then(|v| v.trim().parse::<i32>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or(DEFAULT_PUNCHING_SHORT_TTL)
    })
}

/// Birthday-attack port count (PunchingRandomPortCount). Env:
/// P2PREMOTE_PUNCH_RANDOM_PORTS.
pub fn punching_random_port_count() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("P2PREMOTE_PUNCH_RANDOM_PORTS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or(DEFAULT_PUNCHING_RANDOM_PORT_COUNT)
    })
}

/// MQTT topic prefix (TopicExchange). Env: P2PREMOTE_TOPIC_PREFIX.
pub fn topic_exchange() -> String {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE
        .get_or_init(|| {
            std::env::var("P2PREMOTE_TOPIC_PREFIX")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_TOPIC_EXCHANGE.to_string())
        })
        .clone()
}

/// MQTT broker list. Env: P2PREMOTE_MQTT_BROKERS (comma-separated URLs).
pub fn mqtt_broker_servers() -> Vec<String> {
    static VALUE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    VALUE
        .get_or_init(|| {
            match std::env::var("P2PREMOTE_MQTT_BROKERS") {
                Ok(v) if !v.trim().is_empty() => v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>(),
                _ => DEFAULT_MQTT_BROKER_SERVERS.iter().map(|s| s.to_string()).collect(),
            }
        })
        .clone()
}

/// Capability flag: parallel UDP hole punching through multiple exits.
pub const CAP_MULTI_EXIT_UDP_PUNCH: &str = "multi-exit-udp-punch";
pub const CAP_LAN_PROBE: &str = "lan-probe";
pub const CAP_CANONICAL_LAN_PROBE: &str = "lan-probe-canonical-v2";

pub const EXMODE_MUTUAL: i32 = 0;
pub const EXMODE_WAIT_ONLY: i32 = 1;
pub const EXMODE_PUBLISH_ONLY: i32 = 2;

// ============ errors ============

/// Error with optional traversal diagnostics, mirroring P2PTraversalError /
/// UnRetryableError from easyp2p/p2p.go.
#[derive(Debug, Clone)]
pub struct P2pError {
    message: String,
    unretryable: bool,
    details: Option<candidates::P2PAttemptDetails>,
}

impl P2pError {
    pub fn msg<S: Into<String>>(message: S) -> Self {
        P2pError {
            message: message.into(),
            unretryable: false,
            details: None,
        }
    }

    pub fn wrap_unretryable(self) -> Self {
        let mut e = self;
        e.unretryable = true;
        e
    }

    pub fn with_details(self, details: candidates::P2PAttemptDetails) -> Self {
        let mut e = self;
        e.details = Some(details);
        e
    }

    pub fn is_unretryable(&self) -> bool {
        self.unretryable
    }

    pub fn details(&self) -> Option<&candidates::P2PAttemptDetails> {
        self.details.as_ref()
    }
}

impl std::fmt::Display for P2pError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for P2pError {}

impl From<std::io::Error> for P2pError {
    fn from(err: std::io::Error) -> Self {
        P2pError::msg(err.to_string())
    }
}

impl From<serde_json::Error> for P2pError {
    fn from(err: serde_json::Error) -> Self {
        P2pError::msg(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, P2pError>;

// ============ cancellation ============

/// Cooperative cancellation token + deadline, standing in for Go's context.
#[derive(Clone)]
pub struct CancelToken {
    cancelled: Arc<AtomicBool>,
    tx: Arc<tokio::sync::watch::Sender<bool>>,
    rx: tokio::sync::watch::Receiver<bool>,
}

impl CancelToken {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        CancelToken {
            cancelled: Arc::new(AtomicBool::new(false)),
            tx: Arc::new(tx),
            rx,
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        let _ = self.tx.send(true);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Wait until cancelled. Returns immediately if already cancelled.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let mut rx = self.rx.clone();
        // watch yields the current value first; loop until true.
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Deadline-bounded scope derived from a parent (caller) deadline.
#[derive(Clone, Copy)]
pub struct Scope {
    pub deadline: Instant,
}

impl Scope {
    pub fn from_timeout(timeout: Duration) -> Self {
        Scope {
            deadline: Instant::now() + timeout,
        }
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Child scope bounded by `timeout` but never exceeding this scope.
    pub fn child(&self, timeout: Duration) -> Scope {
        let candidate = Instant::now() + timeout;
        Scope {
            deadline: candidate.min(self.deadline),
        }
    }

    /// boundedTimeout from udp_tunnel.go: min(requested, remaining).
    pub fn bounded_timeout(&self, requested: Duration) -> Duration {
        self.remaining().min(requested)
    }

    #[allow(dead_code)]
    pub async fn sleep_or_cancelled(&self, token: &CancelToken, delay: Duration) -> Result<()> {
        tokio::select! {
            _ = self.sleep_until_deadline(delay) => Ok(()),
            _ = token.cancelled() => Err(P2pError::msg("operation cancelled")),
        }
    }

    pub async fn sleep_until_deadline(&self, delay: Duration) {
        let target = (Instant::now() + delay).min(self.deadline);
        if target <= Instant::now() {
            return;
        }
        tokio::time::sleep_until(tokio::time::Instant::from_std(target)).await;
    }
}

// ============ logging ============
//
// The Go FFI captures easyp2p logs into a buffer it discards. We keep the
// messages but only print them when P2PREMOTE_PUNCH_LOG=1 for debugging.

static LOG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub fn log_enabled() -> bool {
    *LOG_ENABLED.get_or_init(|| {
        std::env::var("P2PREMOTE_PUNCH_LOG").map(|v| v != "0").unwrap_or(false)
    })
}

pub fn p2p_logf(message: &str) {
    if log_enabled() {
        eprintln!("[P2P] {}", message);
    }
}

#[macro_export]
macro_rules! p2plog {
    ($($arg:tt)*) => {
        if $crate::easyp2p::log_enabled() {
            eprintln!("[P2P] {}", format!($($arg)*));
        }
    };
}

#[allow(dead_code)]
pub fn now_unix_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}
