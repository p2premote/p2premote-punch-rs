//! Rust port of easyp2p: gonc NAT-traversal engine used by the WGVPN FFI.

pub mod candidates;
pub mod crypto;
pub mod exchange;
pub mod lan;
#[cfg(feature = "legacy-mqtt")]
pub mod mqtt_signal;
pub mod netx;
pub mod p2p;
pub mod portmap;
pub mod punch_tcp;
pub mod punch_udp;
pub mod signal;
pub mod socketprotect;
pub mod stun;
pub mod udp_tunnel;
#[cfg(feature = "legacy-mqtt")]
pub mod wake;

// live_tests drive the exported C ABI (StartUdpTunnel/FreeCString), which only
// exists with the ffi feature.
#[cfg(all(test, feature = "ffi", feature = "legacy-mqtt"))]
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
        .get_or_init(|| match std::env::var("P2PREMOTE_MQTT_BROKERS") {
            Ok(v) if !v.trim().is_empty() => v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>(),
            _ => DEFAULT_MQTT_BROKER_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
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

pub use crate::error::{AppError, ErrorCode};

/// Failure plus optional socket diagnostics. The business code lives in AppError.
#[derive(Debug, Clone)]
pub struct P2pError {
    error: AppError,
    details: Option<candidates::P2PAttemptDetails>,
}

impl P2pError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: AppError::new(code, message),
            details: None,
        }
    }
    pub fn msg(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::RuntimeExecutionUnclassified, message)
    }
    pub fn with_source(
        code: ErrorCode,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            error: AppError::with_source(code, message, source),
            details: None,
        }
    }
    pub fn context(mut self, message: impl Into<String>) -> Self {
        self.error = self.error.context(message);
        self
    }
    pub fn code(&self) -> ErrorCode {
        self.error.code()
    }
    pub fn app_error(&self) -> AppError {
        self.error.clone()
    }
    pub fn with_details(mut self, details: candidates::P2PAttemptDetails) -> Self {
        self.details = Some(details);
        self
    }
    pub fn is_unretryable(&self) -> bool {
        // A new application network may help, but repeating candidate selection
        // with the same native network matrix cannot produce a usable pair.
        self.code().retry_class() != "next_network_or_attempt"
            || matches!(
                self.code(),
                ErrorCode::TraversalCandidateSelectionNoCommonNetwork
                    | ErrorCode::TraversalCandidateSelectionNoUsableCandidate
            )
    }
    pub fn details(&self) -> Option<&candidates::P2PAttemptDetails> {
        self.details.as_ref()
    }
}

impl std::fmt::Display for P2pError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for P2pError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
impl From<std::io::Error> for P2pError {
    fn from(error: std::io::Error) -> Self {
        Self::with_source(
            ErrorCode::TraversalPunchIoFailed,
            "network operation failed",
            error,
        )
    }
}
impl From<AppError> for P2pError {
    fn from(error: AppError) -> Self {
        Self {
            error,
            details: None,
        }
    }
}
impl From<P2pError> for AppError {
    fn from(error: P2pError) -> Self {
        error.error
    }
}
impl From<serde_json::Error> for P2pError {
    fn from(error: serde_json::Error) -> Self {
        Self::with_source(
            ErrorCode::NativeDecodeInvalidPayload,
            "invalid JSON payload",
            error,
        )
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
#[derive(Clone)]
pub struct Scope {
    pub deadline: Instant,
    cancel: Option<Arc<CancelToken>>,
}

impl Scope {
    pub fn interruption(&self, timeout: ErrorCode) -> P2pError {
        let code = if self
            .cancel
            .as_ref()
            .is_some_and(|token| token.is_cancelled())
        {
            ErrorCode::TraversalExecutionCancelled
        } else {
            timeout
        };
        let message = code.message().to_owned();
        P2pError::new(code, message)
    }
    pub fn from_timeout(timeout: Duration) -> Self {
        Scope {
            deadline: Instant::now() + timeout,
            cancel: None,
        }
    }

    pub fn remaining(&self) -> Duration {
        if self
            .cancel
            .as_ref()
            .map(|t| t.is_cancelled())
            .unwrap_or(false)
        {
            return Duration::ZERO;
        }
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
            || self
                .cancel
                .as_ref()
                .map(|t| t.is_cancelled())
                .unwrap_or(false)
    }

    /// Child scope bounded by `timeout` but never exceeding this scope.
    pub fn child(&self, timeout: Duration) -> Scope {
        let candidate = Instant::now() + timeout;
        Scope {
            deadline: candidate.min(self.deadline),
            cancel: self.cancel.clone(),
        }
    }

    /// boundedTimeout from udp_tunnel.go: min(requested, remaining).
    pub fn bounded_timeout(&self, requested: Duration) -> Duration {
        self.remaining().min(requested)
    }

    pub async fn sleep_until_deadline(&self, delay: Duration) {
        let target = (Instant::now() + delay).min(self.deadline);
        if target <= Instant::now() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(target)) => {},
            _ = self.cancelled() => {},
        }
    }

    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = self.deadline.min(deadline);
        self
    }
    pub fn with_cancel(mut self, cancel: Arc<CancelToken>) -> Self {
        self.cancel = Some(cancel);
        self
    }
    pub async fn cancelled(&self) {
        match &self.cancel {
            Some(cancel) => cancel.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    }
}

// ============ logging ============
//
// The Go FFI captures easyp2p logs into a buffer it discards. Keep the Rust
// diagnostics disabled by default on every platform: the UDP forwarding path
// contains per-packet diagnostics, and writing those to Android logcat can
// severely limit tunnel throughput. Desktop builds can still opt in with
// P2PREMOTE_PUNCH_LOG=1.

static LOG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub fn log_enabled() -> bool {
    *LOG_ENABLED.get_or_init(|| {
        std::env::var("P2PREMOTE_PUNCH_LOG")
            .map(|v| v != "0")
            .unwrap_or(false)
    })
}

/// Emit one diagnostic line: stderr on desktop, logcat (tag P2P) on Android.
pub fn p2p_diag_line(message: &str) {
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;
        use std::os::raw::{c_char, c_int};
        extern "C" {
            fn __android_log_print(prio: c_int, tag: *const c_char, msg: *const c_char) -> c_int;
        }
        let tag = b"P2P\0" as *const u8 as *const c_char;
        if let Ok(text) = CString::new(format!("[P2P] {}", message)) {
            unsafe {
                __android_log_print(4 /* INFO */, tag, text.as_ptr());
            }
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        eprintln!("[P2P] {}", message);
    }
}

pub fn p2p_logf(message: &str) {
    if log_enabled() {
        p2p_diag_line(message);
    }
}

/// Always-on, low-volume traversal diagnostics. Unlike `p2plog!`, these
/// records are intentionally routed through the host application's tracing
/// subscriber so service builds persist them in p2premote-service.log.
pub fn p2p_event_line(message: &str) {
    #[cfg(target_os = "android")]
    p2p_diag_line(message);
    tracing::info!(target: "p2premote_punch::diagnostics", "[P2P-DIAG] {}", message);
}

#[macro_export]
macro_rules! p2pevent {
    ($($arg:tt)*) => {
        $crate::easyp2p::p2p_event_line(&format!($($arg)*));
    };
}

#[macro_export]
macro_rules! p2plog {
    ($($arg:tt)*) => {
        if $crate::easyp2p::log_enabled() {
            $crate::easyp2p::p2p_diag_line(&format!($($arg)*));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_and_stage_survive_context_and_clone() {
        let err = P2pError::new(ErrorCode::TraversalAddressExchangeTimeout, "any message")
            .context("address exchange failed");
        assert_eq!(err.code().stage(), "address_exchange");
        assert_eq!(
            err.clone().code(),
            ErrorCode::TraversalAddressExchangeTimeout
        );
        assert_eq!(
            crate::error::effective_code(&err),
            ErrorCode::TraversalAddressExchangeTimeout
        );
    }
    #[test]
    fn deadline_is_not_user_cancellation() {
        let scope = Scope::from_timeout(Duration::ZERO);
        assert_eq!(
            scope.interruption(ErrorCode::TraversalPunchTimeout).code(),
            ErrorCode::TraversalPunchTimeout
        );
        let token = Arc::new(CancelToken::new());
        token.cancel();
        assert_eq!(
            scope
                .with_cancel(token)
                .interruption(ErrorCode::TraversalPunchTimeout)
                .code(),
            ErrorCode::TraversalExecutionCancelled
        );
    }

    #[test]
    fn rejected_candidates_allow_another_network_without_repeating_native_selection() {
        for code in [
            ErrorCode::TraversalCandidateSelectionNoCommonNetwork,
            ErrorCode::TraversalCandidateSelectionNoUsableCandidate,
        ] {
            assert_eq!(code.retry_class(), "next_network_or_attempt");
            assert!(P2pError::new(code, "no pair in this network matrix").is_unretryable());
        }
    }
}
