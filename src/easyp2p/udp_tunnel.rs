//! Port of easyp2p/udp_tunnel.go: StartUDPTunnel — traversal-mode
//! negotiation over MQTT, LAN or Internet punching, then a local UDP forwarder
//! bridging the local WireGuard endpoint to the punched P2P socket.

use crate::error::ErrorCode;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

// Drain a bounded number of already-ready datagrams after each async wake-up.
// This preserves UDP packet boundaries while amortizing Tokio scheduling and
// task wake-up overhead under sustained LAN throughput.
const UDP_FORWARD_BATCH_SIZE: usize = 32;

fn udp_forward_batch_buffers() -> Vec<Vec<u8>> {
    (0..UDP_FORWARD_BATCH_SIZE)
        .map(|_| vec![0u8; netx::UDP_FORWARD_BUF])
        .collect()
}

use super::crypto;
use super::lan;
use super::netx;
use super::p2p::{self, EasyP2PMPOptions, P2PConn, P2PConnInfo};
use super::signal::{SignalCall, SignalSession};
use super::stun;
use super::{CancelToken, P2pError, Scope, EXMODE_MUTUAL, EXMODE_WAIT_ONLY};
use crate::types::{UdpTunnelInput, UdpTunnelResult};

pub const TRAVERSAL_MODE_AUTO: &str = "auto";
pub const TRAVERSAL_MODE_INTERNET: &str = "internet";
pub const TRAVERSAL_MODE_LAN: &str = "lan";

/// Default tunnel timeout when the request has `timeout_secs <= 0`.
/// Single source of the default: callers only add scheduling margins on top.
pub const DEFAULT_TUNNEL_TIMEOUT_SECS: i32 = 45;

const SELECTED_TRAVERSAL_INTERNET: &str = "internet";
const SELECTED_TRAVERSAL_LAN: &str = "lan";
const TRANSPORT_MODE_PLAIN: &str = "plain";

#[cfg(test)]
#[path = "udp_tunnel_tests.rs"]
mod coverage_tests;

/// Error carrying the structured failure result for the FFI (UDPTunnelError).
#[derive(Debug)]
pub struct StartError {
    pub tunnel_result: Option<UdpTunnelResult>,
    pub error: crate::error::AppError,
}

impl StartError {
    fn plain(message: impl Into<String>) -> Self {
        Self::coded(crate::error::ErrorCode::NativeInputInvalidArgument, message)
    }
    fn coded(code: crate::error::ErrorCode, message: impl Into<String>) -> Self {
        Self {
            tunnel_result: None,
            error: crate::error::AppError::new(code, message),
        }
    }
    pub fn code(&self) -> crate::error::ErrorCode {
        self.error.code()
    }
}
impl From<P2pError> for StartError {
    fn from(error: P2pError) -> Self {
        udp_tunnel_error(0, &error, "tunnel start failed")
    }
}
impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub struct TunnelStop {
    token: Arc<CancelToken>,
    diagnostics: Arc<ForwardState>,
}

/// Bounded data-plane evidence; contains no payloads or credentials.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ForwardDiagnostics {
    pub transport: String,
    pub local_to_peer_packets: u64,
    pub peer_to_local_packets: u64,
    pub local_to_peer_bytes: u64,
    pub peer_to_local_bytes: u64,
    pub last_local_to_peer_unix_ms: Option<u64>,
    pub last_peer_to_local_unix_ms: Option<u64>,
    pub exit_direction: Option<String>,
    pub exit_reason: Option<String>,
    pub os_error: Option<i32>,
}

#[derive(Default)]
struct ForwardState {
    // Per-direction packet count, byte count and last successful forward time.
    // Keep the forwarding hot path free of mutex contention.
    counters: [std::sync::atomic::AtomicU64; 6],
    details: std::sync::Mutex<ForwardDiagnostics>,
}

impl ForwardState {
    fn snapshot(&self) -> ForwardDiagnostics {
        use std::sync::atomic::Ordering::Relaxed;
        let mut snapshot = self.details.lock().unwrap().clone();
        snapshot.local_to_peer_packets = self.counters[0].load(Relaxed);
        snapshot.local_to_peer_bytes = self.counters[1].load(Relaxed);
        snapshot.last_local_to_peer_unix_ms = match self.counters[2].load(Relaxed) {
            0 => None,
            time => Some(time),
        };
        snapshot.peer_to_local_packets = self.counters[3].load(Relaxed);
        snapshot.peer_to_local_bytes = self.counters[4].load(Relaxed);
        snapshot.last_peer_to_local_unix_ms = match self.counters[5].load(Relaxed) {
            0 => None,
            time => Some(time),
        };
        snapshot
    }
}

struct ForwardGuard {
    token: Arc<CancelToken>,
    diagnostics: Arc<ForwardState>,
    direction: &'static str,
    failed: bool,
}

impl ForwardGuard {
    fn packet(&self, bytes: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let offset = if self.direction == "local_to_peer" {
            0
        } else {
            3
        };
        self.diagnostics.counters[offset].fetch_add(1, Relaxed);
        self.diagnostics.counters[offset + 1].fetch_add(bytes as u64, Relaxed);
        self.diagnostics.counters[offset + 2].store(now, Relaxed);
    }

    fn fail(&mut self, operation: &str, error: &std::io::Error) {
        if self.token.is_cancelled() {
            return;
        }
        self.failed = true;
        let mut state = self.diagnostics.details.lock().unwrap();
        if state.exit_reason.is_none() {
            state.exit_direction = Some(self.direction.into());
            state.exit_reason = Some(format!("{operation}: {:?}: {error}", error.kind()));
            state.os_error = error.raw_os_error();
            drop(state);
            crate::p2plog!("forwarder failed: {:?}", self.diagnostics.snapshot());
        }
    }
}

impl Drop for ForwardGuard {
    fn drop(&mut self) {
        // An unexpected exit must not leave the other direction orphaned.
        if !self.token.is_cancelled() {
            if !self.failed {
                let mut state = self.diagnostics.details.lock().unwrap();
                if state.exit_reason.is_none() {
                    state.exit_direction = Some(self.direction.into());
                    state.exit_reason = Some("unexpected_task_exit".into());
                }
            }
            self.token.cancel();
        }
    }
}

impl TunnelStop {
    pub fn diagnostics(&self) -> ForwardDiagnostics {
        self.diagnostics.snapshot()
    }
    pub fn stop(&self) {
        self.token.cancel();
    }
}

pub struct StartUdpTunnelOutcome {
    pub result: UdpTunnelResult,
    pub stop: TunnelStop,
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use crate::easyp2p::candidates::{self, PunchingAddressInfo};
    use crate::error::ErrorCode;

    #[tokio::test]
    async fn forwarder_reports_tcp_eof_with_counters_and_stops_both_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut remote, _) = listener.accept().await.unwrap();
        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let token = Arc::new(CancelToken::new());
        let diagnostics = Arc::new(ForwardState::default());
        spawn_forwarders(
            local,
            P2PConn::Tcp(super::super::punch_tcp::TcpPunchedConn {
                stream,
                remote: listener.local_addr().unwrap(),
            }),
            wg.local_addr().unwrap(),
            token.clone(),
            diagnostics.clone(),
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            wg.send_to(b"abc", local_addr).await.unwrap();
            let mut frame = [0u8; 5];
            remote.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame, b"\x03\x00abc");
            remote.write_all(b"\x02\x00ok").await.unwrap();
            let mut buf = [0u8; 8];
            let (len, _) = wg.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"ok");
            drop(remote);
            token.cancelled().await;
            loop {
                if UdpSocket::bind(local_addr).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let state = diagnostics.snapshot();
        assert_eq!(state.local_to_peer_packets, 1);
        assert_eq!(state.peer_to_local_packets, 1);
        assert_eq!(state.local_to_peer_bytes, 3);
        assert_eq!(state.peer_to_local_bytes, 2);
        assert_eq!(state.exit_direction.as_deref(), Some("peer_to_local"));
        assert!(state
            .exit_reason
            .as_deref()
            .unwrap()
            .contains("tcp_read_header"));
    }

    #[test]
    fn normal_stop_does_not_report_a_forwarding_failure() {
        let token = Arc::new(CancelToken::new());
        let diagnostics = Arc::new(ForwardState::default());
        let guard = ForwardGuard {
            token: token.clone(),
            diagnostics: diagnostics.clone(),
            direction: "local_to_peer",
            failed: false,
        };
        token.cancel();
        drop(guard);
        assert!(diagnostics.snapshot().exit_reason.is_none());
    }

    #[test]
    fn rejected_symmetric_pair_survives_failure_wrapping_and_json() {
        let address = |nat: &str| PunchingAddressInfo {
            network: "udp4".into(),
            nat_type: "symm".into(),
            lan: "10.0.0.2:4000".into(),
            nat: nat.into(),
        };
        let local = [address("203.0.113.1:5000")];
        let remote = [address("198.51.100.1:6000")];
        let (_, candidates) = candidates::build_base_p2p_candidates(&local, &remote, false);
        assert!(candidates.final_results.is_empty());
        let error = P2pError::new(
            ErrorCode::TraversalCandidateSelectionNoUsableCandidate,
            "any language",
        )
        .with_details(candidates::rejected_attempt_details(&local, &remote));
        let failure = StartError::from(error.context("outer context"));
        assert_eq!(
            failure.code(),
            ErrorCode::TraversalCandidateSelectionNoUsableCandidate
        );
        let json = serde_json::to_value(failure.tunnel_result.unwrap()).unwrap();
        assert_eq!(
            json["error_code"],
            "traversal.candidate_selection.no_usable_candidate"
        );
        assert_eq!(json["local_nat_type"], "symm");
        assert_eq!(json["remote_nat_type"], "symm");
        assert_eq!(json["network"], "udp4");
        assert!(json.get("message").is_some());
        assert!(json.get("error").is_none());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TraversalCapability {
    #[serde(default)]
    version: i32,
    #[serde(default)]
    mode: String,
    #[serde(rename = "supports_lan", default)]
    supports_lan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TraversalOutcome {
    #[serde(default)]
    version: i32,
    #[serde(default)]
    success: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    error: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct TraversalDecision {
    selected_traversal: &'static str,
}

fn normalize_traversal_mode(mode: &str) -> Result<&'static str, P2pError> {
    match mode {
        "" => Ok(TRAVERSAL_MODE_INTERNET),
        TRAVERSAL_MODE_AUTO => Ok(TRAVERSAL_MODE_AUTO),
        TRAVERSAL_MODE_INTERNET => Ok(TRAVERSAL_MODE_INTERNET),
        TRAVERSAL_MODE_LAN => Ok(TRAVERSAL_MODE_LAN),
        _ => Err(P2pError::new(
            ErrorCode::TraversalPlanNegotiationInvalidPayload,
            format!("unsupported traversal_mode: {}", mode),
        )),
    }
}

fn select_negotiated_traversal(
    local: &TraversalCapability,
    remote: &TraversalCapability,
) -> Result<&'static str, P2pError> {
    if remote.version < 1 {
        return Err(P2pError::new(
            ErrorCode::TraversalPlanNegotiationInvalidPayload,
            "peer does not support traversal negotiation",
        ));
    }
    if normalize_traversal_mode(&remote.mode).is_err() || remote.mode.is_empty() {
        return Err(P2pError::new(
            ErrorCode::TraversalPlanNegotiationInvalidPayload,
            format!("peer advertised invalid traversal mode {:?}", remote.mode),
        ));
    }
    if local.mode == TRAVERSAL_MODE_LAN || remote.mode == TRAVERSAL_MODE_LAN {
        if local.mode == TRAVERSAL_MODE_INTERNET || remote.mode == TRAVERSAL_MODE_INTERNET {
            return Err(P2pError::new(
                ErrorCode::TraversalPlanNegotiationInvalidPayload,
                format!(
                    "peer traversal modes conflict: local={} remote={}",
                    local.mode, remote.mode
                ),
            ));
        }
        if !local.supports_lan || !remote.supports_lan {
            return Err(P2pError::new(
                ErrorCode::TraversalPlanNegotiationInvalidPayload,
                "LAN traversal is not supported by both peers",
            ));
        }
        return Ok(SELECTED_TRAVERSAL_LAN);
    }
    if local.mode == TRAVERSAL_MODE_INTERNET || remote.mode == TRAVERSAL_MODE_INTERNET {
        return Ok(SELECTED_TRAVERSAL_INTERNET);
    }
    if local.supports_lan && remote.supports_lan {
        return Ok(SELECTED_TRAVERSAL_LAN);
    }
    Ok(SELECTED_TRAVERSAL_INTERNET)
}

/// exchangeRolePayload: role-driven capability exchange over a fresh session.
pub(super) async fn exchange_role_payload<T: Serialize + serde::de::DeserializeOwned + 'static>(
    scope: &Scope,
    role_hint: &str,
    token: &str,
    topic_salt: &str,
    local: &T,
    timeout: Duration,
    external: Option<Arc<SignalCall>>,
) -> Result<T, P2pError> {
    let client_id = crypto::mqtt_generate_client_id("WT", token);
    let signal = SignalSession::new(scope, &client_id, external).await?;

    if role_hint == "active" {
        let (remote, _) = signal
            .secure_exchange::<T>(
                scope,
                EXMODE_MUTUAL,
                local,
                topic_salt,
                token,
                timeout,
                None,
            )
            .await?;
        return Ok(remote);
    }
    if role_hint != "passive" {
        return Err(P2pError::new(
            ErrorCode::TraversalPlanNegotiationInvalidPayload,
            "role_hint is required for coordinated traversal",
        ));
    }

    let (remote, broker_index) = signal
        .secure_exchange::<T>(
            scope,
            EXMODE_WAIT_ONLY,
            local,
            topic_salt,
            token,
            timeout,
            None,
        )
        .await?;
    signal
        .secure_publish::<T>(scope, local, topic_salt, token, timeout, broker_index)
        .await?;
    Ok(remote)
}

async fn coordinate_traversal_mode(
    scope: &Scope,
    traversal_mode: &str,
    role_hint: &str,
    token: &str,
    external: Option<Arc<SignalCall>>,
) -> Result<TraversalDecision, P2pError> {
    let legacy = TraversalDecision {
        selected_traversal: SELECTED_TRAVERSAL_INTERNET,
    };
    if traversal_mode == TRAVERSAL_MODE_INTERNET {
        return Ok(legacy);
    }
    let local = TraversalCapability {
        version: 1,
        mode: traversal_mode.to_string(),
        supports_lan: true,
    };
    let remote = match exchange_role_payload(
        scope,
        role_hint,
        token,
        "wgvpn-traversal-capability-v1",
        &local,
        scope.bounded_timeout(Duration::from_secs(8)),
        external.clone(),
    )
    .await
    {
        Ok(remote) => remote,
        Err(err) => {
            if traversal_mode == TRAVERSAL_MODE_AUTO && external.is_none() {
                crate::p2plog!(
                    "UDP tunnel capability exchange unavailable: {}; using secure Internet P2P for compatibility",
                    err
                );
                return Ok(legacy);
            }
            return Err(err.context("LAN capability exchange failed"));
        }
    };
    match select_negotiated_traversal(&local, &remote) {
        Ok(selected) => Ok(TraversalDecision {
            selected_traversal: selected,
        }),
        Err(err) => {
            if traversal_mode == TRAVERSAL_MODE_AUTO && external.is_none() {
                crate::p2plog!(
                    "Peer traversal capability is incompatible: {}; using Internet P2P",
                    err
                );
                return Ok(legacy);
            }
            Err(err)
        }
    }
}

async fn establish_internet_udp_p2p(
    scope: &Scope,
    network: &str,
    bind_ip: &str,
    token: &str,
    external: Option<Arc<SignalCall>>,
) -> (Option<P2PConnInfo>, i32, Option<StartError>) {
    let signal = external.clone();
    establish_internet_udp_p2p_with(scope, network, external, || {
        p2p::easy_p2p_mp_with_signal(
            scope,
            network,
            token,
            EasyP2PMPOptions {
                bind: bind_ip.to_string(),
            },
            signal.clone(),
        )
    })
    .await
}

pub(super) async fn establish_internet_udp_p2p_with<F, Fut>(
    scope: &Scope,
    network: &str,
    external: Option<Arc<SignalCall>>,
    mut punch: F,
) -> (Option<P2PConnInfo>, i32, Option<StartError>)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<P2PConnInfo, P2pError>>,
{
    const RETRY_DELAY: Duration = Duration::from_secs(2);
    let mut attempt: i32 = 1;
    // Furthest-stage failure across attempts. Once the address exchange has
    // succeeded in ANY attempt, the real blocker is the P2P probing stage —
    // later attempts usually fail back at the exchange because the peer has
    // moved on to probing and stopped republishing, so the LAST error would
    // misleadingly blame the exchange stage.
    let mut exchange_ok_attempt: i32 = 0;
    let mut probe_error: Option<P2pError> = None;
    loop {
        crate::p2plog!(
            "=== P2P tunnel attempt {}: network={} ===",
            attempt,
            network
        );
        if let Some(call) = &external {
            call.begin_probe_attempt((attempt - 1) as u8);
        }
        match punch().await {
            Ok(conn_info) => return (Some(conn_info), attempt, None),
            Err(err) => {
                let failed_at_exchange = err.details().is_none();
                crate::p2pevent!(
                    "p2p tunnel attempt failed: attempt={}, network={}, exchange_succeeded={}, deadline_expired={}, remaining_ms={}, error={}",
                    attempt,
                    network,
                    !failed_at_exchange,
                    scope.expired(),
                    scope.remaining().as_millis(),
                    err
                );
                if failed_at_exchange {
                    // peer addresses already obtained earlier → probing stage.
                } else {
                    exchange_ok_attempt = attempt;
                    probe_error = Some(err.clone());
                }
                if err.is_unretryable()
                    || external
                        .as_ref()
                        .is_some_and(|call| !call.native_retry_supported())
                {
                    return (
                        None,
                        attempt,
                        Some(udp_tunnel_error(
                            attempt,
                            &err,
                            &format!("failed to establish gonc p2p tunnel on attempt {}", attempt),
                        )),
                    );
                }
                if scope.expired() {
                    let final_err = if exchange_ok_attempt > 0 {
                        probe_error.clone().unwrap_or_else(|| err.clone())
                    } else {
                        err
                    };
                    return (None, attempt, Some(udp_tunnel_error(attempt, &final_err, &format!(
                        "failed to establish gonc p2p tunnel after {} attempts (exchange ok in attempt {})",
                        attempt, exchange_ok_attempt
                    ))));
                }
                crate::p2plog!(
                    "UDP tunnel P2P attempt {} failed: {}; retrying in {:?}",
                    attempt,
                    err,
                    RETRY_DELAY
                );
                scope.sleep_until_deadline(RETRY_DELAY).await;
            }
        }
        attempt += 1;
    }
}

/// newUDPTunnelError: structured failure diagnostics without the token.
fn udp_tunnel_error(attempt: i32, cause: &P2pError, message: &str) -> StartError {
    let wrapped = format!("{}: {}", message, cause);
    let mut result = UdpTunnelResult {
        ok: false,
        attempts: attempt,
        error: wrapped.clone(),
        error_code: cause.code().as_str().to_owned(),
        ..Default::default()
    };
    if let Some(details) = cause.details() {
        result.network = details.network.clone();
        result.is_client = details.is_client;
        result.local_lan_addr = details.local_lan.clone();
        result.local_nat_addr = details.local_nat.clone();
        result.local_nat_type = details.local_nat_type.clone();
        result.remote_lan_addr = details.remote_lan.clone();
        result.remote_nat_addr = details.remote_nat.clone();
        result.remote_nat_type = details.remote_nat_type.clone();
    }
    StartError {
        tunnel_result: Some(result),
        error: cause.app_error().context(message),
    }
}

pub(super) fn tunnel_budgets(
    caller_budget: Duration,
    probe_budget: Duration,
    coordinated_lan: bool,
) -> (Duration, Option<Duration>) {
    if coordinated_lan {
        (
            caller_budget.min(probe_budget.saturating_add(Duration::from_secs(10))),
            Some(probe_budget),
        )
    } else {
        (caller_budget.min(probe_budget), None)
    }
}

async fn establish_udp_tunnel_p2p(
    scope: &Scope,
    traversal_mode: &str,
    role_hint: &str,
    network: &str,
    bind_ip: &str,
    token: &str,
    external: Option<Arc<SignalCall>>,
    lan_probe_budget: Option<Duration>,
) -> Result<(P2PConnInfo, i32, TraversalDecision), StartError> {
    let decision =
        coordinate_traversal_mode(scope, traversal_mode, role_hint, token, external.clone())
            .await
            .map_err(StartError::from)?;

    if decision.selected_traversal == SELECTED_TRAVERSAL_INTERNET {
        let (conn_info, attempts, err) =
            establish_internet_udp_p2p(scope, network, bind_ip, token, external.clone()).await;
        match conn_info {
            Some(info) => return Ok((info, attempts, decision)),
            None => {
                return Err(err.unwrap_or_else(|| {
                    StartError::coded(
                        crate::error::ErrorCode::TraversalPunchFailed,
                        "failed to establish gonc p2p tunnel",
                    )
                }))
            }
        }
    }

    // LAN traversal.
    let lan_scope = scope.child(lan_probe_budget.unwrap_or(Duration::from_secs(20)));
    let lan_transport = if network.starts_with("tcp") {
        "tcp"
    } else {
        "udp"
    };
    let lan_result = lan::easy_p2p_lan(
        &lan_scope,
        token,
        lan_transport,
        lan_scope.remaining(),
        role_hint == "passive",
    )
    .await;
    let local_success = lan_result.is_ok();
    let local_outcome = TraversalOutcome {
        version: 1,
        success: local_success,
        error: lan_result
            .as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default(),
    };
    let remote_outcome = exchange_role_payload(
        scope,
        role_hint,
        token,
        "wgvpn-lan-outcome-v1",
        &local_outcome,
        scope.bounded_timeout(Duration::from_secs(22)),
        external.clone(),
    )
    .await;

    let lan_ok = matches!((&lan_result, &remote_outcome), (Ok(_), Ok(remote)) if local_success && remote.version >= 1 && remote.success);
    if lan_ok {
        let lan_info = lan_result.expect("lan_ok implies Ok");
        return Ok((lan_info, 1, decision));
    }

    if traversal_mode == TRAVERSAL_MODE_LAN {
        if let Err(lan_err) = lan_result {
            return Err(StartError::from(lan_err));
        }
        if let Err(outcome_err) = remote_outcome {
            return Err(StartError::from(outcome_err));
        }
        if let Ok(remote) = remote_outcome {
            return Err(StartError::coded(
                ErrorCode::TraversalLanProbeFailed,
                format!("peer LAN traversal failed: {}", remote.error),
            ));
        }
    }

    crate::p2plog!("LAN traversal was not successful on both peers; using Internet P2P");
    let decision = TraversalDecision {
        selected_traversal: SELECTED_TRAVERSAL_INTERNET,
    };
    let (conn_info, attempts, err) =
        establish_internet_udp_p2p(scope, network, bind_ip, token, external).await;
    match conn_info {
        Some(info) => Ok((info, attempts, decision)),
        None => Err(err.unwrap_or_else(|| {
            StartError::coded(
                crate::error::ErrorCode::TraversalPunchFailed,
                "failed to establish gonc p2p tunnel",
            )
        })),
    }
}

// ============ public entry ============

pub async fn start_udp_tunnel(
    req: UdpTunnelInput,
    budget: Duration,
) -> Result<StartUdpTunnelOutcome, StartError> {
    start_udp_tunnel_with_signal(req, budget, None).await
}

pub async fn start_udp_tunnel_with_signal(
    req: UdpTunnelInput,
    budget: Duration,
    external: Option<Arc<SignalCall>>,
) -> Result<StartUdpTunnelOutcome, StartError> {
    if req.token.is_empty() {
        return Err(StartError::plain("token is required"));
    }
    if !req.role_hint.is_empty() && req.role_hint != "active" && req.role_hint != "passive" {
        return Err(StartError::plain(format!(
            "unsupported role_hint: {}",
            req.role_hint
        )));
    }
    let traversal_mode = normalize_traversal_mode(&req.traversal_mode).map_err(StartError::from)?;
    if traversal_mode != TRAVERSAL_MODE_INTERNET && req.role_hint.is_empty() {
        return Err(StartError::plain(
            "role_hint is required for coordinated UDP tunnel capabilities",
        ));
    }
    let network = if req.network.is_empty() {
        "udp4"
    } else {
        req.network.as_str()
    };
    // NetworksForStun owns the network matrix: udp4/tcp4/udp6/tcp6 plus the
    // aggregate forms any/any4/any6/tcp/udp. "any" probes tcp6+tcp4+udp4 and
    // the forward layer follows whichever transport the punch lands on
    // (P2PConn dispatch), so the tunnel accepts the full matrix here.
    if stun::networks_for_stun(network).is_err() {
        return Err(StartError::plain(format!(
            "unsupported network for udp tunnel: {}",
            network
        )));
    }
    if req.allow_relay {
        return Err(StartError::plain(
            "relay is not allowed for wgvpn udp tunnel",
        ));
    }
    let local_listen_ip = if req.local_listen_ip.is_empty() {
        "127.0.0.1"
    } else {
        req.local_listen_ip.as_str()
    };
    let remote_target_ip = if req.remote_target_ip.is_empty() {
        "127.0.0.1"
    } else {
        req.remote_target_ip.as_str()
    };
    if req.remote_target_port <= 0 || req.remote_target_port > 65535 {
        return Err(StartError::plain(format!(
            "invalid remote_target_port: {}",
            req.remote_target_port
        )));
    }
    let timeout_secs = if req.timeout_secs <= 0 {
        DEFAULT_TUNNEL_TIMEOUT_SECS
    } else {
        req.timeout_secs
    };
    let probe_budget = Duration::from_secs(timeout_secs as u64);
    // New signaling must still exchange the LAN outcome after the probe expires.
    // Keep legacy MQTT timing unchanged; the registered call and caller budget
    // remain hard limits on the additional coordination time.
    let (budget, lan_probe_budget) = tunnel_budgets(
        budget,
        probe_budget,
        external.is_some() && traversal_mode == TRAVERSAL_MODE_LAN,
    );
    let scope = match &external {
        Some(call) => {
            if !call.matches_uid(&req.token) || !call.call_id().starts_with("network/") {
                return Err(StartError::plain("signal_context_mismatch"));
            }
            call.scope(budget)
        }
        None => Scope::from_timeout(budget),
    };

    let (conn_info, attempt, decision) = establish_udp_tunnel_p2p(
        &scope,
        traversal_mode,
        &req.role_hint,
        network,
        &req.bind_ip,
        &req.token,
        external,
        lan_probe_budget,
    )
    .await?;

    let details = super::candidates::P2PAttemptDetails {
        network: conn_info.networks_used.first().cloned().unwrap_or_default(),
        is_client: conn_info.is_client,
        local_lan: conn_info.local_lan.clone(),
        local_nat: conn_info.local_nat.clone(),
        local_nat_type: conn_info.local_nat_type.clone(),
        remote_lan: conn_info.remote_lan.clone(),
        remote_nat: conn_info.remote_nat.clone(),
        remote_nat_type: conn_info.remote_nat_type.clone(),
    };
    let failure = |error: P2pError| {
        udp_tunnel_error(
            attempt,
            &error.with_details(details.clone()),
            "local forwarding setup failed",
        )
    };
    if scope.expired() {
        return Err(failure(
            scope.interruption(ErrorCode::ConnectionExecutionDeadlineExceeded),
        ));
    }

    let listen_port = req.local_listen_port.max(0) as u16;
    let listen_addr: SocketAddr = format!("{}:{}", local_listen_ip, listen_port)
        .parse()
        .map_err(|e| {
            failure(P2pError::with_source(
                ErrorCode::TraversalLocalForwardInvalidAddress,
                "invalid local listen address",
                e,
            ))
        })?;
    let target_addr: SocketAddr = format!("{}:{}", remote_target_ip, req.remote_target_port)
        .parse()
        .map_err(|e| {
            failure(P2pError::with_source(
                ErrorCode::TraversalLocalForwardInvalidAddress,
                "invalid remote target address",
                e,
            ))
        })?;

    let local_socket = dial_udp_forward(listen_addr, target_addr)
        .await
        .map_err(|e| {
            failure(P2pError::with_source(
                ErrorCode::TraversalLocalForwardIoFailed,
                "bind local udp forward failed",
                e,
            ))
        })?;
    let local_actual = local_socket.local_addr().map_err(|e| {
        failure(P2pError::with_source(
            ErrorCode::TraversalLocalForwardIoFailed,
            "read local udp address failed",
            e,
        ))
    })?;

    let selected_network = conn_info
        .networks_used
        .first()
        .cloned()
        .unwrap_or_else(|| network.to_string());

    let result = UdpTunnelResult {
        ok: true,
        handle_id: String::new(),
        local_forward_addr: local_actual.to_string(),
        local_forward_port: local_actual.port() as i32,
        peer_endpoint: conn_info.peer_address.clone(),
        local_nat_type: conn_info.local_nat_type.clone(),
        remote_nat_type: conn_info.remote_nat_type.clone(),
        network: selected_network,
        selected_traversal: decision.selected_traversal.to_string(),
        transport_mode: TRANSPORT_MODE_PLAIN.to_string(),
        local_lan_addr: conn_info.local_lan.clone(),
        local_nat_addr: conn_info.local_nat.clone(),
        remote_lan_addr: conn_info.remote_lan.clone(),
        remote_nat_addr: conn_info.remote_nat.clone(),
        is_client: conn_info.is_client,
        attempts: attempt,
        error: String::new(),
        error_code: String::new(),
    };

    let token = Arc::new(CancelToken::new());
    let diagnostics = Arc::new(ForwardState::default());
    spawn_forwarders(
        local_socket,
        conn_info.conn,
        target_addr,
        token.clone(),
        diagnostics.clone(),
    );

    Ok(StartUdpTunnelOutcome {
        result,
        stop: TunnelStop { token, diagnostics },
    })
}

/// dialUDPForward: unconnected socket with SO_REUSEADDR, retrying up to 8
/// times when a random port collides with the fixed target port.
async fn dial_udp_forward(
    listen_addr: SocketAddr,
    target_addr: SocketAddr,
) -> std::io::Result<UdpSocket> {
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..8 {
        let socket = netx::tokio_udp(listen_addr, true)?;
        let local = socket.local_addr()?;
        if local.port() != target_addr.port() {
            return Ok(socket);
        }
        last_err = Some(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!(
                "random local forward port collided with target port {}",
                target_addr.port()
            ),
        ));
        drop(socket);
        if listen_addr.port() != 0 {
            break;
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "udp forward bind failed")
    }))
}

/// Cancellation also interrupts pending stream writes and partial frame reads.
fn spawn_forwarder(
    token: Arc<CancelToken>,
    future: impl std::future::Future<Output = ()> + Send + 'static,
) {
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = token.cancelled() => {},
            _ = future => {},
        }
    });
}

/// Bridge the local WG UDP endpoint to the punched UDP or framed TCP transport.
/// Accept local packets only from the fixed WG target.
fn spawn_forwarders(
    local: UdpSocket,
    p2p_conn: P2PConn,
    target_addr: SocketAddr,
    token: Arc<CancelToken>,
    diagnostics: Arc<ForwardState>,
) {
    let local = Arc::new(local);
    diagnostics.details.lock().unwrap().transport = match &p2p_conn {
        P2PConn::Udp(_) => "udp",
        P2PConn::Tcp(_) => "tcp",
    }
    .into();
    match p2p_conn {
        P2PConn::Udp(p2p) => {
            // local → p2p
            {
                let local = local.clone();
                let p2p = p2p.clone();
                let token = token.clone();
                let diagnostics = diagnostics.clone();
                spawn_forwarder(token.clone(), async move {
                    let mut guard = ForwardGuard {
                        token: token.clone(),
                        diagnostics,
                        direction: "local_to_peer",
                        failed: false,
                    };
                    let mut buffers = udp_forward_batch_buffers();
                    let mut packets = Vec::with_capacity(UDP_FORWARD_BATCH_SIZE);
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            received = local.recv_from(&mut buffers[0]) => {
                                match received {
                                    Ok((n, src)) => {
                                        packets.clear();
                                        packets.push((n, src));
                                        while packets.len() < UDP_FORWARD_BATCH_SIZE {
                                            let index = packets.len();
                                            match local.try_recv_from(&mut buffers[index]) {
                                                Ok(packet) => packets.push(packet),
                                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                                                Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => continue,
                                                Err(err) => {
                                                    crate::p2plog!("fwd local→p2p batch recv error: {}", err);
                                                    break;
                                                }
                                            }
                                        }
                                        let mut send_failed = false;
                                        for (index, &(n, src)) in packets.iter().enumerate() {
                                            if src != target_addr {
                                                crate::p2plog!("fwd local→p2p dropped {} bytes from {} (target {})", n, src, target_addr);
                                                continue;
                                            }
                                            if let Err(err) = p2p.send(&buffers[index][..n]).await {
                                                guard.fail("fwd local→p2p send error", &err);
                                                crate::p2plog!("fwd local→p2p send error: {}", err);
                                                send_failed = true;
                                                break;
                                            }
                                            guard.packet(n);
                                        }
                                        if send_failed {
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                                            continue; // stray ICMP on Windows
                                        }
                                        guard.fail("fwd local→p2p recv error", &err);
                                        crate::p2plog!("fwd local→p2p recv error: {}", err);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
            // p2p → local
            {
                let local = local.clone();
                let token = token.clone();
                let diagnostics = diagnostics.clone();
                spawn_forwarder(token.clone(), async move {
                    let mut guard = ForwardGuard {
                        token: token.clone(),
                        diagnostics,
                        direction: "peer_to_local",
                        failed: false,
                    };
                    let mut buffers = udp_forward_batch_buffers();
                    let mut lengths = Vec::with_capacity(UDP_FORWARD_BATCH_SIZE);
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            received = p2p.recv(&mut buffers[0]) => {
                                match received {
                                    Ok(n) => {
                                        lengths.clear();
                                        lengths.push(n);
                                        while lengths.len() < UDP_FORWARD_BATCH_SIZE {
                                            let index = lengths.len();
                                            match p2p.try_recv(&mut buffers[index]) {
                                                Ok(n) => lengths.push(n),
                                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                                                Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => continue,
                                                Err(err) => {
                                                    crate::p2plog!("fwd p2p→local batch recv error: {}", err);
                                                    break;
                                                }
                                            }
                                        }
                                        let mut send_failed = false;
                                        for (index, &n) in lengths.iter().enumerate() {
                                            if let Err(err) = local.send_to(&buffers[index][..n], target_addr).await {
                                                guard.fail("fwd p2p→local send error", &err);
                                                crate::p2plog!("fwd p2p→local send error: {}", err);
                                                send_failed = true;
                                                break;
                                            }
                                            guard.packet(n);
                                        }
                                        if send_failed {
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                                            continue; // stray ICMP on Windows
                                        }
                                        guard.fail("fwd p2p→local recv error", &err);
                                        crate::p2plog!("fwd p2p→local recv error: {}", err);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
        P2PConn::Tcp(conn) => {
            let (mut rd, mut wr) = conn.stream.into_split();
            // local → p2p: datagram → length-framed stream write
            {
                let local = local.clone();
                let token = token.clone();
                let diagnostics = diagnostics.clone();
                spawn_forwarder(token.clone(), async move {
                    let mut guard = ForwardGuard {
                        token: token.clone(),
                        diagnostics,
                        direction: "local_to_peer",
                        failed: false,
                    };
                    use tokio::io::AsyncWriteExt;
                    let mut buf = vec![0u8; netx::UDP_FORWARD_BUF];
                    let mut frame = Vec::with_capacity(netx::UDP_FORWARD_BUF + 2);
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            received = local.recv_from(&mut buf) => {
                                match received {
                                    Ok((n, src)) => {
                                        if src != target_addr {
                                            crate::p2plog!("fwd local→p2p(tcp) dropped {} bytes from {} (target {})", n, src, target_addr);
                                            continue;
                                        }
                                        frame.clear();
                                        frame.extend_from_slice(&(n as u16).to_le_bytes());
                                        frame.extend_from_slice(&buf[..n]);
                                        if let Err(err) = wr.write_all(&frame).await {
                                            guard.fail("fwd local→p2p(tcp) write error", &err);
                                            crate::p2plog!("fwd local→p2p(tcp) write error: {}", err);
                                            break;
                                        }
                                        guard.packet(n);
                                    }
                                    Err(err) => {
                                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                                            continue;
                                        }
                                        guard.fail("fwd local→p2p(tcp) recv error", &err);
                                        crate::p2plog!("fwd local→p2p(tcp) recv error: {}", err);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
            // p2p → local: length-framed stream read → datagram
            {
                let local = local;
                let token = token;
                spawn_forwarder(token.clone(), async move {
                    let mut guard = ForwardGuard {
                        token: token.clone(),
                        diagnostics,
                        direction: "peer_to_local",
                        failed: false,
                    };
                    use tokio::io::AsyncReadExt;
                    let mut hdr = [0u8; 2];
                    let mut payload = vec![0u8; u16::MAX as usize];
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            read = rd.read_exact(&mut hdr) => {
                                if let Err(err) = read {
                                    guard.fail("tcp_read_header", &err);
                                    break;
                                }
                                let len = u16::from_le_bytes(hdr) as usize;
                                if len == 0 {
                                    continue; // EOF frame is unused on this path
                                }
                                let mut ok = true;
                                tokio::select! {
                                    _ = token.cancelled() => break,
                                    read = rd.read_exact(&mut payload[..len]) => {
                                        if let Err(err) = read {
                                            guard.fail("tcp_read_payload", &err);
                                            crate::p2plog!("fwd p2p→local(tcp) read error: {}", err);
                                            ok = false;
                                        }
                                    }
                                }
                                if !ok {
                                    break;
                                }
                                if let Err(err) = local.send_to(&payload[..len], target_addr).await {
                                    guard.fail("fwd p2p→local(tcp) send error", &err);
                                    crate::p2plog!("fwd p2p→local(tcp) send error: {}", err);
                                    break;
                                }
                                guard.packet(len);
                            }
                        }
                    }
                });
            }
        }
    }
}
