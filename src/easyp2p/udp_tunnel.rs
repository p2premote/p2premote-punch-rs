//! Port of easyp2p/udp_tunnel.go: StartUDPTunnel — traversal-mode
//! negotiation over MQTT, LAN or Internet punching, then a local UDP forwarder
//! bridging the local WireGuard endpoint to the punched P2P socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use super::crypto;
use super::lan;
use super::mqtt_signal::{self, MqttSignalSession};
use super::netx;
use super::p2p::{self, EasyP2PMPOptions, P2PConn, P2PConnInfo};
use super::{CancelToken, P2pError, Scope, EXMODE_MUTUAL, EXMODE_WAIT_ONLY};
use crate::types::{UdpTunnelInput, UdpTunnelResult};

pub const TRAVERSAL_MODE_AUTO: &str = "auto";
pub const TRAVERSAL_MODE_INTERNET: &str = "internet";
pub const TRAVERSAL_MODE_LAN: &str = "lan";

const SELECTED_TRAVERSAL_INTERNET: &str = "internet";
const SELECTED_TRAVERSAL_LAN: &str = "lan";
const TRANSPORT_MODE_PLAIN: &str = "plain";

/// Error carrying the structured failure result for the FFI (UDPTunnelError).
#[derive(Debug)]
pub struct StartError {
    pub tunnel_result: Option<UdpTunnelResult>,
    pub message: String,
}

impl StartError {
    fn plain<S: Into<String>>(message: S) -> Self {
        StartError {
            tunnel_result: None,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub struct TunnelStop {
    token: Arc<CancelToken>,
}

impl TunnelStop {
    pub fn stop(&self) {
        self.token.cancel();
    }
}

pub struct StartUdpTunnelOutcome {
    pub result: UdpTunnelResult,
    pub stop: TunnelStop,
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
        _ => Err(P2pError::msg(format!("unsupported traversal_mode: {}", mode))),
    }
}

fn select_negotiated_traversal(local: &TraversalCapability, remote: &TraversalCapability) -> Result<&'static str, P2pError> {
    if remote.version < 1 {
        return Err(P2pError::msg("peer does not support traversal negotiation"));
    }
    if normalize_traversal_mode(&remote.mode).is_err() || remote.mode.is_empty() {
        return Err(P2pError::msg(format!(
            "peer advertised invalid traversal mode {:?}",
            remote.mode
        )));
    }
    if local.mode == TRAVERSAL_MODE_LAN || remote.mode == TRAVERSAL_MODE_LAN {
        if local.mode == TRAVERSAL_MODE_INTERNET || remote.mode == TRAVERSAL_MODE_INTERNET {
            return Err(P2pError::msg(format!(
                "peer traversal modes conflict: local={} remote={}",
                local.mode, remote.mode
            )));
        }
        if !local.supports_lan || !remote.supports_lan {
            return Err(P2pError::msg("LAN traversal is not supported by both peers"));
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
async fn exchange_role_payload<T: Serialize + serde::de::DeserializeOwned + 'static>(
    scope: &Scope,
    role_hint: &str,
    token: &str,
    topic_salt: &str,
    local: &T,
    timeout: Duration,
) -> Result<T, P2pError> {
    let client_id = crypto::mqtt_generate_client_id("WT", token);
    let signal = MqttSignalSession::new(scope, &client_id, "").await?;

    if role_hint == "active" {
        let (remote, _) = mqtt_signal::secure_exchange_with_session::<T>(
            scope, &signal, EXMODE_MUTUAL, local, topic_salt, token, timeout, None,
        )
        .await?;
        return Ok(remote);
    }
    if role_hint != "passive" {
        return Err(P2pError::msg("role_hint is required for coordinated traversal"));
    }

    let (remote, broker_index) = mqtt_signal::secure_exchange_with_session::<T>(
        scope, &signal, EXMODE_WAIT_ONLY, local, topic_salt, token, timeout, None,
    )
    .await?;
    mqtt_signal::mqtt_secure_publish_with_session::<T>(
        scope, &signal, local, topic_salt, token, timeout, broker_index,
    )
    .await?;
    Ok(remote)
}

async fn coordinate_traversal_mode(
    scope: &Scope,
    traversal_mode: &str,
    role_hint: &str,
    token: &str,
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
    )
    .await
    {
        Ok(remote) => remote,
        Err(err) => {
            if traversal_mode == TRAVERSAL_MODE_AUTO || traversal_mode == TRAVERSAL_MODE_INTERNET {
                crate::p2plog!(
                    "UDP tunnel capability exchange unavailable: {}; using secure Internet P2P for compatibility",
                    err
                );
                return Ok(legacy);
            }
            return Err(P2pError::msg(format!("LAN capability exchange failed: {}", err)));
        }
    };
    match select_negotiated_traversal(&local, &remote) {
        Ok(selected) => Ok(TraversalDecision { selected_traversal: selected }),
        Err(err) => {
            if traversal_mode == TRAVERSAL_MODE_AUTO {
                crate::p2plog!("Peer traversal capability is incompatible: {}; using Internet P2P", err);
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
) -> (Option<P2PConnInfo>, i32, Option<StartError>) {
    const RETRY_DELAY: Duration = Duration::from_secs(2);
    let mut attempt: i32 = 1;
    loop {
        crate::p2plog!("=== UDP tunnel P2P attempt {} ===", attempt);
        match p2p::easy_p2p_mp_with_options(
            scope,
            network,
            token,
            EasyP2PMPOptions {
                bind: bind_ip.to_string(),
            },
        )
        .await
        {
            Ok(conn_info) => return (Some(conn_info), attempt, None),
            Err(err) => {
                if err.is_unretryable() {
                    return (None, attempt, Some(udp_tunnel_error(attempt, &err, &format!(
                        "failed to establish gonc p2p tunnel on attempt {}", attempt
                    ))));
                }
                if scope.expired() {
                    return (None, attempt, Some(udp_tunnel_error(attempt, &err, &format!(
                        "failed to establish gonc p2p tunnel after {} attempts", attempt
                    ))));
                }
                crate::p2plog!(
                    "UDP tunnel P2P attempt {} failed: {}; retrying in {:?}",
                    attempt, err, RETRY_DELAY
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
        message: wrapped,
    }
}

async fn establish_udp_tunnel_p2p(
    scope: &Scope,
    traversal_mode: &str,
    role_hint: &str,
    network: &str,
    bind_ip: &str,
    token: &str,
) -> Result<(P2PConnInfo, i32, TraversalDecision), StartError> {
    let decision = coordinate_traversal_mode(scope, traversal_mode, role_hint, token)
        .await
        .map_err(|e| StartError::plain(e.to_string()))?;

    if decision.selected_traversal == SELECTED_TRAVERSAL_INTERNET {
        let (conn_info, attempts, err) = establish_internet_udp_p2p(scope, network, bind_ip, token).await;
        match conn_info {
            Some(info) => return Ok((info, attempts, decision)),
            None => return Err(err.unwrap_or_else(|| StartError::plain("failed to establish gonc p2p tunnel"))),
        }
    }

    // LAN traversal.
    let lan_scope = scope.child(scope.bounded_timeout(Duration::from_secs(20)));
    let lan_transport = if network == "tcp4" { "tcp" } else { "udp" };
    let lan_result = lan::easy_p2p_lan(&lan_scope, token, lan_transport, lan_scope.remaining(), role_hint == "passive").await;
    let local_success = lan_result.is_ok();
    let local_outcome = TraversalOutcome {
        version: 1,
        success: local_success,
        error: lan_result.as_ref().err().map(|e| e.to_string()).unwrap_or_default(),
    };
    let remote_outcome = exchange_role_payload(
        scope,
        role_hint,
        token,
        "wgvpn-lan-outcome-v1",
        &local_outcome,
        scope.bounded_timeout(Duration::from_secs(22)),
    )
    .await;

    let lan_ok = matches!((&lan_result, &remote_outcome), (Ok(_), Ok(remote)) if local_success && remote.version >= 1 && remote.success);
    if lan_ok {
        let lan_info = lan_result.expect("lan_ok implies Ok");
        return Ok((lan_info, 1, decision));
    }

    if traversal_mode == TRAVERSAL_MODE_LAN {
        if let Err(lan_err) = lan_result {
            return Err(StartError::plain(format!("LAN traversal failed: {}", lan_err)));
        }
        if let Err(outcome_err) = remote_outcome {
            return Err(StartError::plain(format!("LAN outcome exchange failed: {}", outcome_err)));
        }
        if let Ok(remote) = remote_outcome {
            return Err(StartError::plain(format!("peer LAN traversal failed: {}", remote.error)));
        }
    }

    crate::p2plog!("LAN traversal was not successful on both peers; using Internet P2P");
    let decision = TraversalDecision {
        selected_traversal: SELECTED_TRAVERSAL_INTERNET,
    };
    let (conn_info, attempts, err) = establish_internet_udp_p2p(scope, network, bind_ip, token).await;
    match conn_info {
        Some(info) => Ok((info, attempts, decision)),
        None => Err(err.unwrap_or_else(|| StartError::plain("failed to establish gonc p2p tunnel"))),
    }
}

// ============ public entry ============

pub async fn start_udp_tunnel(req: UdpTunnelInput, budget: Duration) -> Result<StartUdpTunnelOutcome, StartError> {
    if req.token.is_empty() {
        return Err(StartError::plain("token is required"));
    }
    if !req.role_hint.is_empty() && req.role_hint != "active" && req.role_hint != "passive" {
        return Err(StartError::plain(format!("unsupported role_hint: {}", req.role_hint)));
    }
    let traversal_mode = normalize_traversal_mode(&req.traversal_mode)
        .map_err(|e| StartError::plain(e.to_string()))?;
    if traversal_mode != TRAVERSAL_MODE_INTERNET && req.role_hint.is_empty() {
        return Err(StartError::plain("role_hint is required for coordinated UDP tunnel capabilities"));
    }
    let network = if req.network.is_empty() { "udp4" } else { req.network.as_str() };
    if network != "udp4" && network != "tcp4" {
        return Err(StartError::plain(format!("unsupported network for udp tunnel: {}", network)));
    }
    if req.allow_relay {
        return Err(StartError::plain("relay is not allowed for wgvpn udp tunnel"));
    }
    let local_listen_ip = if req.local_listen_ip.is_empty() { "127.0.0.1" } else { req.local_listen_ip.as_str() };
    let remote_target_ip = if req.remote_target_ip.is_empty() { "127.0.0.1" } else { req.remote_target_ip.as_str() };
    if req.remote_target_port <= 0 || req.remote_target_port > 65535 {
        return Err(StartError::plain(format!("invalid remote_target_port: {}", req.remote_target_port)));
    }
    let timeout_secs = if req.timeout_secs <= 0 { 45 } else { req.timeout_secs };
    let scope = Scope::from_timeout(budget.min(Duration::from_secs(timeout_secs as u64)));

    let (conn_info, attempt, decision) = establish_udp_tunnel_p2p(
        &scope,
        traversal_mode,
        &req.role_hint,
        network,
        &req.bind_ip,
        &req.token,
    )
    .await?;

    let listen_port = req.local_listen_port.max(0) as u16;
    let listen_addr: SocketAddr = format!("{}:{}", local_listen_ip, listen_port)
        .parse()
        .map_err(|e| StartError::plain(format!("resolve local listen addr failed: {}", e)))?;
    let target_addr: SocketAddr = format!("{}:{}", remote_target_ip, req.remote_target_port)
        .parse()
        .map_err(|e| StartError::plain(format!("resolve remote target addr failed: {}", e)))?;

    let local_socket = dial_udp_forward(listen_addr, target_addr)
        .await
        .map_err(|e| StartError::plain(format!("dial local udp forward failed: {}", e)))?;
    let local_actual = local_socket.local_addr().map_err(|e| StartError::plain(e.to_string()))?;

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
    };

    let token = Arc::new(CancelToken::new());
    spawn_forwarders(local_socket, conn_info.conn, target_addr, token.clone());

    Ok(StartUdpTunnelOutcome {
        result,
        stop: TunnelStop { token },
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
            format!("random local forward port collided with target port {}", target_addr.port()),
        ));
        drop(socket);
        if listen_addr.port() != 0 {
            break;
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "udp forward bind failed")))
}

/// copyPackets ×2: local WG endpoint ↔ punched P2P connection. The local side
/// is always a UDP socket (the WG endpoint is UDP); when the P2P transport is
/// TCP the datagrams are carried over the stream with a 2-byte little-endian
/// length frame per datagram (netx.FramedConn semantics). The local socket
/// only accepts packets sourced from the fixed target (BoundUDPConn filter) —
/// a connected socket would surface async ECONNREFUSED from stray ICMP.
fn spawn_forwarders(
    local: UdpSocket,
    p2p_conn: P2PConn,
    target_addr: SocketAddr,
    token: Arc<CancelToken>,
) {
    let local = Arc::new(local);
    match p2p_conn {
        P2PConn::Udp(p2p) => {
            // local → p2p
            {
                let local = local.clone();
                let p2p = p2p.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; netx::UDP_FORWARD_BUF];
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            received = local.recv_from(&mut buf) => {
                                match received {
                                    Ok((n, src)) => {
                                        if src != target_addr {
                                            crate::p2plog!("fwd local→p2p dropped {} bytes from {} (target {})", n, src, target_addr);
                                            continue;
                                        }
                                        crate::p2plog!("fwd local→p2p forwarding {} bytes from {}", n, src);
                                        if let Err(err) = p2p.send(&buf[..n]).await {
                                            crate::p2plog!("fwd local→p2p send error: {}", err);
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                                            continue; // stray ICMP on Windows
                                        }
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
                tokio::spawn(async move {
                    let mut buf = vec![0u8; netx::UDP_FORWARD_BUF];
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            received = p2p.recv(&mut buf) => {
                                match received {
                                    Ok(n) => {
                                        crate::p2plog!("fwd p2p→local forwarding {} bytes to {}", n, target_addr);
                                        if let Err(err) = local.send_to(&buf[..n], target_addr).await {
                                            crate::p2plog!("fwd p2p→local send error: {}", err);
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                                            continue; // stray ICMP on Windows
                                        }
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
                tokio::spawn(async move {
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
                                            crate::p2plog!("fwd local→p2p(tcp) write error: {}", err);
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                                            continue;
                                        }
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
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut hdr = [0u8; 2];
                    let mut payload = vec![0u8; u16::MAX as usize];
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            read = rd.read_exact(&mut hdr) => {
                                if read.is_err() {
                                    crate::p2plog!("fwd p2p→local(tcp) header read error");
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
                                            crate::p2plog!("fwd p2p→local(tcp) read error: {}", err);
                                            ok = false;
                                        }
                                    }
                                }
                                if !ok {
                                    break;
                                }
                                if let Err(err) = local.send_to(&payload[..len], target_addr).await {
                                    crate::p2plog!("fwd p2p→local(tcp) send error: {}", err);
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    }
}
