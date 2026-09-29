//! Port of easyp2p/lan.go: authenticated LAN discovery over UDP multicast
//! (239.255.255.250:19730, four-step B/R/C/A handshake) used by
//! traversal_mode=auto/lan.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::candidates::P2PAddressInfo;
use super::netx;
use super::p2p::{P2PConn, P2PSessionContext};
use super::punch_tcp;
use super::punch_udp;
use super::{P2pError, Result, Scope};

pub const LAN_MULTICAST_IP: &str = "239.255.255.250";
pub const LAN_MULTICAST_PORT: u16 = 19730;
const LAN_BEACON_MAGIC: &str = "GONC-LAN-V1";
const LAN_NONCE_SIZE: usize = 16;

const LAN_ACTIVE_BEACON_INTERVAL: Duration = Duration::from_millis(1500);
const LAN_ACTIVE_SLOW_BEACON_INTERVAL: Duration = Duration::from_secs(5);
const LAN_ACTIVE_FAST_BEACON_WINDOW: Duration = Duration::from_secs(30);
const LAN_PASSIVE_BEACON_INTERVAL: Duration = Duration::from_secs(15);

// ============ messages ============

#[derive(Debug, Serialize, Deserialize)]
struct LanMsg {
    #[serde(rename = "m")]
    magic: String,
    #[serde(rename = "t")]
    kind: String,
    #[serde(rename = "p")]
    payload: String,
    #[serde(rename = "mac")]
    mac: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LanBeacon {
    #[serde(rename = "sid")]
    session_id: String,
    #[serde(rename = "na")]
    nonce_a: String,
    #[serde(rename = "tp")]
    transport: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LanResponse {
    #[serde(rename = "na")]
    nonce_a: String,
    #[serde(rename = "nb")]
    nonce_b: String,
    #[serde(rename = "tp")]
    transport: String,
    #[serde(rename = "ip")]
    ip: String,
    #[serde(rename = "port")]
    port: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LanConfirm {
    #[serde(rename = "nb")]
    nonce_b: String,
    #[serde(rename = "tp")]
    transport: String,
    #[serde(rename = "ip")]
    ip: String,
    #[serde(rename = "port")]
    port: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LanAck {
    #[serde(rename = "na")]
    nonce_a: String,
}

#[derive(Debug, Clone)]
pub struct LanDiscoverResult {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub transport: String,
}

// ============ crypto ============

fn b64_raw_engine() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD_NO_PAD
}

fn lan_derive_key(session_key: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"gonc-lan-discovery-v1");
    h.update(session_key.as_bytes());
    h.finalize().into()
}

fn lan_derive_session_id(session_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"gonc-lan-session-id-v1");
    h.update(session_key.as_bytes());
    b64_raw_engine().encode(&h.finalize()[..12])
}

fn lan_hmac(key: &[u8; 32], t: &str, p: &str) -> String {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(format!("{}|{}", t, p).as_bytes());
    b64_raw_engine().encode(mac.finalize().into_bytes())
}

fn lan_encode<T: Serialize>(key: &[u8; 32], t: &str, payload: &T) -> Vec<u8> {
    let pb = serde_json::to_string(payload).unwrap_or_default();
    let p64 = b64_raw_engine().encode(pb.as_bytes());
    let msg = LanMsg {
        magic: LAN_BEACON_MAGIC.to_string(),
        kind: t.to_string(),
        mac: lan_hmac(key, t, &p64),
        payload: p64,
    };
    serde_json::to_vec(&msg).unwrap_or_default()
}

fn lan_decode(key: &[u8; 32], data: &[u8]) -> Option<LanMsg> {
    let msg: LanMsg = serde_json::from_slice(data).ok()?;
    if msg.magic != LAN_BEACON_MAGIC || msg.mac != lan_hmac(key, &msg.kind, &msg.payload) {
        return None;
    }
    Some(msg)
}

fn lan_unmarshal<T: for<'de> Deserialize<'de>>(msg: &LanMsg) -> Option<T> {
    let raw = b64_raw_engine().decode(msg.payload.as_bytes()).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn lan_nonce() -> String {
    let mut b = [0u8; LAN_NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b64_raw_engine().encode(b)
}

fn negotiate_transport(a: &str, b: &str) -> String {
    if a == "udp" || b == "udp" {
        "udp".to_string()
    } else {
        "tcp".to_string()
    }
}

fn best_local_ip_for_remote(remote_ip: &str) -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    let target = format!("{}:1", remote_ip);
    sock.connect(target).ok()?;
    sock.local_addr().ok().map(|a| a.ip().to_string())
}

// ============ multicast socket ============

struct LanMcast {
    socket: Arc<UdpSocket>,
    group: SocketAddrV4,
    iface_addrs: Vec<Ipv4Addr>,
}

impl LanMcast {
    fn new() -> std::io::Result<LanMcast> {
        let group = Ipv4Addr::new(239, 255, 255, 250);
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true).ok();
        socket.bind(&socket2::SockAddr::from(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            LAN_MULTICAST_PORT,
        ))))?;
        socket.set_multicast_loop_v4(true)?;
        socket.set_nonblocking(true)?;

        let mut iface_addrs = Vec::new();
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for iface in ifaces {
                if let std::net::IpAddr::V4(v4) = iface.ip() {
                    if v4.is_loopback() || v4.is_unspecified() {
                        continue;
                    }
                    // Join on every IPv4 interface; failures tolerated.
                    if socket.join_multicast_v4(&group, &v4).is_ok() {
                        iface_addrs.push(v4);
                    }
                }
            }
        }
        if iface_addrs.is_empty() {
            socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)?;
        }

        Ok(LanMcast {
            socket: Arc::new(UdpSocket::from_std(socket.into())?),
            group: SocketAddrV4::new(group, LAN_MULTICAST_PORT),
            iface_addrs,
        })
    }

    async fn broadcast(&self, data: &[u8]) {
        let dst = SocketAddr::V4(self.group);
        for iface in &self.iface_addrs {
            let sock_ref = socket2::SockRef::from(self.socket.as_ref());
            let _ = sock_ref.set_multicast_if_v4(iface);
            let _ = sock_ref.set_multicast_ttl_v4(2);
            let _ = self.socket.send_to(data, dst).await;
        }
        if self.iface_addrs.is_empty() {
            let _ = self.socket.send_to(data, dst).await;
        }
    }

    async fn send_to(&self, data: &[u8], dst: Option<SocketAddr>) {
        if let Some(dst) = dst {
            let _ = self.socket.send_to(data, dst).await;
        }
    }
}

// ============ discovery ============

struct Dispatch {
    beacon: mpsc::Receiver<(LanMsg, SocketAddr)>,
    response: mpsc::Receiver<(LanMsg, SocketAddr)>,
    confirm: mpsc::Receiver<(LanMsg, SocketAddr)>,
    ack: mpsc::Receiver<(LanMsg, SocketAddr)>,
}

fn spawn_dispatcher(mc: Arc<LanMcast>, stop: Arc<crate::easyp2p::CancelToken>, key: [u8; 32]) -> Dispatch {
    let (beacon_tx, beacon_rx) = mpsc::channel(32);
    let (response_tx, response_rx) = mpsc::channel(32);
    let (confirm_tx, confirm_rx) = mpsc::channel(32);
    let (ack_tx, ack_rx) = mpsc::channel(32);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let received = tokio::select! {
                _ = stop.cancelled() => return,
                r = mc.socket.recv_from(&mut buf) => r,
            };
            let Ok((n, src)) = received else { return };
            let Some(msg) = lan_decode(&key, &buf[..n]) else { continue };
            let pkt = (msg, src);
            match pkt.0.kind.as_str() {
                "B" => { let _ = beacon_tx.try_send(pkt); }
                "R" => { let _ = response_tx.try_send(pkt); }
                "C" => { let _ = confirm_tx.try_send(pkt); }
                "A" => { let _ = ack_tx.try_send(pkt); }
                _ => {}
            }
        }
    });
    Dispatch {
        beacon: beacon_rx,
        response: response_rx,
        confirm: confirm_rx,
        ack: ack_rx,
    }
}

pub async fn lan_discover(
    scope: &Scope,
    session_key: &str,
    transport_pref: &str,
    timeout: Duration,
    passive: bool,
) -> Result<LanDiscoverResult> {
    let scope = scope.child(timeout);
    let key = lan_derive_key(session_key);
    let sid = lan_derive_session_id(session_key);
    let self_nonces: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let punch_port: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(None));

    let mc = Arc::new(LanMcast::new().map_err(|e| P2pError::msg(format!("bind {}:{}: {}", LAN_MULTICAST_IP, LAN_MULTICAST_PORT, e)))?);
    let stop = Arc::new(crate::easyp2p::CancelToken::new());
    let mut dispatch = spawn_dispatcher(mc.clone(), stop.clone(), key);

    let (result_tx, mut result_rx) = mpsc::channel::<std::result::Result<LanDiscoverResult, P2pError>>(2);

    // initiator
    {
        let mc = mc.clone();
        let mut response = std::mem::replace(&mut dispatch.response, mpsc::channel(1).1);
        let mut ack = std::mem::replace(&mut dispatch.ack, mpsc::channel(1).1);
        let result_tx = result_tx.clone();
        let self_nonces = self_nonces.clone();
        let punch_port = punch_port.clone();
        let scope = scope.clone();
        let sid = sid.clone();
        let tp = transport_pref.to_string();
        tokio::spawn(async move {
            let result = lan_initiator(&scope, &mc, &mut response, &mut ack, &key, &sid, &tp, &self_nonces, &punch_port, passive).await;
            let _ = result_tx.send(result).await;
        });
    }
    // responder
    {
        let mc = mc.clone();
        let mut beacon = dispatch.beacon;
        let mut confirm = dispatch.confirm;
        let result_tx = result_tx.clone();
        let self_nonces = self_nonces.clone();
        let punch_port = punch_port.clone();
        let sid = sid.clone();
        let tp = transport_pref.to_string();
        let scope = scope.clone();
        tokio::spawn(async move {
            let result = lan_responder(&scope, &mc, &mut beacon, &mut confirm, &key, &sid, &tp, &self_nonces, &punch_port).await;
            let _ = result_tx.send(result).await;
        });
    }
    drop(result_tx);

    let outcome = tokio::select! {
        result = result_rx.recv() => {
            stop.cancel();
            result.unwrap_or_else(|| Err(P2pError::msg("LAN discovery failed")))
        }
        _ = scope.sleep_until_deadline(scope.remaining()) => {
            stop.cancel();
            Err(P2pError::msg("LAN discovery timeout"))
        }
    };
    outcome
}

fn next_beacon_delay(passive: bool, beacons_sent: u32) -> Duration {
    if !passive {
        let fast = (LAN_ACTIVE_FAST_BEACON_WINDOW.as_millis() / LAN_ACTIVE_BEACON_INTERVAL.as_millis()) as u32;
        if beacons_sent > fast {
            return LAN_ACTIVE_SLOW_BEACON_INTERVAL;
        }
        return LAN_ACTIVE_BEACON_INTERVAL;
    }
    match beacons_sent {
        1 => Duration::from_millis(250),
        2 => Duration::from_millis(750),
        3 => Duration::from_secs(4),
        4 => Duration::from_secs(10),
        _ => LAN_PASSIVE_BEACON_INTERVAL,
    }
}

fn take_punch_port(punch_port: &Arc<Mutex<Option<u16>>>) -> Result<u16> {
    let mut guard = punch_port.lock().unwrap();
    if guard.is_none() {
        *guard = Some(netx::get_free_port().map_err(|e| P2pError::msg(format!("allocate LAN punch port: {}", e)))?);
    }
    Ok(guard.unwrap())
}

async fn lan_initiator(
    scope: &Scope,
    mc: &Arc<LanMcast>,
    response_rx: &mut mpsc::Receiver<(LanMsg, SocketAddr)>,
    ack_rx: &mut mpsc::Receiver<(LanMsg, SocketAddr)>,
    key: &[u8; 32],
    sid: &str,
    tp: &str,
    self_nonces: &Arc<Mutex<HashSet<String>>>,
    punch_port: &Arc<Mutex<Option<u16>>>,
    passive: bool,
) -> Result<LanDiscoverResult> {
    let nonce_a = lan_nonce();
    self_nonces.lock().unwrap().insert(nonce_a.clone());

    let beacon_data = lan_encode(key, "B", &LanBeacon {
        session_id: sid.to_string(),
        nonce_a: nonce_a.clone(),
        transport: tp.to_string(),
    });

    let role_name = if passive { "Passive" } else { "Initiator" };
    crate::p2plog!("[LAN] {}: broadcasting beacon", role_name);
    mc.broadcast(&beacon_data).await;

    let mut beacons_sent: u32 = 1;
    let mut beacon_delay = next_beacon_delay(passive, beacons_sent);

    // Phase 1: wait for a Response.
    let resp: (LanResponse, SocketAddr) = loop {
        tokio::select! {
            _ = scope.sleep_until_deadline(scope.remaining()) => return Err(P2pError::msg("LAN discovery timeout")),
            _ = tokio::time::sleep(beacon_delay) => {
                mc.broadcast(&beacon_data).await;
                beacons_sent += 1;
                beacon_delay = next_beacon_delay(passive, beacons_sent);
            }
            pkt = response_rx.recv() => {
                let Some((msg, src)) = pkt else { return Err(P2pError::msg("LAN discovery failed")) };
                let Some(resp): Option<LanResponse> = lan_unmarshal(&msg) else { continue };
                if resp.nonce_a != nonce_a { continue; }
                break (resp, src);
            }
        }
    };

    let local_ip = best_local_ip_for_remote(&resp.0.ip).unwrap_or_default();
    let final_tp = negotiate_transport(tp, &resp.0.transport);
    let port = take_punch_port(punch_port)?;
    crate::p2plog!("[LAN] {}: got response from {}:{}, localIP={}", role_name, resp.0.ip, resp.0.port, local_ip);

    // Phase 2: send Confirm + wait for Ack.
    let confirm_data = lan_encode(key, "C", &LanConfirm {
        nonce_b: resp.0.nonce_b.clone(),
        transport: final_tp.clone(),
        ip: local_ip.clone(),
        port: port as i64,
    });
    for _ in 0..3 {
        mc.broadcast(&confirm_data).await;
        mc.send_to(&confirm_data, Some(resp.1)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut confirm_ticker = tokio::time::interval(Duration::from_millis(300));
    confirm_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    confirm_ticker.tick().await; // consume immediate tick
    loop {
        tokio::select! {
            _ = scope.sleep_until_deadline(scope.remaining()) => return Err(P2pError::msg("LAN discovery timeout")),
            _ = confirm_ticker.tick() => {
                mc.broadcast(&confirm_data).await;
                mc.send_to(&confirm_data, Some(resp.1)).await;
            }
            pkt = ack_rx.recv() => {
                let Some((msg, _)) = pkt else { return Err(P2pError::msg("LAN discovery failed")) };
                let Some(ack): Option<LanAck> = lan_unmarshal(&msg) else { continue };
                if ack.nonce_a != nonce_a { continue; }
                crate::p2plog!("[LAN] {}: got ACK → discovery complete", role_name);
                return Ok(LanDiscoverResult {
                    local_ip,
                    local_port: port,
                    remote_ip: resp.0.ip,
                    remote_port: resp.0.port as u16,
                    transport: final_tp,
                });
            }
        }
    }
}

async fn lan_responder(
    scope: &Scope,
    mc: &Arc<LanMcast>,
    beacon_rx: &mut mpsc::Receiver<(LanMsg, SocketAddr)>,
    confirm_rx: &mut mpsc::Receiver<(LanMsg, SocketAddr)>,
    key: &[u8; 32],
    sid: &str,
    tp: &str,
    self_nonces: &Arc<Mutex<HashSet<String>>>,
    punch_port: &Arc<Mutex<Option<u16>>>,
) -> Result<LanDiscoverResult> {
    crate::p2plog!("[LAN] Responder: listening");
    loop {
        // Phase 1: wait for a Beacon.
        let (beacon, src, remote_ip, local_ip) = loop {
            tokio::select! {
                _ = scope.sleep_until_deadline(scope.remaining()) => return Err(P2pError::msg("LAN discovery timeout")),
                pkt = beacon_rx.recv() => {
                    let Some((msg, src)) = pkt else { return Err(P2pError::msg("LAN discovery failed")) };
                    let Some(b): Option<LanBeacon> = lan_unmarshal(&msg) else { continue };
                    if b.session_id != sid || self_nonces.lock().unwrap().contains(&b.nonce_a) { continue; }
                    let remote_ip = src.ip().to_string();
                    let Some(local_ip) = best_local_ip_for_remote(&remote_ip) else { continue };
                    if local_ip == remote_ip { continue; }
                    break (b, src, remote_ip, local_ip);
                }
            }
        };
        let port = take_punch_port(punch_port)?;
        crate::p2plog!("[LAN] Responder: beacon from {}, bestLocal={}", remote_ip, local_ip);

        let nonce_b = lan_nonce();
        let resp_data = lan_encode(key, "R", &LanResponse {
            nonce_a: beacon.nonce_a.clone(),
            nonce_b: nonce_b.clone(),
            transport: tp.to_string(),
            ip: local_ip.clone(),
            port: port as i64,
        });
        for _ in 0..3 {
            mc.broadcast(&resp_data).await;
            mc.send_to(&resp_data, Some(src)).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Phase 2: keep responding + wait for Confirm (10s deadline).
        let mut resp_ticker = tokio::time::interval(Duration::from_millis(300));
        resp_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        resp_ticker.tick().await;
        let confirm_deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(confirm_deadline);

        let confirmed: Option<(LanConfirm, SocketAddr)> = loop {
            tokio::select! {
                _ = scope.sleep_until_deadline(scope.remaining()) => return Err(P2pError::msg("LAN discovery timeout")),
                _ = &mut confirm_deadline => break None,
                _ = resp_ticker.tick() => {
                    mc.broadcast(&resp_data).await;
                    mc.send_to(&resp_data, Some(src)).await;
                }
                pkt = confirm_rx.recv() => {
                    let Some((msg, csrc)) = pkt else { return Err(P2pError::msg("LAN discovery failed")) };
                    let Some(confirm): Option<LanConfirm> = lan_unmarshal(&msg) else { continue };
                    if confirm.nonce_b != nonce_b { continue; }
                    break Some((confirm, csrc));
                }
            }
        };
        let Some((confirm, confirm_src)) = confirmed else {
            crate::p2plog!("[LAN] Responder: confirm timeout, resume beacon listen");
            continue;
        };

        // Phase 3: send ACK.
        let ack_data = lan_encode(key, "A", &LanAck { nonce_a: beacon.nonce_a.clone() });
        for _ in 0..8 {
            mc.broadcast(&ack_data).await;
            mc.send_to(&ack_data, Some(confirm_src)).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        crate::p2plog!("[LAN] Responder: sent ACK → discovery complete");
        return Ok(LanDiscoverResult {
            local_ip,
            local_port: port,
            remote_ip: confirm.ip,
            remote_port: confirm.port as u16,
            transport: confirm.transport,
        });
    }
}

// ============ Easy_P2P_LAN ============

/// easyP2PLAN: multicast discovery → punch (round=0 skips MQTT round sync).
/// The negotiated transport (udp preferred, tcp if both prefer it) selects
/// which punch state machine runs.
pub async fn easy_p2p_lan(
    scope: &Scope,
    session_key: &str,
    transport_pref: &str,
    timeout: Duration,
    passive: bool,
) -> Result<super::p2p::P2PConnInfo> {
    crate::p2plog!("=== LAN Discovery Mode ===");
    let result = lan_discover(scope, session_key, transport_pref, timeout, passive).await?;

    let network = if result.transport == "tcp" { "tcp4" } else { "udp4" };
    let local_addr = netx::join_host_port(&result.local_ip, result.local_port);
    let remote_addr = netx::join_host_port(&result.remote_ip, result.remote_port);
    let shared_key = {
        let mut h = Sha256::new();
        h.update(format!("gonc-lan-shared-{}", session_key).as_bytes());
        h.finalize().into()
    };

    let p2p_info = P2PAddressInfo {
        network: network.to_string(),
        local_lan: local_addr.clone(),
        local_nat: local_addr.clone(),
        local_nat_type: "easy".to_string(),
        remote_lan: remote_addr.clone(),
        remote_nat: remote_addr.clone(),
        remote_nat_type: "easy".to_string(),
        lan_probe_only: false,
        remote_udp4_nat_alternatives: Vec::new(),
    };
    // LAN mode has no MQTT session; round=0 skips round sync entirely.
    let sess_ctx = P2PSessionContext {
        shared_key,
        signal: None,
        local_public_ipv4_count: 1,
    };

    let (conn, is_client) = if network == "tcp4" {
        punch_tcp::auto_p2p_tcp_nat_traversal(scope, network, session_key, &p2p_info, &sess_ctx, 0)
            .await
            .map(|(conn, role)| (P2PConn::Tcp(conn), role))
    } else {
        punch_udp::auto_p2p_udp_nat_traversal(scope, network, session_key, &p2p_info, &sess_ctx, 0)
            .await
            .map(|(conn, role)| (P2PConn::Udp(conn), role))
    }
    .map_err(|e| P2pError::msg(format!("LAN traversal: {}", e)))?;

    Ok(super::p2p::P2PConnInfo {
        peer_address: conn.remote_addr(),
        conn,
        shared_key,
        is_client,
        networks_used: vec![network.to_string()],
        local_nat_type: p2p_info.local_nat_type.clone(),
        remote_nat_type: p2p_info.remote_nat_type.clone(),
        local_lan: p2p_info.local_lan.clone(),
        local_nat: p2p_info.local_nat.clone(),
        remote_lan: p2p_info.remote_lan.clone(),
        remote_nat: p2p_info.remote_nat.clone(),
    })
}
