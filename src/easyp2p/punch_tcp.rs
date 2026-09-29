//! Port of Auto_P2P_TCP_NAT_Traversal (easyp2p/p2p.go:1886-2391): TCP
//! simultaneous-open hole punching with the +100 port convention, an 8-byte
//! binary punch-ACK handshake (derive_key_for_payload ascii=false) and the
//! three-layer connection convergence: per-side ACK selector → C-side closed
//! loop → single commit.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use super::candidates::{self, is_same_lan, P2PAddressInfo};
use super::netx;
use super::p2p::{self, P2PSessionContext};
use super::punch_udp::StopFlag;
use super::{P2pError, Result, Scope};

const MAX_WORKERS: usize = 800;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DIAL_TIMEOUT: Duration = Duration::from_secs(6);
const LAN_PROBE_DIAL_TIMEOUT: Duration = Duration::from_secs(3);
const ERROR_GRACE: Duration = Duration::from_secs(1);
const UNSYNC_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const FIRST_PLAIN_DIAL_WAIT: Duration = Duration::from_millis(1500);
const ACTIVE_DIAL_DELAY: Duration = Duration::from_secs(2);

/// A punched TCP stream produced by a successful traversal.
pub struct TcpPunchedConn {
    pub stream: TcpStream,
    pub remote: SocketAddr,
}

/// incPort: +100 with wraparound into the 1024+ range when it would exceed
/// 65535. Both sides apply the same rule to the same ports, so the results
/// agree.
fn inc_port(port: u16) -> u16 {
    let bumped = port as u32 + 100;
    if bumped > 65535 {
        (1024 + bumped % 65535) as u16
    } else {
        bumped as u16
    }
}

/// tcpPunchAckSelector: one winner per side. A failed confirm write does not
/// consume the slot (Go runs confirm while holding the mutex; the double-check
/// after our await preserves that outcome).
struct AckSelector {
    selected: Mutex<bool>,
}

impl AckSelector {
    fn try_select(&self) -> bool {
        let mut s = self.selected.lock().unwrap();
        if *s {
            return false;
        }
        *s = true;
        true
    }
    fn is_selected(&self) -> bool {
        *self.selected.lock().unwrap()
    }
    fn mark_selected(&self) -> bool {
        let mut s = self.selected.lock().unwrap();
        if *s {
            return false;
        }
        *s = true;
        true
    }
}

/// Shared traversal state (attemptCtx + channels + selector in Go).
struct PunchShared {
    stop: StopFlag,
    selector: AckSelector,
    committed: AtomicBool,
    conn_tx: mpsc::Sender<TcpPunchedConn>,
    err_tx: mpsc::Sender<String>,
    workers: tokio::sync::Semaphore,
    payload: Vec<u8>,
    is_client: bool,
}

impl PunchShared {
    /// reportErr: dial/accept terminal errors wait a cancelable 1s grace so a
    /// successful commit that is still in flight wins the race.
    async fn report_error(&self, message: String) {
        tokio::select! {
            _ = self.stop.wait() => {}
            _ = tokio::time::sleep(ERROR_GRACE) => {
                let _ = self.err_tx.try_send(message);
            }
        }
    }
}

async fn write_full(stream: &mut TcpStream, buf: &[u8], stop: &StopFlag) -> std::io::Result<()> {
    tokio::select! {
        _ = stop.wait() => Err(std::io::Error::new(std::io::ErrorKind::Other, "cancelled")),
        result = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.write_all(buf)) => match result {
            Ok(res) => res,
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake write timeout")),
        },
    }
}

async fn read_full(stream: &mut TcpStream, buf: &mut [u8], stop: &StopFlag) -> std::io::Result<()> {
    tokio::select! {
        _ = stop.wait() => Err(std::io::Error::new(std::io::ErrorKind::Other, "cancelled")),
        result = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(buf)) => match result {
            Ok(res) => res.map(|_| ()),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake read timeout")),
        },
    }
}

/// doHandshake: C writes then reads the ACK; S reads, claims the slot and only
/// then writes the ACK back (a failed write leaves the slot free for the next
/// candidate).
async fn do_handshake(
    sh: &Arc<PunchShared>,
    mut stream: TcpStream,
    tag: &str,
) -> std::result::Result<TcpPunchedConn, String> {
    let remote = stream.peer_addr().map_err(|e| e.to_string())?;
    let payload = sh.payload.clone();
    let mut buf = vec![0u8; payload.len()];
    if sh.is_client {
        write_full(&mut stream, &payload, &sh.stop)
            .await
            .map_err(|e| format!("connection({}) failed to write: {}", tag, e))?;
        read_full(&mut stream, &mut buf, &sh.stop)
            .await
            .map_err(|e| format!("connection({}) failed to read: {}", tag, e))?;
        if buf != payload {
            return Err(format!("connection({}) got invalid punchAckPayload", tag));
        }
        if !sh.selector.try_select() {
            return Err(format!("connection({}) not selected", tag));
        }
    } else {
        read_full(&mut stream, &mut buf, &sh.stop)
            .await
            .map_err(|e| format!("connection({}) failed to read: {}", tag, e))?;
        if buf != payload {
            return Err(format!("connection({}) got invalid punchAckPayload", tag));
        }
        if sh.selector.is_selected() {
            return Err(format!("connection({}) not selected", tag));
        }
        if let Err(e) = write_full(&mut stream, &payload, &sh.stop).await {
            return Err(format!("connection({}) failed to write: {}", tag, e));
        }
        if !sh.selector.mark_selected() {
            return Err(format!("connection({}) not selected", tag));
        }
    }
    Ok(TcpPunchedConn { stream, remote })
}

/// tryCommit: only the first commit sends the connection and cancels all other
/// attempts; late committers drop their connection.
async fn try_commit(sh: &Arc<PunchShared>, conn: TcpPunchedConn, _tag: &str) -> bool {
    let mut committed = false;
    if sh
        .committed
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        if !sh.stop.is_stopped() && sh.conn_tx.try_send(conn).is_ok() {
            sh.stop.stop();
            committed = true;
        }
        // else: traversal already finished (main select gone) — conn dropped.
    }
    sh.stop.wait().await;
    committed
}

/// tryConnect: one dial attempt (bounded by the worker semaphore), then the
/// punch-ACK handshake, then commit.
async fn try_connect(
    sh: Arc<PunchShared>,
    target: SocketAddr,
    local: Option<SocketAddr>,
    reuse: bool,
    timeout: Duration,
    tag: &'static str,
) -> bool {
    let permit = tokio::select! {
        _ = sh.stop.wait() => return false,
        permit = sh.workers.acquire() => permit,
    };
    let Ok(_permit) = permit else { return false };
    let stream = tokio::select! {
        _ = sh.stop.wait() => return false,
        dial = tokio::time::timeout(timeout, netx::connect_tcp_bind(target, local, reuse)) => match dial {
            Ok(Ok(stream)) => stream,
            _ => return false,
        },
    };
    match do_handshake(&sh, stream, tag).await {
        Ok(conn) => try_commit(&sh, conn, tag).await,
        Err(_err) => false, // handshake closes the connection (dropped here)
    }
}

struct DialPlan {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    remote_ip: IpAddr,
    lan_target: Option<SocketAddr>,
    orig_local_port: i32,
    orig_remote_port: i32,
    in_same_lan: bool,
    unsync_same_lan: bool,
    random_dst_port: bool,
    random_src_port: bool,
    lan_probe_enabled: bool,
    lan_probe_only: bool,
    is_client: bool,
    local_easy: bool,
    remote_easy: bool,
}

/// doPunching: role-delayed concurrent dialing.
async fn run_dial(sh: Arc<PunchShared>, plan: DialPlan, round_scope: Scope) {
    let active_dial_delay = if plan.is_client || plan.in_same_lan || plan.lan_probe_only {
        Duration::ZERO
    } else {
        ACTIVE_DIAL_DELAY
    };
    if !active_dial_delay.is_zero() {
        tokio::select! {
            _ = sh.stop.wait() => return,
            _ = round_scope.sleep_until_deadline(active_dial_delay) => {}
        }
    }
    if sh.stop.is_stopped() || round_scope.expired() {
        return;
    }

    // LAN direct probe (parallel extra attempt; the only attempt in
    // LANProbeOnly mode).
    if plan.lan_probe_enabled {
        if let Some(lan_target) = plan.lan_target {
            crate::p2plog!("  ↑ LAN probe: trying direct connect to peer LAN address {} ...", lan_target);
            let probe = tokio::spawn(try_connect(
                sh.clone(),
                lan_target,
                Some(plan.local_addr),
                true,
                LAN_PROBE_DIAL_TIMEOUT,
                "lan-probe",
            ));
            if plan.lan_probe_only {
                let _ = probe.await;
                if !sh.stop.is_stopped() && !round_scope.expired() {
                    sh.report_error("LAN probe failed, no other punching method available".to_string())
                        .await;
                }
                return;
            }
        } else if plan.lan_probe_only {
            sh.report_error("LAN probe failed, no other punching method available".to_string())
                .await;
            return;
        }
    }

    // Same subnet or easy×easy: try a direct connection first (synchronous,
    // like Go — the escalation below depends on its outcome).
    let mut tried_direct_dial = false;
    let mut random_dst_port = plan.random_dst_port;
    let mut random_src_port = plan.random_src_port;
    if plan.in_same_lan || (plan.local_easy && plan.remote_easy) {
        crate::p2plog!("  ↑ Trying direct dial to peer...");
        loop {
            if sh.stop.is_stopped() || round_scope.expired() {
                return;
            }
            if try_connect(
                sh.clone(),
                plan.remote_addr,
                Some(plan.local_addr),
                true,
                DIAL_TIMEOUT,
                "dial",
            )
            .await
            {
                return;
            }
            tried_direct_dial = true;
            if !plan.unsync_same_lan {
                break;
            }
            tokio::select! {
                _ = sh.stop.wait() => return,
                _ = round_scope.sleep_until_deadline(UNSYNC_RETRY_INTERVAL) => {}
            }
        }
        if !plan.in_same_lan {
            if plan.is_client {
                // easy-easy failed: the peer's hole may not be open yet, don't
                // poke it directly — spray random destination ports instead.
                tokio::select! {
                    _ = sh.stop.wait() => return,
                    _ = round_scope.sleep_until_deadline(Duration::from_secs(3)) => {}
                }
                random_dst_port = true;
            } else {
                random_src_port = true;
            }
        }
    }

    // Birthday attack: ≤3 rounds of 600-port sprays, each round fully drained.
    for _round in 0..3 {
        if !(random_dst_port || random_src_port) {
            break;
        }
        if sh.stop.is_stopped() || round_scope.expired() {
            return;
        }
        let random_port_count = super::punching_random_port_count();
        let mut in_flight: Vec<tokio::task::JoinHandle<bool>> = Vec::new();
        if random_dst_port {
            let ports = p2p::generate_random_ports(random_port_count);
            crate::p2plog!("  ↑ Trying {} Random Destination Ports concurrently...", ports.len());
            for port in ports {
                if port as i32 == plan.orig_remote_port {
                    // avoid the port the peer used to talk to the STUN server
                    continue;
                }
                if sh.stop.is_stopped() {
                    return;
                }
                let target = SocketAddr::new(plan.remote_ip, port);
                in_flight.push(tokio::spawn(try_connect(
                    sh.clone(),
                    target,
                    Some(plan.local_addr),
                    true,
                    DIAL_TIMEOUT,
                    "RDP",
                )));
            }
        }
        if random_src_port {
            let ports = p2p::generate_random_ports(random_port_count);
            crate::p2plog!("  ↑ Trying {} Random Source Ports concurrently...", random_port_count);
            for port in ports {
                if port as i32 == plan.orig_local_port {
                    // avoid our own STUN port
                    continue;
                }
                if sh.stop.is_stopped() {
                    return;
                }
                let new_local = SocketAddr::new(plan.local_addr.ip(), port);
                if !tried_direct_dial {
                    // Wait briefly for the first plain dial — the peer may have
                    // no NAT/firewall at all, in which case we are done.
                    tried_direct_dial = true;
                    let first = tokio::spawn(try_connect(
                        sh.clone(),
                        plan.remote_addr,
                        Some(new_local),
                        false,
                        DIAL_TIMEOUT,
                        "dial",
                    ));
                    tokio::select! {
                        _ = first => {}
                        _ = sh.stop.wait() => return,
                        _ = tokio::time::sleep(FIRST_PLAIN_DIAL_WAIT) => {}
                    }
                } else {
                    in_flight.push(tokio::spawn(try_connect(
                        sh.clone(),
                        plan.remote_addr,
                        Some(new_local),
                        false,
                        DIAL_TIMEOUT,
                        "RSP",
                    )));
                }
            }
        }
        // wg.Wait(): drain the round before regenerating ports.
        for handle in in_flight {
            let _ = handle.await;
        }
    }
    if !sh.stop.is_stopped() && !round_scope.expired() {
        sh.report_error("all connection attempts failed".to_string()).await;
    }
}

/// doAccept: serial accept loop; source-validated connections run the punch-ACK
/// handshake inline (Go behavior), then commit.
async fn run_accept(
    sh: Arc<PunchShared>,
    listener: TcpListener,
    round_scope: Scope,
    remote_ip: IpAddr,
    remote_lan_ip: Option<IpAddr>,
    local_ip: IpAddr,
    same_nat: bool,
    similar_lan: bool,
    lan_probe_enabled: bool,
    in_same_lan: bool,
) {
    loop {
        let accepted = tokio::select! {
            _ = sh.stop.wait() => return,
            _ = round_scope.sleep_until_deadline(round_scope.remaining()) => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                if sh.stop.is_stopped() {
                    return;
                }
                sh.report_error(err.to_string()).await;
                return;
            }
        };
        let peer_ip = peer.ip();
        let allowed = peer_ip == remote_ip
            || (same_nat && similar_lan && is_same_lan(&peer_ip.to_string(), &remote_ip.to_string()))
            || (same_nat && remote_lan_ip == Some(peer_ip))
            || (lan_probe_enabled
                && (remote_lan_ip == Some(peer_ip) || is_same_lan(&peer_ip.to_string(), &local_ip.to_string())));
        if !allowed {
            drop(stream);
            if in_same_lan {
                continue;
            }
            sh.report_error(format!("unexpected peer connection from {}", peer_ip)).await;
            return;
        }
        match do_handshake(&sh, stream, "accept").await {
            Ok(conn) => {
                try_commit(&sh, conn, "accept").await;
                return;
            }
            Err(_) => {
                // handshake failed; connection already dropped
                if in_same_lan {
                    continue;
                }
                sh.report_error("accept handshake failed".to_string()).await;
                return;
            }
        }
    }
}

pub async fn auto_p2p_tcp_nat_traversal(
    scope: &Scope,
    network: &str,
    session_uid: &str,
    p2p_info: &P2PAddressInfo,
    sess_ctx: &P2PSessionContext,
    round: i32,
) -> Result<(TcpPunchedConn, bool)> {
    let _ = network;
    crate::p2plog!("=== Trying P2P Connection ===");
    if scope.expired() {
        return Err(P2pError::msg("operation cancelled"));
    }

    let is_client = candidates::select_role(p2p_info, "");
    let (same_nat, similar_lan) = candidates::compare_p2p_addresses(p2p_info);
    let mut info = p2p_info.clone();
    let mut remote_addr_s = info.remote_nat.clone();
    let mut in_same_lan = false;
    if same_nat && similar_lan {
        remote_addr_s = info.remote_lan.clone();
        in_same_lan = true;
    }

    let lan_probe_enabled =
        candidates::should_try_lan_probe(in_same_lan, round, p2p_info) || info.lan_probe_only;
    let unsync_same_lan = round == 0 && in_same_lan;

    let mut random_dst_port = false;
    let mut random_src_port = false;
    if !in_same_lan {
        let local_easy = info.local_nat_type == "easy";
        let remote_easy = info.remote_nat_type == "easy";
        if local_easy && !remote_easy {
            random_dst_port = true;
        } else if !local_easy && remote_easy {
            random_src_port = true;
        } else if local_easy && remote_easy {
            // plain probing
        } else if is_client {
            random_dst_port = true;
        } else {
            random_src_port = true;
        }
    }

    // Resolve the four addresses before the +100 shift and remember the ports
    // the random sprays must avoid (they carried STUN traffic).
    let local_addr_orig: SocketAddr = netx::parse_addr(&info.local_lan)
        .ok_or_else(|| P2pError::msg(format!("failed to resolve local address: {}", info.local_lan)))?;
    let orig_local_port = local_addr_orig.port() as i32;
    let local_nat_addr_orig: SocketAddr = netx::parse_addr(&info.local_nat)
        .ok_or_else(|| P2pError::msg(format!("failed to resolve local address: {}", info.local_nat)))?;
    let remote_lan_addr_orig: SocketAddr = netx::parse_addr(&info.remote_lan)
        .ok_or_else(|| P2pError::msg(format!("failed to resolve remote address: {}", info.remote_lan)))?;
    let (remote_ip_s, remote_port_orig) = netx::split_host_port(&remote_addr_s)
        .ok_or_else(|| P2pError::msg(format!("invalid remote address: {}", remote_addr_s)))?;
    let remote_ip: IpAddr = remote_ip_s
        .parse()
        .map_err(|_| P2pError::msg(format!("invalid remote address: {}", remote_addr_s)))?;
    let orig_remote_port = remote_port_orig as i32;

    let mut local_addr = local_addr_orig;
    if !in_same_lan {
        if info.local_nat_type != "easy" && info.remote_nat_type != "easy" && !lan_probe_enabled {
            return Err(P2pError::msg(
                "NAT type need at least one easy NAT for TCP hole punching",
            ));
        }
        // Shift all four ports by +100: the original ports talked to the STUN
        // servers, and their mappings may be torn down by STUN FINs/RSTs.
        local_addr.set_port(inc_port(local_addr.port()));
        info.local_lan = local_addr.to_string();
        let mut local_nat = local_nat_addr_orig;
        local_nat.set_port(inc_port(local_nat.port()));
        info.local_nat = local_nat.to_string();
        let mut remote_lan = remote_lan_addr_orig;
        remote_lan.set_port(inc_port(remote_lan.port()));
        info.remote_lan = remote_lan.to_string();
        remote_addr_s = netx::join_host_port(&remote_ip_s, inc_port(remote_port_orig));
        info.remote_nat = remote_addr_s.clone();
    }
    let remote_addr: SocketAddr = netx::parse_addr(&remote_addr_s)
        .ok_or_else(|| P2pError::msg(format!("invalid remote address: {}", remote_addr_s)))?;
    let remote_lan_ip = candidates::extract_ip(&info.remote_lan).parse::<IpAddr>().ok();

    let timeout_max = if info.lan_probe_only {
        Duration::from_secs(5)
    } else if unsync_same_lan {
        Duration::from_secs(8)
    } else {
        Duration::from_secs(25)
    };

    // Listener is bound before the round sync (Go order).
    let std_listener = netx::listen_tcp(local_addr, true)
        .map_err(|e| P2pError::msg(format!("failed to listen: {}", e)))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| P2pError::msg(e.to_string()))?;
    let listener = TcpListener::from_std(std_listener)
        .map_err(|e| P2pError::msg(format!("failed to listen: {}", e)))?;

    if round > 0 {
        let signal = sess_ctx
            .signal
            .as_ref()
            .ok_or_else(|| P2pError::msg("missing MQTT signal session"))?;
        p2p::mqtt_p2p_round_sync(scope, session_uid, signal, is_client, round, Duration::from_secs(25))
            .await
            .map_err(|e| P2pError::msg(format!("failed to sync P2P round: {}", e)).wrap_unretryable())?;
    }

    super::punch_udp::print_p2p_info(&info);
    if lan_probe_enabled {
        if info.lan_probe_only {
            crate::p2plog!("  - {:<14}: enabled (LAN probe only mode)", "LAN Probe");
        } else {
            crate::p2plog!("  - {:<14}: enabled", "LAN Probe");
        }
    }
    crate::p2plog!("  - {:<14}: {} ({}s)", "Timeout", "TCP traversal", timeout_max.as_secs());
    if is_client {
        crate::p2plog!("  - {:<14}: connect start immediately", "Active Mode");
    } else {
        crate::p2plog!("  - {:<14}: connect start after 2s", "Passive Mode");
    }

    let round_scope = scope.child(timeout_max);
    let (conn_tx, mut conn_rx) = mpsc::channel::<TcpPunchedConn>(1);
    let (err_tx, mut err_rx) = mpsc::channel::<String>(1);
    let sh = Arc::new(PunchShared {
        stop: StopFlag::new(),
        selector: AckSelector {
            selected: Mutex::new(false),
        },
        committed: AtomicBool::new(false),
        conn_tx,
        err_tx,
        workers: tokio::sync::Semaphore::new(MAX_WORKERS),
        payload: super::crypto::derive_key_for_payload(session_uid, false),
        is_client,
    });

    let plan = DialPlan {
        local_addr,
        remote_addr,
        remote_ip,
        lan_target: netx::parse_addr(&info.remote_lan),
        orig_local_port,
        orig_remote_port,
        in_same_lan,
        unsync_same_lan,
        random_dst_port,
        random_src_port,
        lan_probe_enabled,
        lan_probe_only: info.lan_probe_only,
        is_client,
        local_easy: info.local_nat_type == "easy",
        remote_easy: info.remote_nat_type == "easy",
    };

    let accept_task = tokio::spawn(run_accept(
        sh.clone(),
        listener,
        round_scope.clone(),
        remote_addr.ip(),
        remote_lan_ip,
        local_addr.ip(),
        same_nat,
        similar_lan,
        lan_probe_enabled,
        in_same_lan,
    ));
    let dial_task = tokio::spawn(run_dial(sh.clone(), plan, round_scope.clone()));

    enum Outcome {
        Conn(TcpPunchedConn),
        Err(String),
        Timeout,
    }
    let outcome = tokio::select! {
        conn = conn_rx.recv() => match conn {
            Some(conn) => Outcome::Conn(conn),
            None => Outcome::Err("socket closed".to_string()),
        },
        err = err_rx.recv() => match err {
            Some(text) => Outcome::Err(text),
            None => Outcome::Err("socket closed".to_string()),
        },
        _ = round_scope.sleep_until_deadline(round_scope.remaining()) => Outcome::Timeout,
    };

    sh.stop.stop();
    for (name, task) in [("accept", accept_task), ("dial", dial_task)] {
        match tokio::time::timeout(Duration::from_millis(500), task).await {
            Ok(Ok(())) => {}
            Ok(Err(join_err)) => crate::p2plog!("punch tcp {} task failed: {}", name, join_err),
            Err(_) => crate::p2plog!("punch tcp {} task did not finish in grace period", name),
        }
    }

    match outcome {
        Outcome::Conn(conn) => {
            if scope.expired() {
                Err(P2pError::msg("operation cancelled"))
            } else {
                crate::p2plog!("P2P(TCP) connection established!");
                Ok((conn, is_client))
            }
        }
        Outcome::Err(err) => {
            if scope.expired() {
                Err(P2pError::msg("operation cancelled"))
            } else {
                Err(P2pError::msg(format!("P2P TCP hole punching failed: {}", err)))
            }
        }
        Outcome::Timeout => {
            if scope.expired() {
                Err(P2pError::msg("operation cancelled"))
            } else {
                Err(P2pError::msg("P2P TCP hole punching failed: Timeout"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::inc_port;

    #[test]
    fn inc_port_basics() {
        assert_eq!(inc_port(1000), 1100);
        assert_eq!(inc_port(65435), 65535);
        // 65436+100 = 65536 > 65535 → 1024 + 65536 % 65535 = 1025
        assert_eq!(inc_port(65436), 1025);
        // 65500+100 = 65600 → 1024 + 65600 % 65535 = 1089
        assert_eq!(inc_port(65500), 1089);
    }
}
