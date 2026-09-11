//! Port of Auto_P2P_UDP_NAT_Traversal (easyp2p/p2p.go:1186-1801): role-based
//! UDP hole punching with low-TTL probes, 600-port birthday spraying and a
//! payload triple-handshake.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::candidates::{self, P2PAddressInfo};
use super::netx;
use super::p2p::{self, P2PSessionContext};
use super::{P2pError, Result, Scope, DEFAULT_PUNCHING_SHORT_TTL, PUNCHING_RANDOM_PORT_COUNT, PUNCHING_SHORT_TTL};

const RPP_TIMEOUT_SECS: u64 = 7;

/// A connected UDP socket produced by a successful punch.
#[derive(Clone)]
#[allow(dead_code)]
pub struct PunchedConn {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    remote: SocketAddr,
}

impl PunchedConn {
    #[allow(dead_code)]
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.send(buf).await
    }
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.socket.recv(buf).await
    }
    #[allow(dead_code)]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }
    #[allow(dead_code)]
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }
}

struct PunchCtx {
    /// Shared main socket; swapped by the EACCES rebuild path (best effort —
    /// the macOS firewall workaround degrades to force-rebind if the old
    /// socket is still referenced elsewhere).
    socket: RwLock<Arc<UdpSocket>>,
    stop: StopFlag,
    picked: AtomicBool,
    last_remote: Mutex<Option<SocketAddr>>,
    force_rebind: AtomicBool,
    ttl: AtomicU32,
}

impl PunchCtx {
    fn socket(&self) -> Arc<UdpSocket> {
        self.socket.read().unwrap().clone()
    }
}

/// Cancellation latch equivalent to ctxStopPunching.
pub(crate) struct StopFlag {
    notified: tokio::sync::Notify,
    stopped: AtomicBool,
}

impl StopFlag {
    pub(crate) fn new() -> Self {
        StopFlag {
            notified: tokio::sync::Notify::new(),
            stopped: AtomicBool::new(false),
        }
    }
    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.notified.notify_waiters();
        self.notified.notify_one();
    }
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
    pub(crate) async fn wait(&self) {
        if self.is_stopped() {
            return;
        }
        self.notified.notified().await
    }
}

pub async fn auto_p2p_udp_nat_traversal(
    scope: &Scope,
    network: &str,
    session_uid: &str,
    p2p_info: &P2PAddressInfo,
    sess_ctx: &P2PSessionContext,
    round: i32,
) -> Result<(PunchedConn, bool)> {
    let _ = network;
    let punch_payload = super::crypto::derive_key_for_payload(session_uid, true);

    crate::p2plog!("=== Trying P2P Connection ===");
    let is_client = candidates::select_role(p2p_info, "");

    let (same_nat, similar_lan) = candidates::compare_p2p_addresses(p2p_info);
    let mut remote_addr = p2p_info.remote_nat.clone();
    let route_reason;
    let mut in_same_lan = false;
    if same_nat && similar_lan {
        remote_addr = p2p_info.remote_lan.clone();
        route_reason = "same LAN";
        in_same_lan = true;
    } else {
        route_reason = "different network";
    }
    let udp_lan_probe_addr = if !in_same_lan && candidates::should_try_lan_probe(in_same_lan, round, p2p_info) {
        p2p_info.remote_lan.clone()
    } else {
        String::new()
    };

    let mut ttl: u32 = 64;
    let mut random_src_port = false;
    let mut random_dst_port = false;
    if !in_same_lan {
        let local_easy = p2p_info.local_nat_type == "easy";
        let remote_easy = p2p_info.remote_nat_type == "easy";
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
    if is_client {
        ttl = PUNCHING_SHORT_TTL as u32;
        if ttl == DEFAULT_PUNCHING_SHORT_TTL as u32
            && p2p_info.network.ends_with('4')
            && sess_ctx.local_public_ipv4_count > 1
        {
            ttl = 10;
        }
    }
    let count: u64 = if !in_same_lan
        && (p2p_info.local_nat_type != "easy" || p2p_info.remote_nat_type != "easy")
    {
        4 + RPP_TIMEOUT_SECS * 2
    } else {
        8
    };

    let local_addr: SocketAddr = netx::parse_addr(&p2p_info.local_lan)
        .ok_or_else(|| P2pError::msg(format!("failed to resolve local address: {}", p2p_info.local_lan)))?;
    let remote_udp_addr: SocketAddr = netx::parse_addr(&remote_addr)
        .ok_or_else(|| P2pError::msg(format!("failed to resolve remote address: {}", remote_addr)))?;

    // net.ListenUDP: plain bind, no socket options.
    let std_socket = netx::listen_udp(local_addr, false)
        .map_err(|e| P2pError::msg(format!("error binding UDP address: {}", e)))?;
    std_socket.set_nonblocking(true).map_err(|e| P2pError::msg(e.to_string()))?;
    let socket = Arc::new(
        UdpSocket::from_std(std_socket).map_err(|e| P2pError::msg(format!("error binding UDP address: {}", e)))?,
    );
    let _ = netx::set_udp_ttl(&socket, ttl);

    let ctx = Arc::new(PunchCtx {
        socket: RwLock::new(socket),
        stop: StopFlag::new(),
        picked: AtomicBool::new(false),
        last_remote: Mutex::new(None),
        force_rebind: AtomicBool::new(false),
        ttl: AtomicU32::new(ttl),
    });

    if round > 0 {
        let signal = sess_ctx
            .signal
            .as_ref()
            .ok_or_else(|| P2pError::msg("missing MQTT signal session"))?;
        p2p::mqtt_p2p_round_sync(scope, session_uid, signal, is_client, round, Duration::from_secs(25))
            .await
            .map_err(|e| P2pError::msg(format!("failed to sync P2P round: {}", e)).wrap_unretryable())?;
    }

    print_p2p_info(p2p_info);
    crate::p2plog!("  - {:<14}: {} (reason: {})", "Best Route", remote_addr, route_reason);
    if is_client {
        crate::p2plog!("  - {:<14}: sending PING every 1s (start immediately)", "Client Mode");
    } else {
        crate::p2plog!("  - {:<14}: sending PING every 1s (start after 2s)", "Server Mode");
    }
    if !udp_lan_probe_addr.is_empty() {
        crate::p2plog!("  - {:<14}: enabled (target: {})", "LAN Probe", udp_lan_probe_addr);
    }
    crate::p2plog!("  - {:<14}: {}s", "Timeout", count);

    let round_scope = scope.child(Duration::from_secs(count));

    let (recv_tx, mut recv_rx) = mpsc::channel::<bool>(1);
    let _ = &recv_tx; // keep alive for the whole traversal
    let (err_tx, mut err_rx) = mpsc::channel::<String>(8);
    let (hole_tx, mut hole_rx) = mpsc::channel::<HoleClaim>(1);

    // ---- reader: any source until the punch payload arrives ----
    let reader = {
        let ctx = ctx.clone();
        let payload = punch_payload.clone();
        let round_scope = round_scope.clone();
        let err_tx = err_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            loop {
                let socket = ctx.socket();
                let received = tokio::select! {
                    _ = ctx.stop.wait() => {
                        crate::p2plog!("reader exit: stop fired (stopped={})", ctx.stop.is_stopped());
                        return;
                    }
                    r = socket.recv_from(&mut buf) => r,
                };
                match received {
                    Ok((n, remote)) => {
                        crate::p2plog!("reader got {} bytes from {}", n, remote);
                        if buf[..n] == payload[..] {
                            ctx.stop.stop();
                            if !ctx.picked.swap(true, Ordering::SeqCst) {
                                *ctx.last_remote.lock().unwrap() = Some(remote);
                                let _ = netx::set_udp_ttl(&socket, 64);
                                let _ = socket.send_to(&payload, remote).await;
                                if round_scope.remaining() > Duration::from_millis(250) {
                                    tokio::time::sleep(Duration::from_millis(250)).await;
                                    let _ = socket.send_to(&payload, remote).await;
                                }
                                let _ = recv_tx.try_send(true);
                            }
                            return;
                        }
                    }
                    Err(err) => {
                        crate::p2plog!("reader recv_from error (kind={:?}): {}", err.kind(), err);
                        let _ = err_tx.try_send(err.to_string());
                        return;
                    }
                }
            }
        })
    };

    // ---- writer: role-based probing ----
    let writer = {
        let ctx = ctx.clone();
        let payload = punch_payload.clone();
        let round_scope = round_scope.clone();
        let info = p2p_info.clone();
        let udp_lan_probe_addr = udp_lan_probe_addr.clone();
        let remote_addr = remote_addr.clone();
        let err_tx = err_tx.clone();
        tokio::spawn(async move {
            // server role: first ping is delayed 2s
            if !is_client {
                tokio::select! {
                    _ = ctx.stop.wait() => return,
                    _ = round_scope.sleep_until_deadline(Duration::from_secs(2)) => {}
                }
            }
            for i in 0..count {
                if i > 0 {
                    tokio::select! {
                        _ = ctx.stop.wait() => return,
                        _ = round_scope.sleep_until_deadline(Duration::from_secs(1)) => {}
                    }
                }
                if ctx.stop.is_stopped() || round_scope.expired() {
                    return;
                }
                if i < 3 {
                    if !send_ping(&ctx, &info, &payload, remote_udp_addr, &udp_lan_probe_addr, i as usize, &err_tx).await {
                        return;
                    }
                } else {
                    if is_client {
                        let ttl = ctx.ttl.load(Ordering::SeqCst);
                        if ttl < 64 {
                            ctx.ttl.store(ttl + 1, Ordering::SeqCst);
                        }
                    }
                    if random_src_port {
                        if send_rsp_ping(
                            ctx.clone(),
                            &round_scope,
                            &payload,
                            local_addr,
                            remote_udp_addr,
                            &info,
                            Duration::from_secs(RPP_TIMEOUT_SECS),
                            &hole_tx,
                        )
                        .await
                        {
                            return;
                        }
                    } else if random_dst_port {
                        send_rdp_ping(&ctx, &payload, remote_udp_addr, &remote_addr, &info).await;
                        // give the batch time to draw replies
                        tokio::select! {
                            _ = ctx.stop.wait() => return,
                            _ = round_scope.sleep_until_deadline(Duration::from_millis(RPP_TIMEOUT_SECS * 500)) => {}
                        }
                    } else if !send_ping(&ctx, &info, &payload, remote_udp_addr, &udp_lan_probe_addr, i as usize, &err_tx).await {
                        return;
                    }
                }
            }
        })
    };

    // ---- await the outcome ----
    enum Outcome {
        Hole(HoleClaim),
        Recv,
        Err(String),
        Timeout,
    }
    // A channel end (e.g. the writer dropping hole_tx on exit) is not itself a
    // failure — the reader's match message may still be in flight. Closed
    // channels are disabled and the wait continues.
    let mut hole_open = true;
    let mut recv_open = true;
    let mut err_open = true;
    let outcome = loop {
        if !hole_open && !recv_open && !err_open {
            break Outcome::Err("socket closed".to_string());
        }
        tokio::select! {
            holed = hole_rx.recv(), if hole_open => match holed {
                Some(claim) => break Outcome::Hole(claim),
                None => hole_open = false,
            },
            received = recv_rx.recv(), if recv_open => match received {
                Some(_) => break Outcome::Recv,
                None => recv_open = false,
            },
            err = err_rx.recv(), if err_open => match err {
                Some(text) => break Outcome::Err(text),
                None => err_open = false,
            },
            _ = round_scope.sleep_until_deadline(round_scope.remaining()) => break Outcome::Timeout,
        }
    };

    ctx.stop.stop();
    // Bounded grace period so helper tasks finish their post-pick writes and
    // stop touching the sockets before we connect them.
    match tokio::time::timeout(Duration::from_millis(500), reader).await {
        Ok(Ok(())) => {}
        Ok(Err(join_err)) => crate::p2plog!("punch reader task failed: {}", join_err),
        Err(_) => crate::p2plog!("punch reader task did not finish in grace period"),
    }
    match tokio::time::timeout(Duration::from_millis(500), writer).await {
        Ok(Ok(())) => {}
        Ok(Err(join_err)) => crate::p2plog!("punch writer task failed: {}", join_err),
        Err(_) => crate::p2plog!("punch writer task did not finish in grace period"),
    }

    let final_result: Result<PunchedConn> = match outcome {
        Outcome::Hole(claim) => {
            if scope.expired() {
                Err(P2pError::msg("operation cancelled"))
            } else {
                crate::p2plog!("P2P(UDP) connection established (RSP)!");
                finalize_conn(claim.socket, claim.local, claim.remote, false, &punch_payload)
                    .await
                    .map_err(|e| P2pError::msg(format!("error binding UDP address: {}", e)))
            }
        }
        Outcome::Recv => {
            if scope.expired() {
                Err(P2pError::msg("operation cancelled"))
            } else {
                crate::p2plog!("P2P(UDP) connection established!");
                let raddr = ctx.last_remote.lock().unwrap().unwrap_or(remote_udp_addr);
                let force_rebind = ctx.force_rebind.load(Ordering::SeqCst);
                let socket = ctx.socket();
                let laddr = socket.local_addr().unwrap_or(local_addr);
                finalize_conn(socket, laddr, raddr, force_rebind, &punch_payload)
                    .await
                    .map_err(|e| P2pError::msg(format!("error binding UDP address: {}", e)))
            }
        }
        Outcome::Err(err) => Err(P2pError::msg(format!("P2P UDP hole punching failed: {}", err))),
        Outcome::Timeout => {
            if scope.expired() {
                Err(P2pError::msg("operation cancelled"))
            } else {
                Err(P2pError::msg(format!("P2P UDP hole punching failed: timeout ({}s)", count)))
            }
        }
    };

    match final_result {
        Ok(conn) => Ok((conn, is_client)),
        Err(err) => Err(err),
    }
}

struct HoleClaim {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    remote: SocketAddr,
}

/// Reuse the surviving socket: connect it to the peer (or rebind wildcard for
/// the forceRebind path) and fire the payload once to open the local firewall.
async fn finalize_conn(
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    remote: SocketAddr,
    force_rebind: bool,
    punch_payload: &[u8],
) -> std::io::Result<PunchedConn> {
    let connected = if force_rebind {
        Arc::new(netx::connected_udp_wildcard(local, remote).await?)
    } else {
        socket.connect(remote).await?;
        socket
    };
    let _ = connected.send(punch_payload).await;
    Ok(PunchedConn {
        socket: connected,
        local,
        remote,
    })
}

pub(crate) fn print_p2p_info(info: &P2PAddressInfo) {
    if info.local_lan == info.local_nat {
        crate::p2plog!("  - {:<14}: {} (NAT-{})", "Local Address", info.local_lan, info.local_nat_type);
    } else {
        crate::p2plog!(
            "  - {:<14}: {} (LAN) / {} (NAT-{})",
            "Local Address", info.local_lan, info.local_nat, info.local_nat_type
        );
    }
    if info.remote_lan == info.remote_nat {
        crate::p2plog!("  - {:<14}: {} (NAT-{})", "Remote Address", info.remote_lan, info.remote_nat_type);
    } else {
        crate::p2plog!(
            "  - {:<14}: {} (LAN) / {} (NAT-{})",
            "Remote Address", info.remote_lan, info.remote_nat, info.remote_nat_type
        );
    }
}

/// sendPing: main probe + extra NAT exits + LAN probe address.
async fn send_ping(
    ctx: &PunchCtx,
    info: &P2PAddressInfo,
    payload: &[u8],
    remote_udp_addr: SocketAddr,
    udp_lan_probe_addr: &str,
    iteration: usize,
    err_tx: &mpsc::Sender<String>,
) -> bool {
    let socket = ctx.socket();
    let ttl = ctx.ttl.load(Ordering::SeqCst);
    let result = socket.send_to(payload, remote_udp_addr).await;
    let socket = match result {
        Ok(_) => socket,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                crate::p2plog!("UDP sendto permission denied; try rebinding...");
                let local = socket.local_addr().ok();
                // Swap the shared socket so the port frees up for the rebind.
                let rebuilt = local.and_then(|l| netx::tokio_udp(l, false).ok());
                match rebuilt {
                    Some(rebuilt) => {
                        let rebuilt = Arc::new(rebuilt);
                        *ctx.socket.write().unwrap() = rebuilt.clone();
                        if rebuilt.send_to(payload, remote_udp_addr).await.is_ok() {
                            rebuilt
                        } else {
                            let _ = err_tx.try_send(err.to_string());
                            return false;
                        }
                    }
                    None => {
                        // Cannot rebuild: force the wildcard-rebind path.
                        ctx.stop.stop();
                        if !ctx.picked.swap(true, Ordering::SeqCst) {
                            ctx.force_rebind.store(true, Ordering::SeqCst);
                            *ctx.last_remote.lock().unwrap() = Some(remote_udp_addr);
                        }
                        return true;
                    }
                }
            } else {
                crate::p2plog!("send_ping error (kind={:?}): {}", err.kind(), err);
                let _ = err_tx.try_send(err.to_string());
                return false;
            }
        }
    };

    for alt in &info.remote_udp4_nat_alternatives {
        if let Some(addr) = netx::parse_addr(alt) {
            let _ = socket.send_to(payload, addr).await;
        }
    }
    if !udp_lan_probe_addr.is_empty() {
        if let Some(addr) = netx::parse_addr(udp_lan_probe_addr) {
            let _ = socket.send_to(payload, addr).await;
        }
    }
    let mut addr_count = 1 + info.remote_udp4_nat_alternatives.len();
    if !udp_lan_probe_addr.is_empty() {
        addr_count += 1;
    }
    crate::p2plog!("  ↑ Sent PING(TTL={}) to {} IP ({})", ttl, addr_count, iteration + 1);
    true
}

/// sendRDPPing: spray 600 random destination ports across every known peer IP.
async fn send_rdp_ping(
    ctx: &PunchCtx,
    payload: &[u8],
    remote_udp_addr: SocketAddr,
    remote_addr_str: &str,
    info: &P2PAddressInfo,
) {
    let remote_nat_ip = netx::split_host_port(remote_addr_str)
        .map(|(h, _)| h)
        .unwrap_or_default();
    let mut remote_nat_ips = vec![remote_nat_ip];
    for alt in &info.remote_udp4_nat_alternatives {
        if let Some((ip, _)) = netx::split_host_port(alt) {
            remote_nat_ips.push(ip);
        }
    }
    if ctx.stop.is_stopped() {
        return;
    }
    let socket = ctx.socket();
    let ttl = ctx.ttl.load(Ordering::SeqCst);
    let _ = netx::set_udp_ttl(&socket, ttl);
    let ports = p2p::generate_random_ports(PUNCHING_RANDOM_PORT_COUNT);
    crate::p2plog!(
        "  ↑ Sending Random Dst Ports hole-punching packets to {} IP. TTL={}; total={}",
        remote_nat_ips.len(),
        ttl,
        PUNCHING_RANDOM_PORT_COUNT * remote_nat_ips.len()
    );
    for ip in &remote_nat_ips {
        let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() else { continue };
        for port in &ports {
            let addr = SocketAddr::new(ip_addr, *port);
            let _ = socket.send_to(payload, addr).await;
        }
    }
    let _ = remote_udp_addr;
}

/// sendRSPPing: bind ~600 random source ports, spray, first matching reply
/// claims the hole.
async fn send_rsp_ping(
    ctx: Arc<PunchCtx>,
    round_scope: &Scope,
    payload: &[u8],
    local_addr: SocketAddr,
    remote_udp_addr: SocketAddr,
    info: &P2PAddressInfo,
    timeout: Duration,
    hole_tx: &mpsc::Sender<HoleClaim>,
) -> bool {
    let rsp_scope = round_scope.child(timeout);
    let mut all_remote_addrs = vec![remote_udp_addr];
    for alt in &info.remote_udp4_nat_alternatives {
        if let Some(addr) = netx::parse_addr(alt) {
            all_remote_addrs.push(addr);
        }
    }
    crate::p2plog!(
        "  ↑ Sending Random Src Ports hole-punching packets to {} IP. total={}",
        1 + info.remote_udp4_nat_alternatives.len(),
        PUNCHING_RANDOM_PORT_COUNT * (1 + info.remote_udp4_nat_alternatives.len())
    );

    let ttl = ctx.ttl.load(Ordering::SeqCst);
    let rand_ports = p2p::generate_random_ports(PUNCHING_RANDOM_PORT_COUNT + 50);

    let mut conns: Vec<Arc<UdpSocket>> = Vec::with_capacity(PUNCHING_RANDOM_PORT_COUNT);
    let bind_ip = local_addr.ip();
    for port in &rand_ports {
        if conns.len() >= PUNCHING_RANDOM_PORT_COUNT {
            break;
        }
        let sa = SocketAddr::new(bind_ip, *port);
        if let Ok(sock) = netx::tokio_udp(sa, false) {
            let _ = netx::set_udp_ttl(&sock, ttl);
            conns.push(Arc::new(sock));
        }
    }

    for conn in &conns {
        for ra in &all_remote_addrs {
            let _ = conn.send_to(payload, *ra).await;
        }
    }

    let (winner_tx, mut winner_rx) = mpsc::channel::<HoleClaim>(1);
    for conn in conns.iter().cloned() {
        let ctx = ctx.clone();
        let payload = payload.to_vec();
        let winner_tx = winner_tx.clone();
        let round_scope = round_scope.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32];
            let deadline = tokio::time::sleep(Duration::from_secs(5));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => return,
                    _ = ctx.stop.wait() => return,
                    received = conn.recv_from(&mut buf) => {
                        let Ok((n, raddr)) = received else { return };
                        if buf[..n] != payload[..] { continue; }
                        if !ctx.picked.swap(true, Ordering::SeqCst) {
                            let _ = netx::set_udp_ttl(&conn, 64);
                            let _ = conn.send_to(&payload, raddr).await;
                            if round_scope.remaining() > Duration::from_millis(250) {
                                tokio::time::sleep(Duration::from_millis(250)).await;
                                let _ = conn.send_to(&payload, raddr).await;
                            }
                            let local = conn.local_addr().unwrap_or(raddr);
                            let _ = winner_tx.try_send(HoleClaim {
                                socket: conn.clone(),
                                local,
                                remote: raddr,
                            });
                        }
                        return;
                    }
                }
            }
        });
    }
    drop(winner_tx);

    let mut won = false;
    tokio::select! {
        winner = winner_rx.recv() => {
            if let Some(claim) = winner {
                ctx.stop.stop();
                let _ = hole_tx.try_send(claim);
                won = true;
            }
        }
        _ = ctx.stop.wait() => {}
        _ = rsp_scope.sleep_until_deadline(rsp_scope.remaining()) => {}
        _ = tokio::time::sleep(timeout + Duration::from_millis(500)) => {}
    }
    won
}
