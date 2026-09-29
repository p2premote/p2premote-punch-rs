//! Port of easyp2p/stun.go: STUN probing over 6 public servers (TCP and UDP,
//! UDP multiplexed over one socket via a UDPSessionDialer equivalent), plus
//! the easy/hard/symm NAT classification.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::netx;
use super::{P2pError, Result, Scope};

pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    // 两个国内保底（腾讯云 + 芒果TV，双栈、故障域独立），其后为国际站。
    // 列表纯本地探测用，不进交换协议，与对端列表是否一致无关。
    "stun.gonc.cc:3478",
    "stun.hitv.com:3478",
    "tcp://turn.cloudflare.com:80",
    "udp://turn.cloudflare.com:53?3478",
    "udp://stun.l.google.com:19302",
    "global.turn.twilio.com:3478",
    "stun.nextcloud.com:443",
];

/// STUN server list (gonc STUNServers). Env: P2PREMOTE_STUN_SERVERS
/// (comma-separated, same URL syntax incl. tcp:// / udp:// and ?port races).
pub fn stun_servers() -> Vec<String> {
    static VALUE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    VALUE
        .get_or_init(|| {
            match std::env::var("P2PREMOTE_STUN_SERVERS") {
                Ok(v) if !v.trim().is_empty() => v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>(),
                _ => DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            }
        })
        .clone()
}

const STUN_MAGIC: u32 = 0x2112_A442;
// RFC 5389/8489: XOR-MAPPED-ADDRESS masks the 16-bit port with the
// most-significant 16 bits of the magic cookie (0x2112), not its low half.
const STUN_PORT_XOR_MASK: u16 = (STUN_MAGIC >> 16) as u16;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub fn networks_for_stun(network: &str) -> Result<Vec<String>> {
    match network {
        "any" => Ok(vec!["tcp6".into(), "tcp4".into(), "udp4".into()]),
        "any6" => Ok(vec!["tcp6".into()]),
        "any4" => Ok(vec!["tcp4".into(), "udp4".into()]),
        "tcp" => Ok(vec!["tcp6".into(), "tcp4".into()]),
        "udp" => Ok(vec!["udp6".into(), "udp4".into()]),
        "tcp6" | "tcp4" | "udp6" | "udp4" => Ok(vec![network.to_string()]),
        _ => Err(P2pError::msg(format!("unsupported network type: '{}'", network))),
    }
}

#[derive(Debug, Clone)]
pub struct StunResult {
    pub index: usize,
    pub network: String,
    pub local: String,
    pub nat: String,
    pub err: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AnalyzedStunResult {
    pub nattype: String,
    pub network: String,
    pub lan: String,
    pub nat: String,
}

// ============ UDP multiplexer (netx.UDPSessionDialer) ============

pub struct UdpMux {
    pub(crate) socket: Arc<tokio::net::UdpSocket>,
    routes: Arc<Mutex<HashMap<SocketAddr, Vec<mpsc::Sender<Vec<u8>>>>>>,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl UdpMux {
    pub fn bind(local: SocketAddr) -> std::io::Result<Arc<UdpMux>> {
        // SO_REUSEADDR: attempt loops rebind the same local port while a
        // previous attempt's socket may still be draining; Linux/Android
        // fail the bind with EADDRINUSE otherwise (Windows ignores it).
        let socket = netx::tokio_udp(local, true)?;
        let socket = Arc::new(socket);
        let routes = Arc::new(Mutex::new(HashMap::<
            SocketAddr,
            Vec<mpsc::Sender<Vec<u8>>>,
        >::new()));
        // Do not move Arc<UdpMux> into this task. Doing so keeps the STUN
        // socket alive forever, whereas gonc closes its UDPSessionDialer and
        // underlying socket before the puncher re-binds the STUN-discovered
        // local port. A leaked reader can steal every inbound punch packet on
        // Windows when both sockets are allowed to bind the same port.
        let reader_socket = socket.clone();
        let reader_routes = routes.clone();
        let reader_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match reader_socket.recv_from(&mut buf).await {
                    Ok((n, remote)) => {
                        let senders: Vec<mpsc::Sender<Vec<u8>>> = reader_routes
                            .lock()
                            .unwrap()
                            .get(&remote)
                            .cloned()
                            .unwrap_or_default();
                        for tx in senders {
                            let _ = tx.try_send(buf[..n].to_vec());
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        Ok(Arc::new(UdpMux {
            socket,
            routes,
            reader_task: Mutex::new(Some(reader_task)),
        }))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap_or(local_any())
    }

    async fn connect(self: &Arc<Self>, remote: SocketAddr) -> std::io::Result<VirtualUdpConn> {
        let (tx, rx) = mpsc::channel(256);
        self.routes.lock().unwrap().entry(remote).or_default().push(tx);
        // Determine the concrete local IP when bound to the wildcard address
        // (netx.UDPSessionDialer dummies a UDP connect for this).
        let mux_local = self.local_addr();
        let local_ip = if mux_local.ip().is_unspecified() {
            dummy_local_ip(remote).unwrap_or(mux_local.ip())
        } else {
            mux_local.ip()
        };
        Ok(VirtualUdpConn {
            socket: self.socket.clone(),
            remote,
            rx,
            local_addr: SocketAddr::new(local_ip, mux_local.port()),
        })
    }
}

impl Drop for UdpMux {
    fn drop(&mut self) {
        if let Some(task) = self.reader_task.lock().unwrap().take() {
            task.abort();
        }
    }
}

fn local_any() -> SocketAddr {
    SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
}

fn dummy_local_ip(remote: SocketAddr) -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind(match remote {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .ok()?;
    sock.connect(remote).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

#[allow(dead_code)]
pub struct VirtualUdpConn {
    socket: Arc<tokio::net::UdpSocket>,
    remote: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    local_addr: SocketAddr,
}

impl VirtualUdpConn {
    pub async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(data, self.remote).await
    }
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    #[allow(dead_code)]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }
}

// ============ transport conn (TCP / UDP / UDP port-race) ============

enum ConnKind {
    Tcp(tokio::net::TcpStream),
    Udp(VirtualUdpConn),
    UdpRace {
        socket: Arc<tokio::net::UdpSocket>,
        remotes: Vec<SocketAddr>,
        rx: mpsc::Receiver<(usize, Vec<u8>)>,
        winner: Arc<AtomicUsize>,
    },
}

pub struct StunConn {
    kind: ConnKind,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

const NO_WINNER: usize = usize::MAX;

impl StunConn {
    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        match &mut self.kind {
            ConnKind::Tcp(stream) => {
                use tokio::io::AsyncWriteExt;
                stream.write_all(data).await?;
                Ok(())
            }
            ConnKind::Udp(conn) => {
                conn.send(data).await?;
                Ok(())
            }
            ConnKind::UdpRace { socket, remotes, winner, .. } => {
                let w = winner.load(Ordering::SeqCst);
                if w != NO_WINNER {
                    socket.send_to(data, remotes[w]).await?;
                } else {
                    for remote in remotes {
                        let _ = socket.send_to(data, *remote).await;
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        match &mut self.kind {
            ConnKind::Tcp(stream) => {
                let mut buf = vec![0u8; 2048];
                use tokio::io::AsyncReadExt;
                let n = stream.read(&mut buf).await.ok()?;
                buf.truncate(n);
                Some(buf)
            }
            ConnKind::Udp(conn) => conn.recv().await,
            ConnKind::UdpRace { rx, winner, .. } => loop {
                let (index, data) = rx.recv().await?;
                let w = winner.load(Ordering::SeqCst);
                if w == NO_WINNER {
                    winner.store(index, Ordering::SeqCst);
                    return Some(data);
                }
                if w == index {
                    return Some(data);
                }
                // Non-winner traffic is dropped (netx.RaceConn semantics).
            },
        }
    }
}

// ============ STUN message codec ============

fn build_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    msg.extend_from_slice(txid);
    msg
}

fn parse_mapped_address(msg: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if msg.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    let _msg_len = u16::from_be_bytes([msg[2], msg[3]]);
    let magic = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if msg_type != STUN_BINDING_SUCCESS || magic != STUN_MAGIC {
        return None;
    }
    if msg[8..20] != *txid {
        return None;
    }
    let mut offset = 20usize;
    while offset + 4 <= msg.len() {
        let attr_type = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
        let attr_len = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]) as usize;
        let value_start = offset + 4;
        if value_start + attr_len > msg.len() {
            return None;
        }
        let value = &msg[value_start..value_start + attr_len];
        if attr_type == ATTR_XOR_MAPPED_ADDRESS && value.len() >= 8 {
            let family = value[1];
            let xport = u16::from_be_bytes([value[2], value[3]]) ^ STUN_PORT_XOR_MASK;
            let magic_bytes = STUN_MAGIC.to_be_bytes();
            match family {
                0x01 if value.len() >= 8 => {
                    let mut ip = [0u8; 4];
                    for i in 0..4 {
                        ip[i] = value[4 + i] ^ magic_bytes[i];
                    }
                    return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), xport));
                }
                0x02 if value.len() >= 20 => {
                    let mut ip = [0u8; 16];
                    let mut key = [0u8; 16];
                    key[..4].copy_from_slice(&magic_bytes);
                    key[4..].copy_from_slice(txid);
                    for i in 0..16 {
                        ip[i] = value[4 + i] ^ key[i];
                    }
                    return Some(SocketAddr::new(
                        IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                        xport,
                    ));
                }
                _ => {}
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS && value.len() >= 8 {
            let family = value[1];
            let port = u16::from_be_bytes([value[2], value[3]]);
            match family {
                0x01 if value.len() >= 8 => {
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(&value[4..8]);
                    return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
                }
                0x02 if value.len() >= 20 => {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&value[4..20]);
                    return Some(SocketAddr::new(
                        IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                        port,
                    ));
                }
                _ => {}
            }
        }
        // Attributes are padded to 4-byte boundaries.
        offset = value_start + attr_len.div_ceil(4) * 4;
    }
    None
}

fn validate_nat_ip(nat_ip: IpAddr, server_addr: SocketAddr) -> std::result::Result<(), String> {
    let bad = match nat_ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || v4.octets()[0] >= 224 // multicast / reserved
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xff00) == 0xfe00 // link-local
                || (v6.segments()[0] & 0xff00) == 0xff00 // multicast
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local
        }
    };
    if bad {
        return Err(format!("NAT IP {} is a private/reserved address", nat_ip));
    }
    if server_addr.ip() == nat_ip {
        return Err(format!("NAT IP {} is the same as STUN server IP", nat_ip));
    }
    Ok(())
}

async fn stun_query(conn: &mut StunConn, deadline: Instant) -> std::result::Result<SocketAddr, String> {
    let mut txid = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut txid);
    let request = build_binding_request(&txid);

    let mut rto = Duration::from_millis(120);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("STUN query timeout".to_string());
        }
        if conn.send(&request).await.is_err() {
            return Err("STUN send failed".to_string());
        }
        let wait = rto.min(deadline.saturating_duration_since(now));
        let sleep = tokio::time::sleep(wait);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                data = conn.recv() => {
                    let Some(data) = data else { return Err("STUN connection closed".to_string()) };
                    if let Some(addr) = parse_mapped_address(&data, &txid) {
                        validate_nat_ip(addr.ip(), conn.remote_addr)?;
                        return Ok(addr);
                    }
                    // Not our transaction (or malformed); keep waiting.
                }
            }
        }
        rto = (rto * 2).min(Duration::from_secs(2));
    }
}

// ============ dial + probe ============

/// Resolve a STUN target for the network family. Go's
/// ResolveTCPAddr("tcp6", …) fails when there is no AAAA record — no
/// cross-family fallback here either.
async fn resolve_stun_target(host: &str, port: &str, ipv6: bool) -> std::result::Result<SocketAddr, String> {
    use tokio::net::lookup_host;
    let target = format!("{}:{}", host, port);
    let addrs: Vec<SocketAddr> = lookup_host(target)
        .await
        .map_err(|e| format!("resolve failed: {}", e))?
        .collect();
    addrs
        .into_iter()
        .find(|a| a.is_ipv6() == ipv6)
        .ok_or_else(|| "no address for network family".to_string())
}

async fn dial_stun_conn(
    network: &str,
    server: &str,
    bind: Option<SocketAddr>,
    udp_mux: Option<&Arc<UdpMux>>,
) -> std::result::Result<StunConn, String> {
    // server may be "host:port?p2?p3" (netx.DialRace syntax).
    let mut parts = server.split('?');
    let base = parts.next().unwrap_or(server);
    let extra_ports: Vec<&str> = parts.collect();
    let (host, port) = netx::split_host_port(base).ok_or("invalid base address")?;
    let port_str = port.to_string();

    let is_tcp = network.starts_with("tcp");
    let is_ipv6 = network.ends_with('6');
    if is_tcp {
        let primary = resolve_stun_target(&host, &port_str, is_ipv6).await?;
        let mut targets = vec![primary];
        for extra in &extra_ports {
            if let Ok(addr) = resolve_stun_target(&host, extra, is_ipv6).await {
                targets.push(addr);
            }
        }
        if targets.len() == 1 {
            let stream = dial_tcp_bind(targets[0], bind).await?;
            return Ok(StunConn {
                local_addr: stream.local_addr().map_err(|e| e.to_string())?,
                remote_addr: targets[0],
                kind: ConnKind::Tcp(stream),
            });
        }
        // Happy-eyeballs over ports.
        let (tx, mut rx) = mpsc::channel(targets.len());
        for target in targets {
            let tx = tx.clone();
            let bind = bind;
            tokio::spawn(async move {
                if let Ok(stream) = dial_tcp_bind(target, bind).await {
                    let _ = tx.send(stream).await;
                }
            });
        }
        drop(tx);
        match rx.recv().await {
            Some(stream) => Ok(StunConn {
                local_addr: stream.local_addr().map_err(|e| e.to_string())?,
                remote_addr: stream.peer_addr().map_err(|e| e.to_string())?,
                kind: ConnKind::Tcp(stream),
            }),
            None => Err("all tcp dials failed".to_string()),
        }
    } else {
        let mux = udp_mux.ok_or("no udp mux")?;
        let primary = resolve_stun_target(&host, &port_str, is_ipv6).await?;
        if extra_ports.is_empty() {
            let conn = mux.connect(primary).await.map_err(|e| e.to_string())?;
            Ok(StunConn {
                local_addr: conn.local_addr(),
                remote_addr: primary,
                kind: ConnKind::Udp(conn),
            })
        } else {
            let (tx, rx) = mpsc::channel::<(usize, Vec<u8>)>(100);
            let winner = Arc::new(AtomicUsize::new(NO_WINNER));
            let mut remotes = Vec::new();
            let mut local = local_any();
            for target_port in std::iter::once(port_str.as_str()).chain(extra_ports.iter().copied()) {
                if let Ok(addr) = resolve_stun_target(&host, target_port, is_ipv6).await {
                    if let Ok(conn) = mux.connect(addr).await {
                        local = conn.local_addr();
                        remotes.push(addr);
                    }
                }
            }
            if remotes.is_empty() {
                return Err("all udp dials failed".to_string());
            }
            // One forwarder task per port: first data wins (RaceConn).
            for target_port in std::iter::once(port_str.as_str()).chain(extra_ports.iter().copied()) {
                if let Ok(addr) = resolve_stun_target(&host, target_port, is_ipv6).await {
                    if let Ok(mut conn) = mux.connect(addr).await {
                        let index = remotes.iter().position(|r| *r == addr).unwrap_or(0);
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            while let Some(data) = conn.recv().await {
                                if tx.send((index, data)).await.is_err() {
                                    return;
                                }
                            }
                        });
                    }
                }
            }
            drop(tx);
            Ok(StunConn {
                local_addr: local,
                remote_addr: remotes[0],
                kind: ConnKind::UdpRace {
                    socket: mux.socket.clone(),
                    remotes,
                    rx,
                    winner,
                },
            })
        }
    }
}

async fn dial_tcp_bind(
    target: SocketAddr,
    bind: Option<SocketAddr>,
) -> std::result::Result<tokio::net::TcpStream, String> {
    let socket = if target.is_ipv6() {
        tokio::net::TcpSocket::new_v6()
    } else {
        tokio::net::TcpSocket::new_v4()
    }
    .map_err(|e| e.to_string())?;
    #[cfg(target_os = "android")]
    match bind {
        Some(address) => super::socketprotect::protect_socket_bound(&socket, &address),
        None => super::socketprotect::protect_socket(&socket),
    }
    // netx.ControlTCP: SO_REUSEADDR + SO_REUSEPORT before bind.
    let _ = socket.set_reuseaddr(true);
    #[cfg(unix)]
    let _ = socket.set_reuseport(true);
    if let Some(bind) = bind {
        socket.bind(bind).map_err(|e| e.to_string())?;
    }
    socket.connect(target).await.map_err(|e| e.to_string())
}

/// GetPublicIPsContext: probe all servers for one network concurrently.
pub async fn get_public_ips(
    scope: &Scope,
    network: &str,
    bind: &str,
    timeout: Duration,
) -> Result<Vec<StunResult>> {
    let phase_scope = scope.child(timeout);
    let is_tcp = network.starts_with("tcp");
    let is_ipv6 = network.ends_with('6');

    let mut udp_mux = None;
    let mut _udp_mux_guard: Option<Arc<UdpMux>> = None;
    let bind_addr: Option<SocketAddr> = if !bind.is_empty() {
        let (host, port) = netx::split_host_port(bind)
            .ok_or_else(|| P2pError::msg(format!("invalid bind address: {}", bind)))?;
        let ip: IpAddr = if host.is_empty() {
            if is_ipv6 {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        } else {
            host.parse().map_err(|_| P2pError::msg(format!("invalid bind ip: {}", host)))?
        };
        Some(SocketAddr::new(ip, port))
    } else {
        None
    };

    if !is_tcp {
        let mux_local = bind_addr.unwrap_or_else(|| {
            if is_ipv6 {
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }
        });
        let mux = UdpMux::bind(mux_local)
            .map_err(|e| P2pError::msg(format!("error binding UDP address: {}", e)))?;
        _udp_mux_guard = Some(mux.clone());
        udp_mux = Some(mux);
    }

    let result_network = if is_ipv6 {
        if is_tcp { "tcp6" } else { "udp6" }.to_string()
    } else if is_tcp {
        "tcp4".to_string()
    } else {
        "udp4".to_string()
    };

    struct ServerSpec {
        index: usize,
        addr: String,
        #[allow(dead_code)]
        scheme: String,
    }
    let mut specs = Vec::new();
    let stun_servers = stun_servers();
    for (index, raw) in stun_servers.iter().enumerate() {
        let (scheme, addr) = if let Some(rest) = raw.strip_prefix("udp://") {
            ("udp".to_string(), rest.to_string())
        } else if let Some(rest) = raw.strip_prefix("tcp://") {
            ("tcp".to_string(), rest.to_string())
        } else {
            (String::new(), raw.to_string())
        };
        let proto = if is_tcp { "tcp" } else { "udp" };
        if !scheme.is_empty() && scheme != proto {
            continue;
        }
        specs.push(ServerSpec {
            index,
            addr,
            scheme,
        });
    }

    let (tx, mut rx) = mpsc::channel::<StunResult>(specs.len());
    let mut pending: HashSet<usize> = specs.iter().map(|s| s.index).collect();
    for spec in specs {
        let tx = tx.clone();
        let network_name = result_network.clone();
        let bind_addr = bind_addr;
        let mux_ref = udp_mux.clone();
        let deadline = phase_scope.deadline;
        let spec_addr = spec.addr.clone();
        let spec_index = spec.index;
        tokio::spawn(async move {
            let started = Instant::now();
            let send = |err: Option<String>, local: String, nat: String| StunResult {
                index: spec_index,
                network: network_name.clone(),
                local,
                nat,
                err,
            };
            let mut conn = match dial_stun_conn(&network_name, &spec_addr, bind_addr, mux_ref.as_ref()).await {
                Ok(conn) => conn,
                Err(err) => {
                    crate::p2plog!("STUN dial failed [{}]: {}", spec_addr, err);
                    let _ = tx
                        .send(send(Some(format!("STUN dial failed: {}", err)), String::new(), String::new()))
                        .await;
                    return;
                }
            };
            match stun_query(&mut conn, deadline).await {
                Ok(nat_addr) => {
                    let _ = tx
                        .send(send(
                            None,
                            conn.local_addr.to_string(),
                            nat_addr.to_string(),
                        ))
                        .await;
                }
                Err(err) => {
                    crate::p2plog!("STUN response error [{}]: {}", spec_addr, err);
                    let _ = tx
                        .send(send(Some(format!("STUN response error: {}", err)), String::new(), String::new()))
                        .await;
                }
            }
            let _ = started;
        });
    }
    drop(tx);

    let mut collected = Vec::new();
    loop {
        if phase_scope.expired() {
            for index in &pending {
                collected.push(StunResult {
                    index: *index,
                    network: result_network.clone(),
                    local: String::new(),
                    nat: String::new(),
                    err: Some("context deadline exceeded".to_string()),
                });
            }
            break;
        }
        tokio::select! {
            received = rx.recv() => {
                match received {
                    Some(result) => {
                        pending.remove(&result.index);
                        collected.push(result);
                        if pending.is_empty() { break; }
                    }
                    None => break,
                }
            }
            _ = phase_scope.sleep_until_deadline(phase_scope.remaining()) => {
                continue; // loop head marks pending timeouts
            }
        }
    }

    Ok(collected)
}

/// GetNetworksPublicIPsContext for a list of networks.
pub async fn get_networks_public_ips(
    scope: &Scope,
    network_list: &[String],
    bind: &str,
    timeout: Duration,
) -> Result<Vec<StunResult>> {
    let mut bind_owned = bind.to_string();
    let bind_unspecified = bind.is_empty();
    if bind.is_empty() {
        let port = netx::get_free_port().map_err(|e| P2pError::msg(e.to_string()))?;
        bind_owned = format!(":{}", port);
    }

    let (tx, rx) = mpsc::channel(network_list.len());
    let mut tasks = Vec::new();
    let mut udp_attempt_number = 0usize;
    for network in network_list {
        let is_ipv6 = network.ends_with('6');
        let mut bind_candidate = bind_owned.clone();
        if udp_attempt_number > 0 && bind_unspecified {
            if let Ok(port) = netx::get_free_port_for(is_ipv6) {
                bind_candidate = format!(":{}", port);
            }
        }
        if network.starts_with("udp") {
            udp_attempt_number += 1;
        }
        let tx = tx.clone();
        let network = network.clone();
        let scope = scope.clone();
        let bind_candidate = bind_candidate;
        tasks.push(tokio::spawn(async move {
            let result = get_public_ips(&scope, &network, &bind_candidate, timeout).await;
            if let Err(err) = &result {
                crate::p2plog!("get_public_ips({}) failed: {}", network, err);
            }
            let _ = tx.send((network, result)).await;
        }));
    }
    drop(tx);
    let mut rx = rx;
    let mut all_results = Vec::new();
    for _ in 0..tasks.len() {
        if let Some((_, Ok(results))) = rx.recv().await {
            all_results.extend(results);
        }
    }
    for task in tasks {
        if let Err(join_err) = task.await {
            crate::p2plog!("stun task panicked: {}", join_err);
        }
    }

    if all_results.is_empty() {
        return Err(P2pError::msg("no public IP addresses found or all attempts failed"));
    }
    Ok(all_results)
}

pub fn succeeded_stun_results(results: &[StunResult]) -> usize {
    results.iter().filter(|r| r.err.is_none()).count()
}

/// analyzeSTUNResults: easy (port preserving) / hard (remapped, consistent) /
/// symm (port varies by server).
pub fn analyze_stun_results(results: &[StunResult]) -> Vec<AnalyzedStunResult> {
    #[derive(Hash, PartialEq, Eq, Clone)]
    struct Key {
        network: String,
        local: String,
        nat_ip: String,
    }
    let mut grouped: HashMap<Key, Vec<&StunResult>> = HashMap::new();
    let mut order: Vec<Key> = Vec::new();
    for r in results.iter().filter(|r| r.err.is_none()) {
        let nat_ip = netx::split_host_port(&r.nat)
            .map(|(h, _)| h)
            .unwrap_or_else(|| r.nat.clone());
        let key = Key {
            network: r.network.clone(),
            local: r.local.clone(),
            nat_ip,
        };
        if !grouped.contains_key(&key) {
            order.push(key.clone());
        }
        grouped.entry(key).or_default().push(r);
    }

    let mut out = Vec::new();
    for key in order {
        let group = &grouped[&key];
        let lan_port = netx::split_host_port(&key.local).map(|(_, p)| p).unwrap_or_default();
        let first = group[0];
        let nat_port = netx::split_host_port(&first.nat).map(|(_, p)| p).unwrap_or_default();
        let mut seen_ports = HashSet::new();
        for r in group {
            if let Some((_, port)) = netx::split_host_port(&r.nat) {
                seen_ports.insert(port);
            }
        }
        let nattype = if group.len() == 1 || seen_ports.len() == 1 {
            if lan_port == nat_port {
                "easy"
            } else {
                "hard"
            }
        } else {
            "symm"
        };
        out.push(AnalyzedStunResult {
            nattype: nattype.to_string(),
            network: key.network.clone(),
            lan: key.local.clone(),
            nat: first.nat.clone(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_mux_reader_does_not_keep_mux_alive() {
        let mux = UdpMux::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let weak = Arc::downgrade(&mux);
        drop(mux);
        tokio::task::yield_now().await;
        assert!(
            weak.upgrade().is_none(),
            "STUN reader must not retain the mux and its bound socket"
        );
    }

    #[test]
    fn binding_request_layout() {
        let txid = [7u8; 12];
        let msg = build_binding_request(&txid);
        assert_eq!(msg.len(), 20);
        assert_eq!(&msg[0..2], &[0x00, 0x01]);
        assert_eq!(&msg[4..8], &[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(&msg[8..20], &txid);
    }

    #[test]
    fn parse_xor_mapped_v4() {
        // Build a response with XOR-MAPPED-ADDRESS 1.2.3.4:80
        let txid = [9u8; 12];
        let magic = STUN_MAGIC.to_be_bytes();
        let mut addr = vec![0x00, 0x01];
        let xport = 80u16 ^ STUN_PORT_XOR_MASK;
        addr.extend_from_slice(&xport.to_be_bytes());
        let ip = [1, 2, 3, 4];
        for i in 0..4 {
            addr.push(ip[i] ^ magic[i]);
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(4 + addr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&magic);
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&addr);
        let parsed = parse_mapped_address(&msg, &txid).unwrap();
        assert_eq!(parsed.to_string(), "1.2.3.4:80");
    }

    #[test]
    fn parse_xor_mapped_v4_real_capture_preserves_port() {
        // Captured from stun.gonc.cc. Local UDP source port was 56591; the
        // response must decode to the same public port, not 22623 (the value
        // produced when XORing with the cookie's low 16 bits, 0xa442).
        let response = [
            0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
            0x09, 0xce, 0xf7, 0xbb, 0xdb, 0x92, 0xeb, 0xf2,
            0xb7, 0x41, 0x0f, 0xf6, 0x00, 0x20, 0x00, 0x08,
            0x00, 0x01, 0xfc, 0x1d, 0x54, 0xbd, 0x2e, 0x4f,
        ];
        let txid: [u8; 12] = response[8..20].try_into().unwrap();
        let parsed = parse_mapped_address(&response, &txid).unwrap();
        assert_eq!(parsed.to_string(), "117.175.138.13:56591");
    }

    #[test]
    fn classification_rules() {
        let mk = |network: &str, local: &str, nat: &str| StunResult {
            index: 0,
            network: network.into(),
            local: local.into(),
            nat: nat.into(),
            err: None,
        };
        // single result, port preserved → easy
        let easy = analyze_stun_results(&[mk("udp4", "192.168.1.5:5000", "1.1.1.1:5000")]);
        assert_eq!(easy[0].nattype, "easy");
        // single result, port remapped → hard
        let hard = analyze_stun_results(&[mk("udp4", "192.168.1.5:5000", "1.1.1.1:6000")]);
        assert_eq!(hard[0].nattype, "hard");
        // multiple servers, same NAT ip+port, local port equal → easy
        let same = analyze_stun_results(&[
            mk("udp4", "192.168.1.5:5000", "1.1.1.1:5000"),
            mk("udp4", "192.168.1.5:5000", "1.1.1.1:5000"),
        ]);
        assert_eq!(same[0].nattype, "easy");
        // multiple ports → symm
        let symm = analyze_stun_results(&[
            mk("udp4", "192.168.1.5:5000", "1.1.1.1:5000"),
            mk("udp4", "192.168.1.5:5000", "1.1.1.1:5001"),
        ]);
        assert_eq!(symm[0].nattype, "symm");
    }
}
