//! Socket plumbing mirroring netx (control_unix.go SetUDPTTL/ControlUDP,
//! bound UDP creation used by punching and tunnel forwarding).

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket as StdUdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, Type};

pub const UDP_FORWARD_BUF: usize = 65535;

/// net.ListenUDP equivalent, optionally with SO_REUSEADDR (netx.ControlUDP).
/// IPv6 binds are v6-only, mirroring Go's "udp6" sockets.
pub fn listen_udp(bind: SocketAddr, reuse_addr: bool) -> io::Result<StdUdpSocket> {
    let domain = if bind.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    super::socketprotect::protect_socket(&socket);
    if reuse_addr {
        socket.set_reuse_address(true)?;
    }
    if bind.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&socket2::SockAddr::from(bind))?;
    // Go's net package disables SIO_UDP_CONNRESET by default on Windows so
    // unconnected UDP reads don't fail with WSAECONNRESET after an ICMP
    // port-unreachable. Mirror that, or hole punching/forwarding dies.
    #[cfg(windows)]
    disable_udp_connreset(&socket);
    Ok(socket.into())
}

/// Best-effort SIO_UDP_CONNRESET=FALSE (Windows only, Go net parity).
#[cfg(windows)]
fn disable_udp_connreset(socket: &Socket) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::WSAIoctl;
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    let mut enable: u32 = 0; // FALSE
    let mut returned: u32 = 0;
    unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            &mut enable as *mut u32 as *const core::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        );
    }
}

/// netx.SetUDPTTL: IP_TTL (v4) or IPV6_UNICAST_HOPS (v6).
pub fn set_udp_ttl(socket: &tokio::net::UdpSocket, ttl: u32) -> io::Result<()> {
    let is_v6 = socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    let sref = SockRef::from(socket);
    if is_v6 {
        sref.set_unicast_hops_v6(ttl)
    } else {
        sref.set_ttl_v4(ttl)
    }
}

#[allow(dead_code)]
pub fn get_udp_ttl(socket: &tokio::net::UdpSocket) -> io::Result<u32> {
    SockRef::from(socket).ttl_v4()
}

/// Create an unconnected bound socket as a tokio UdpSocket.
pub fn tokio_udp(bind: SocketAddr, reuse_addr: bool) -> io::Result<tokio::net::UdpSocket> {
    let std_sock = listen_udp(bind, reuse_addr)?;
    std_sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std_sock)
}

/// CreateUDPConnFromAddr (non-force path): bind local addr then connect to the
/// remote. Returns a connected tokio UdpSocket.
pub async fn connected_udp(local: SocketAddr, remote: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let domain = if local.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    super::socketprotect::protect_socket(&socket);
    socket.bind(&socket2::SockAddr::from(local))?;
    socket.set_nonblocking(true)?;
    let std_sock: StdUdpSocket = socket.into();
    let tokio_sock = tokio::net::UdpSocket::from_std(std_sock)?;
    tokio_sock.connect(remote).await?;
    Ok(tokio_sock)
}

/// CreateUDPConnFromAddr force path: bind the port on the wildcard address
/// (the specific IP may already be in use) and connect.
pub async fn connected_udp_wildcard(local: SocketAddr, remote: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let wildcard = match local {
        SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, v4.port())),
        SocketAddr::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            v6.port(),
            0,
            0,
        )),
    };
    connected_udp(wildcard, remote).await
}

/// netx.ControlTCP listen side: SO_REUSEADDR (+ SO_REUSEPORT on unix) TCP
/// listener for simultaneous-open punching.
pub fn listen_tcp(bind: SocketAddr, reuse: bool) -> io::Result<TcpListener> {
    let domain = if bind.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if reuse {
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
    }
    if bind.is_ipv6() {
        // Go's net package keeps "tcp6" listeners v6-only.
        socket.set_only_v6(true)?;
    }
    socket.bind(&socket2::SockAddr::from(bind))?;
    socket.listen(1024)?;
    Ok(TcpListener::from(socket))
}

/// tryConnect dial path: optional local bind, optionally with the ControlTCP
/// reuse options (same-port dial beside the listener).
pub async fn connect_tcp_bind(
    target: SocketAddr,
    bind: Option<SocketAddr>,
    reuse: bool,
) -> io::Result<tokio::net::TcpStream> {
    let socket = if target.is_ipv6() {
        tokio::net::TcpSocket::new_v6()
    } else {
        tokio::net::TcpSocket::new_v4()
    }?;
    if reuse {
        let _ = socket.set_reuseaddr(true);
        #[cfg(unix)]
        let _ = socket.set_reuseport(true);
    }
    if let Some(bind) = bind {
        socket.bind(bind)?;
    }
    socket.connect(target).await
}

/// GetFreePort: a port bindable by both TCP and UDP, per family.
pub fn get_free_port_for(ipv6: bool) -> io::Result<u16> {
    for _ in 0..100 {
        let tcp = if ipv6 {
            TcpListener::bind("[::]:0")?
        } else {
            TcpListener::bind("0.0.0.0:0")?
        };
        let port = tcp.local_addr()?.port();
        let udp = if ipv6 {
            StdUdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, port))
        } else {
            StdUdpSocket::bind(("0.0.0.0", port))
        };
        match udp {
            Ok(udp) => {
                drop(udp);
                drop(tcp);
                return Ok(port);
            }
            Err(_) => {
                drop(tcp);
                continue;
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, "no free TCP/UDP ports available"))
}

/// GetFreePort (IPv4 form, the netx.GetFreePort default).
pub fn get_free_port() -> io::Result<u16> {
    get_free_port_for(false)
}

/// Wait with deadline, returning remaining time budget style used by copy loops.
#[allow(dead_code)]
pub fn deadline_from_now(timeout: Duration) -> tokio::time::Instant {
    tokio::time::Instant::from_std(std::time::Instant::now() + timeout)
}

/// Split "host:port" keeping brackets for IPv6; returns None when not host:port.
pub fn split_host_port(addr: &str) -> Option<(String, u16)> {
    // Handle [::1]:80
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = addr.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// JoinHostPort equivalent good enough for our address strings.
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Parse an address string that may be "ip", "ip:port", "[v6]:port" or a
/// hostname (hostnames never occur on this path).
pub fn parse_addr(addr: &str) -> Option<SocketAddr> {
    use std::net::IpAddr;
    if addr.parse::<IpAddr>().is_ok() {
        return None; // bare IP without port: not a socket address
    }
    addr.parse::<SocketAddr>().ok().or_else(|| {
        split_host_port(addr).and_then(|(h, p)| {
            h.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, p))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_join_roundtrip() {
        assert_eq!(split_host_port("1.2.3.4:5678"), Some(("1.2.3.4".into(), 5678)));
        assert_eq!(split_host_port("[::1]:443"), Some(("::1".into(), 443)));
        assert_eq!(join_host_port("::1", 443), "[::1]:443");
        assert_eq!(join_host_port("1.2.3.4", 443), "1.2.3.4:443");
    }

    #[test]
    fn free_port_is_bindable() {
        let port = get_free_port().unwrap();
        assert!(port > 0);
    }

    #[test]
    fn tcp_listener_and_same_port_dial() {
        // ControlTCP semantics: listener + a dial bound to the same local port
        // must coexist (REUSEADDR/REUSEPORT).
        let port = get_free_port().unwrap();
        let bind: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let _listener = listen_tcp(bind, true).expect("listen_tcp with reuse");
        // Binding another listener on the same port with reuse must also work.
        let _listener2 = listen_tcp(bind, true).expect("second listener with reuse");
    }
}
