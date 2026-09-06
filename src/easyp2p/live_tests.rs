//! Live network tests — run manually with:
//!   cargo test --lib -- --ignored
//! They hit real public MQTT brokers / STUN servers and punch real holes.

use std::net::SocketAddr;
use std::time::Duration;

use super::*;

/// Real STUN probe: at least one of the six servers must answer so NAT
/// classification produces an entry.
#[tokio::test]
#[ignore = "hits real STUN servers"]
async fn stun_live_udp4() {
    let scope = Scope::from_timeout(Duration::from_secs(15));
    let results = stun::get_networks_public_ips(&scope, &["udp4".to_string()], "", Duration::from_millis(2828))
        .await
        .expect("stun phase failed");
    let ok = results.iter().filter(|r| r.err.is_none()).count();
    eprintln!("STUN results: {}/{} succeeded", ok, results.len());
    for r in &results {
        eprintln!("  [{}] {} local={} nat={} err={:?}", r.index, r.network, r.local, r.nat, r.err);
    }
    assert!(ok > 0, "no STUN server answered");
    let analyzed = stun::analyze_stun_results(&results);
    assert!(!analyzed.is_empty());
    eprintln!("NAT classification: {:?}", analyzed);
}

/// Rust↔Rust MQTT exchange inside one process (two sessions, two roles).
#[tokio::test]
#[ignore = "hits real MQTT brokers"]
async fn exchange_rust_to_rust() {
    let token = format!("rs-r2r-{}", &crypto::calculate_md5(&format!("{:?}", std::time::SystemTime::now()))[..8]);
    let active = tokio::spawn({
        let token = token.clone();
        async move {
            exchange::mqtt_exchange_payload(
                EXMODE_MUTUAL,
                "hello-from-active",
                &token,
                "wgvpn-kx/",
                Duration::from_secs(30),
                Duration::from_secs(40),
            )
            .await
        }
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let passive = tokio::spawn({
        let token = token.clone();
        async move {
            exchange::mqtt_exchange_payload(
                EXMODE_WAIT_ONLY,
                "hello-from-passive",
                &token,
                "wgvpn-kx/",
                Duration::from_secs(30),
                Duration::from_secs(40),
            )
            .await
        }
    });
    let a = tokio::time::timeout(Duration::from_secs(45), active)
        .await
        .expect("active timeout")
        .expect("active join")
        .expect("active exchange failed");
    let b = tokio::time::timeout(Duration::from_secs(45), passive)
        .await
        .expect("passive timeout")
        .expect("passive join")
        .expect("passive exchange failed");
    assert_eq!(a, "hello-from-passive");
    assert_eq!(b, "hello-from-active");
}

/// Full Rust↔Rust UDP tunnel through the exported C ABI, exactly like the
/// desktop client drives it: two roles, traversal negotiation, hole punching
/// (same-host peers land in the "easy/easy same-LAN" candidate), local
/// forwarders, and payload round-trip through both forward ports.
#[tokio::test]
#[ignore = "hits real MQTT/STUN servers"]
async fn udp_tunnel_rust_to_rust() {
    use crate::types::UdpTunnelResult;

    let token = format!("rs-tunnel-{}", &crypto::calculate_md5(&format!("{:?}", std::time::SystemTime::now()))[..8]);

    let run_side = |role: &'static str, target_port: u16, token: String| {
        tokio::task::spawn_blocking(move || {
            let input = format!(
                r#"{{"token":"{}","role_hint":"{}","traversal_mode":"auto","network":"udp4","timeout_secs":60,"remote_target_port":{}}}"#,
                token, role, target_port
            );
            let c = std::ffi::CString::new(input).unwrap();
            let raw = unsafe { crate::StartUdpTunnel(c.as_ptr()) };
            let out = unsafe { std::ffi::CStr::from_ptr(raw) }.to_string_lossy().into_owned();
            unsafe { crate::FreeCString(raw) };
            let result: UdpTunnelResult = serde_json::from_str(&out).expect(out.as_str());
            (out, result)
        })
    };

    // Echo server on the active side's WireGuard port (52820): replies ACK-*.
    let echo = tokio::spawn(async move {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:52820").await.expect("bind 52820");
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, src) = tokio::time::timeout(Duration::from_secs(90), socket.recv_from(&mut buf))
                .await
                .expect("echo timeout")
                .expect("echo recv");
            let data = String::from_utf8_lossy(&buf[..n]).into_owned();
            eprintln!("[echo-52820] got {:?} from {}", data, src);
            let reply = format!("ACK-{}", data);
            socket.send_to(reply.as_bytes(), src).await.unwrap();
            if data == "ping" {
                return reply;
            }
        }
    });

    let passive = run_side("passive", 52821, token.clone());
    tokio::time::sleep(Duration::from_secs(1)).await;
    let active = run_side("active", 52820, token.clone());

    let (active_out, active_result) = tokio::time::timeout(Duration::from_secs(100), active)
        .await
        .expect("active tunnel timeout")
        .expect("active join");
    assert!(active_result.ok, "active tunnel failed: {}", active_out);
    eprintln!("active: forward={}:{} peer={} traversal={}",
        active_result.local_forward_addr, active_result.local_forward_port, active_result.peer_endpoint, active_result.selected_traversal);

    let (passive_out, passive_result) = tokio::time::timeout(Duration::from_secs(100), passive)
        .await
        .expect("passive tunnel timeout")
        .expect("passive join");
    assert!(passive_result.ok, "passive tunnel failed: {}", passive_out);
    eprintln!("passive: forward={}:{} peer={} traversal={}",
        passive_result.local_forward_addr, passive_result.local_forward_port, passive_result.peer_endpoint, passive_result.selected_traversal);

    // The passive side acts as the WireGuard client: it sends from its WG
    // endpoint port (52821 — the tunnel's remote_target_port, exactly how
    // kernel WG behaves) through the forward port, and receives the echo back
    // on the same port.
    let target: SocketAddr = format!("127.0.0.1:{}", passive_result.local_forward_port).parse().unwrap();
    let wg_socket = tokio::net::UdpSocket::bind("127.0.0.1:52821").await.expect("bind 52821");
    let mut got = String::new();
    for i in 0..20 {
        wg_socket.send_to(b"ping", target).await.unwrap();
        eprintln!("[wg-52821] sent ping ({})", i + 1);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            let mut buf = vec![0u8; 2048];
            let wait = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
            tokio::select! {
                received = wg_socket.recv_from(&mut buf) => {
                    let (n, src) = received.expect("wg recv");
                    let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                    eprintln!("[wg-52821] got {:?} from {}", data, src);
                    // The peer's post-punch payload probe also lands here
                    // (WireGuard ignores it in production); keep waiting.
                    if data == "ACK-ping" {
                        got = data;
                        break;
                    }
                }
                _ = wait => break,
            }
        }
        if !got.is_empty() {
            break;
        }
    }
    assert_eq!(got, "ACK-ping");
    let echoed = tokio::time::timeout(Duration::from_secs(90), echo)
        .await
        .expect("echo join timeout")
        .expect("echo panicked");
    assert_eq!(echoed, "ACK-ping");

    // Stop both tunnels through the FFI.
    for handle in [&active_result.handle_id, &passive_result.handle_id] {
        let input = format!(r#"{{"handle_id":"{}"}}"#, handle);
        let c = std::ffi::CString::new(input).unwrap();
        let raw = unsafe { crate::StopUdpTunnel(c.as_ptr()) };
        let out = unsafe { std::ffi::CStr::from_ptr(raw) }.to_string_lossy().into_owned();
        unsafe { crate::FreeCString(raw) };
        assert!(out.contains(r#""ok":true"#), "stop failed: {}", out);
    }
}
