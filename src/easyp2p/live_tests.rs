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

/// Full Rust↔Rust tunnel through the exported C ABI, exactly like the
/// desktop client drives it: two roles, traversal negotiation, hole punching
/// (same-host peers land in the "easy/easy same-LAN" candidate), local
/// forwarders, and payload round-trip through both forward ports.
#[tokio::test]
#[ignore = "hits real MQTT/STUN servers"]
async fn udp_tunnel_rust_to_rust() {
    tunnel_roundtrip("udp4", 52820).await;
}

/// Same full-chain round-trip as `udp_tunnel_rust_to_rust` but the P2P
/// transport is TCP4: WG datagrams travel length-framed over the punched
/// stream.
#[tokio::test]
#[ignore = "hits real MQTT/STUN servers"]
async fn tcp_tunnel_rust_to_rust() {
    tunnel_roundtrip("tcp4", 52840).await;
}

/// IPv6 forms: same-host peers typically get global (non-ULA) v6 addresses,
/// which lands in the "same NAT, different network" bucket — this exercises
/// the TCP +100 simultaneous-open path and the UDP NAT-address route.
#[tokio::test]
#[ignore = "hits real MQTT/STUN servers; requires IPv6 connectivity"]
async fn udp_tunnel_rust_to_rust_v6() {
    tunnel_roundtrip("udp6", 52850).await;
}

/// Aggregate network matrix: "any" probes tcp6+tcp4+udp4 and the forward
/// layer follows whichever transport the punch lands on.
#[tokio::test]
#[ignore = "hits real MQTT/STUN servers"]
async fn tunnel_rust_to_rust_any() {
    tunnel_roundtrip("any", 52870).await;
}

#[tokio::test]
#[ignore = "hits real MQTT/STUN servers; requires IPv6 connectivity"]
async fn tcp_tunnel_rust_to_rust_v6() {
    // TCP needs at least one easy side; on port-randomizing v6 firewalls both
    // peers classify hard and the punch is (correctly) refused — treat that
    // as an environment skip, everything else must succeed.
    tunnel_roundtrip_inner("tcp6", 52860, true).await;
}

/// STUN probe over the IPv6 networks (requires IPv6 connectivity).
#[tokio::test]
#[ignore = "hits real STUN servers; requires IPv6 connectivity"]
async fn stun_live_v6() {
    let scope = Scope::from_timeout(Duration::from_secs(15));
    let networks = ["udp6".to_string(), "tcp6".to_string()];
    let results = stun::get_networks_public_ips(&scope, &networks, "", Duration::from_millis(2828))
        .await
        .expect("stun phase failed");
    let ok = results.iter().filter(|r| r.err.is_none()).count();
    eprintln!("STUN v6 results: {}/{} succeeded", ok, results.len());
    for r in &results {
        eprintln!("  [{}] {} local={} nat={} err={:?}", r.index, r.network, r.local, r.nat, r.err);
    }
    assert!(ok > 0, "no v6 STUN server answered (no IPv6 connectivity?)");
}

async fn tunnel_roundtrip(network: &str, echo_port: u16) {
    tunnel_roundtrip_inner(network, echo_port, false).await;
}

async fn tunnel_roundtrip_inner(network: &str, echo_port: u16, tolerate_hard_hard_refusal: bool) {
    use crate::types::UdpTunnelResult;

    // Same-host peers share one NAT classification: when the local side is
    // non-easy the pair is hard×hard and TCP punching is (correctly) refused
    // — probe first and skip deterministically instead of burning 60s.
    if tolerate_hard_hard_refusal {
        let probe_scope = Scope::from_timeout(Duration::from_secs(10));
        if let Ok(results) = stun::get_networks_public_ips(
            &probe_scope,
            &[network.to_string()],
            "",
            Duration::from_millis(2828),
        )
        .await
        {
            let analyzed = stun::analyze_stun_results(&results);
            let types: Vec<String> = analyzed.iter().map(|a| a.nattype.clone()).collect();
            if !types.is_empty() && types.iter().all(|t| t != "easy") {
                eprintln!(
                    "SKIPPED: local {} classification {:?} is non-easy — same-host peers are hard×hard; TCP punch correctly refused (gonc parity)",
                    network, types
                );
                return;
            }
        }
    }

    let wg_port = echo_port + 1;
    let token = format!(
        "rs-tunnel-{}-{}",
        network,
        &crypto::calculate_md5(&format!("{:?}", std::time::SystemTime::now()))[..8]
    );

    let run_side = |role: &'static str, target_port: u16, token: String, network: String| {
        tokio::task::spawn_blocking(move || {
            let input = format!(
                r#"{{"token":"{}","role_hint":"{}","traversal_mode":"auto","network":"{}","timeout_secs":60,"remote_target_port":{}}}"#,
                token, role, network, target_port
            );
            let c = std::ffi::CString::new(input).unwrap();
            let raw = crate::StartUdpTunnel(c.as_ptr());
            let out = unsafe { std::ffi::CStr::from_ptr(raw) }.to_string_lossy().into_owned();
            crate::FreeCString(raw);
            let result: UdpTunnelResult = serde_json::from_str(&out).expect(out.as_str());
            (out, result)
        })
    };

    // Echo server on the active side's WireGuard port: replies ACK-*.
    let echo = tokio::spawn(async move {
        let bind_to = format!("127.0.0.1:{}", echo_port);
        let socket = tokio::net::UdpSocket::bind(&bind_to).await.expect("bind echo port");
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, src) = tokio::time::timeout(Duration::from_secs(90), socket.recv_from(&mut buf))
                .await
                .expect("echo timeout")
                .expect("echo recv");
            let data = String::from_utf8_lossy(&buf[..n]).into_owned();
            eprintln!("[echo-{}] got {:?} from {}", echo_port, data, src);
            let reply = format!("ACK-{}", data);
            socket.send_to(reply.as_bytes(), src).await.unwrap();
            if data == "ping" {
                return reply;
            }
        }
    });

    let passive = run_side("passive", wg_port, token.clone(), network.to_string());
    tokio::time::sleep(Duration::from_secs(1)).await;
    let active = run_side("active", echo_port, token.clone(), network.to_string());

    let (active_out, active_result) = tokio::time::timeout(Duration::from_secs(100), active)
        .await
        .expect("active tunnel timeout")
        .expect("active join");
    assert!(active_result.ok, "active tunnel failed: {}", active_out);
    eprintln!("active: forward={}:{} peer={} traversal={} network={}",
        active_result.local_forward_addr, active_result.local_forward_port, active_result.peer_endpoint, active_result.selected_traversal, active_result.network);

    let (passive_out, passive_result) = tokio::time::timeout(Duration::from_secs(100), passive)
        .await
        .expect("passive tunnel timeout")
        .expect("passive join");
    assert!(passive_result.ok, "passive tunnel failed: {}", passive_out);
    eprintln!("passive: forward={}:{} peer={} traversal={} network={}",
        passive_result.local_forward_addr, passive_result.local_forward_port, passive_result.peer_endpoint, passive_result.selected_traversal, passive_result.network);

    // The passive side acts as the WireGuard client: it sends from its WG
    // endpoint port (the tunnel's remote_target_port, exactly how kernel WG
    // behaves) through the forward port, and receives the echo back on the
    // same port.
    let target: SocketAddr = format!("127.0.0.1:{}", passive_result.local_forward_port).parse().unwrap();
    let bind_to = format!("127.0.0.1:{}", wg_port);
    let wg_socket = tokio::net::UdpSocket::bind(&bind_to).await.expect("bind wg port");
    let mut got = String::new();
    for i in 0..20 {
        wg_socket.send_to(b"ping", target).await.unwrap();
        eprintln!("[wg-{}] sent ping ({})", wg_port, i + 1);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            let mut buf = vec![0u8; 2048];
            let wait = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
            tokio::select! {
                received = wg_socket.recv_from(&mut buf) => {
                    let (n, src) = received.expect("wg recv");
                    let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                    eprintln!("[wg-{}] got {:?} from {}", wg_port, data, src);
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
        let raw = crate::StopUdpTunnel(c.as_ptr());
        let out = unsafe { std::ffi::CStr::from_ptr(raw) }.to_string_lossy().into_owned();
        crate::FreeCString(raw);
        assert!(out.contains(r#""ok":true"#), "stop failed: {}", out);
    }
}
