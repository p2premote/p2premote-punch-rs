//! Cross-implementation interop driver for p2premote-punch-rs.
//!
//! Usage:
//!   cargo run --release --example interop -- exchange <exmode> <token> <senddata>
//!   cargo run --release --example interop -- tunnel <active|passive> <token> [wgPort]
//!   cargo run --release --example interop -- punch-tcp <token>
//!
//! Mirrors the Go harness in go-interop/ so the two implementations can be
//! pointed at each other over the real network. punch-tcp runs the raw TCP
//! punch (library level, no local forwarder) and does a ping/ACK echo over
//! the punched stream — the Go side is `go run . punch-tcp <token>`.

use std::ffi::{CStr, CString};
use std::net::UdpSocket;
use std::os::raw::c_char;
use std::time::{Duration, Instant};

use p2premote_punch::*;

fn call(f: unsafe extern "C" fn(*const c_char) -> *mut c_char, input: &str) -> String {
    let c = CString::new(input).unwrap();
    let raw = unsafe { f(c.as_ptr()) };
    let out = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
    FreeCString(raw);
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: interop exchange|tunnel ...");
        std::process::exit(2);
    }
    match args[1].as_str() {
        "exchange" => exchange(&args[2..]),
        "tunnel" => tunnel(&args[2..]),
        "punch-tcp" => punch_tcp(&args[2..]),
        "wait" => wait_cmd(&args[2..]),
        "hello" => hello_cmd(&args[2..]),
        other => {
            eprintln!("unknown mode {}", other);
            std::process::exit(2);
        }
    }
}

/// Wake channel against the Go harness: `wait <token>` parks until a hello,
/// `hello <token> [app] [param]` wakes it. Both print the same tid on success.
fn wait_cmd(args: &[String]) {
    let token = args[0].clone();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async move {
            use p2premote_punch::easyp2p::wake::mqtt_wait;
            use p2premote_punch::easyp2p::Scope;
            let scope = Scope::from_timeout(Duration::from_secs(70));
            match mqtt_wait(&scope, &token, "", Duration::from_secs(60)).await {
                Ok(tid) => {
                    let (parsed, salt) = p2premote_punch::easyp2p::wake::HelloPayload::parse_from(&tid);
                    println!("WAIT_TID {:?} salt={:?} control={:?} app={:?} param={:?}", tid, salt, parsed.control, parsed.app, parsed.param);
                }
                Err(err) => println!("WAIT_FAILED error={}", err),
            }
        });
}

fn hello_cmd(args: &[String]) {
    let token = args[0].clone();
    let mut payload = p2premote_punch::easyp2p::wake::HelloPayload::default();
    if let Some(app) = args.get(1) {
        payload.app = app.clone();
        if let Some(param) = args.get(2) {
            payload.param = param.clone();
        }
    }
    if let Some(cs) = args.get(3) {
        payload.set_control_value("cs", cs);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async move {
            use p2premote_punch::easyp2p::wake::mqtt_hello;
            use p2premote_punch::easyp2p::Scope;
            let scope = Scope::from_timeout(Duration::from_secs(70));
            match mqtt_hello(&scope, &token, "", &payload, Duration::from_secs(30)).await {
                Ok(tid) => println!("HELLO_TID {:?}", tid),
                Err(err) => println!("HELLO_FAILED error={}", err),
            }
        });
}

/// Raw TCP punch against the Go harness (`go run . punch-tcp <token>`): the
/// client side sends "ping\n", the server side echoes "ACK-ping\n". Optional
/// second argument is the network (tcp4 default, tcp6 for IPv6).
fn punch_tcp(args: &[String]) {
    let token = args[0].clone();
    let network = args.get(1).cloned().unwrap_or_else(|| "tcp4".to_string());
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async move {
            use p2premote_punch::easyp2p::p2p::{easy_p2p_mp_with_options, EasyP2PMPOptions, P2PConn};
            use p2premote_punch::easyp2p::Scope;
            use tokio::io::AsyncWriteExt;

            let scope = Scope::from_timeout(Duration::from_secs(110));
            let info = match easy_p2p_mp_with_options(&scope, &network, &token, EasyP2PMPOptions::default()).await {
                Ok(info) => info,
                Err(err) => {
                    println!("PUNCH_FAILED error={}", err);
                    return;
                }
            };
            println!(
                "PUNCHED peer={} is_client={} networks={:?} local_nat={} remote_nat={}",
                info.peer_address, info.is_client, info.networks_used, info.local_nat_type, info.remote_nat_type
            );
            let conn = match info.conn {
                P2PConn::Tcp(conn) => conn,
                _ => {
                    println!("PUNCH_FAILED error=non-tcp connection");
                    return;
                }
            };
            let (mut rd, mut wr) = conn.stream.into_split();
            if info.is_client {
                if wr.write_all(b"ping\n").await.is_err() {
                    println!("PUNCH_FAILED error=client write failed");
                    return;
                }
                match read_line(&mut rd).await {
                    Some(line) => println!("PONG {:?}", String::from_utf8_lossy(&line)),
                    None => println!("PUNCH_FAILED error=client read timeout"),
                }
            } else {
                match read_line(&mut rd).await {
                    Some(line) => {
                        println!("RECV {:?}", String::from_utf8_lossy(&line));
                        let _ = wr.write_all(b"ACK-ping\n").await;
                    }
                    None => println!("PUNCH_FAILED error=server read timeout"),
                }
            }
        });
}

async fn read_line(rd: &mut tokio::net::tcp::OwnedReadHalf) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut line: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), rd.read(&mut byte)).await {
            Ok(Ok(1)) => {
                if byte[0] == b'\n' {
                    return Some(line);
                }
                line.push(byte[0]);
            }
            _ => return None,
        }
    }
}

fn exchange(args: &[String]) {
    let exmode: i32 = args[0].parse().unwrap();
    let input = serde_json::json!({
        "token": args[1],
        "exmode": exmode,
        "send_data": args[2],
        "timeout_secs": 60,
    })
    .to_string();
    let out = call(Exchange, &input);
    println!("RESULT {}", out);
}

fn tunnel(args: &[String]) {
    let role = args[0].clone();
    let token = args[1].clone();
    let default_port: i32 = if role == "active" { 54820 } else { 54821 };
    let wg_port: i32 = args.get(2).map(|p| p.parse().unwrap()).unwrap_or(default_port);

    // ACK echo server on the WG endpoint port.
    let echo = UdpSocket::bind(("127.0.0.1", wg_port as u16)).expect("bind wg port");
    let echo_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, src)) = echo.recv_from(&mut buf) else { return };
            let data = String::from_utf8_lossy(&buf[..n]).into_owned();
            println!("RECV {:?}", data);
            let _ = echo.send_to(format!("ACK-{}", data).as_bytes(), src);
        }
    });

    let input = serde_json::json!({
        "token": token,
        "role_hint": role,
        "traversal_mode": "auto",
        "network": "udp4",
        "timeout_secs": 60,
        "remote_target_ip": "127.0.0.1",
        "remote_target_port": wg_port,
        "local_listen_ip": "127.0.0.1",
    })
    .to_string();
    let out = call(StartUdpTunnel, &input);
    println!("RESULT {}", out);
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    if parsed["ok"].as_bool() != Some(true) {
        std::thread::sleep(Duration::from_secs(5));
        return;
    }
    let handle_id = parsed["handle_id"].as_str().unwrap().to_string();
    let forward_port = parsed["local_forward_port"].as_i64().unwrap() as u16;
    println!("FORWARD_PORT {}", forward_port);

    // Passive side drives pings from its WG port through its forward port.
    if role == "passive" {
        std::thread::sleep(Duration::from_secs(3));
        let local = format!("127.0.0.1:{}", wg_port);
        let target = format!("127.0.0.1:{}", forward_port);
        let sender = UdpSocket::bind(local).expect("bind sender");
        let reader = sender.try_clone().expect("clone sender");
        let reader_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, _)) = reader.recv_from(&mut buf) else { return };
                println!("PONG {:?}", String::from_utf8_lossy(&buf[..n]));
            }
        });
        let deadline = Instant::now() + Duration::from_secs(40);
        while Instant::now() < deadline {
            let _ = sender.send_to(b"ping", &target);
            std::thread::sleep(Duration::from_secs(1));
        }
        let _ = reader_thread.join();
    }

    std::thread::sleep(Duration::from_secs(45));
    let stop = serde_json::json!({"handle_id": handle_id}).to_string();
    let out = call(StopUdpTunnel, &stop);
    println!("STOP {}", out);
    let _ = echo_thread.join();
}
