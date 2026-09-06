//! Cross-implementation interop driver for p2premote-punch-rs.
//!
//! Usage:
//!   cargo run --release --example interop -- exchange <exmode> <token> <senddata>
//!   cargo run --release --example interop -- tunnel <active|passive> <token> [wgPort]
//!
//! Mirrors the Go harness in p2premote-punch/tmp-interop so the two
//! implementations can be pointed at each other over the real network.

use std::ffi::{CStr, CString};
use std::net::UdpSocket;
use std::os::raw::c_char;
use std::time::{Duration, Instant};

use p2premote_punch::*;

fn call(f: unsafe extern "C" fn(*const c_char) -> *mut c_char, input: &str) -> String {
    let c = CString::new(input).unwrap();
    let raw = unsafe { f(c.as_ptr()) };
    let out = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
    unsafe { FreeCString(raw) };
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
        other => {
            eprintln!("unknown mode {}", other);
            std::process::exit(2);
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
