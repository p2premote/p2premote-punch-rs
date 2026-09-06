//! p2premote-punch-rs: Rust rewrite of the p2premote-punch punchffi C ABI.
//!
//! The ABI is JSON-string-in / JSON-string-out: every exported function takes
//! a NUL-terminated C string and returns a malloc'd C string that the caller
//! releases with [`FreeCString`]. See punchffi/main.go in the Go project for
//! the contract this mirrors.

mod easyp2p;
mod handles;
mod platform;
mod runtime;
mod subnet_router;
mod types;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use types::*;

const NULL_INPUT: &str = r#"{"ok":false,"error":"input is null"}"#;

fn alloc_cstring(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new(r#"{"ok":false,"error":"result contains NUL byte"}"#).unwrap())
        .into_raw()
}

unsafe fn input_to_string(input: *const c_char) -> Option<String> {
    if input.is_null() {
        return None;
    }
    let bytes = CStr::from_ptr(input).to_bytes();
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn json_err(prefix: &str, err: serde_json::Error) -> String {
    format!("{}: {}", prefix, err)
}

// ============ UDP tunnel ============

fn handle_start_udp_tunnel_json(input: &str) -> String {
    let req: UdpTunnelInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            let result = UdpTunnelResult {
                ok: false,
                error: json_err("invalid input json", err),
                ..Default::default()
            };
            return encode_tunnel_result(&result);
        }
    };
    let timeout_secs = if req.timeout_secs <= 0 { 45 } else { req.timeout_secs };
    // Go: ctx deadline = timeout + 10s.
    let deadline = std::time::Duration::from_secs(timeout_secs as u64 + 10);

    match runtime::block_on(easyp2p::udp_tunnel::start_udp_tunnel(req, deadline)) {
        Ok(tunnel) => {
            let mut result = tunnel.result;
            let stop = tunnel.stop;
            let handle_id = handles::register_udp_tunnel(result.clone(), Box::new(move || stop.stop()));
            result.handle_id = handle_id;
            encode_tunnel_result(&result)
        }
        Err(err) => match err.tunnel_result {
            Some(result) => encode_tunnel_result(&result),
            None => encode_tunnel_result(&UdpTunnelResult {
                ok: false,
                error: err.to_string(),
                ..Default::default()
            }),
        },
    }
}

fn encode_tunnel_result(result: &UdpTunnelResult) -> String {
    match serde_json::to_string(result) {
        Ok(s) => s,
        Err(_) => r#"{"ok":false,"error":"failed to encode tunnel result"}"#.to_string(),
    }
}

fn encode_stop_tunnel_result(ok: bool, error: &str) -> String {
    let result = StopTunnelResult {
        ok,
        error: error.to_string(),
    };
    match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(_) => r#"{"ok":false,"error":"failed to encode stop tunnel result"}"#.to_string(),
    }
}

fn handle_stop_udp_tunnel_json(input: &str) -> String {
    let req: StopTunnelInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            return encode_stop_tunnel_result(false, &json_err("invalid input json", err))
        }
    };
    if req.handle_id.is_empty() {
        return encode_stop_tunnel_result(false, "handle_id is required");
    }
    handles::stop_udp_tunnel(&req.handle_id);
    encode_stop_tunnel_result(true, "")
}

// ============ subnet router ============

fn encode_subnet_router_result(result: &SubnetRouterResult) -> String {
    match serde_json::to_string(result) {
        Ok(s) => s,
        Err(_) => r#"{"ok":false,"error":"failed to encode subnet router result"}"#.to_string(),
    }
}

fn handle_start_subnet_router_json(input: &str) -> String {
    let req: StartSubnetRouterInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            return encode_subnet_router_result(&SubnetRouterResult {
                ok: false,
                error: json_err("invalid input json", err),
                ..Default::default()
            })
        }
    };
    if req.session_id <= 0 {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "session_id must be positive".into(),
            ..Default::default()
        });
    }
    if req.peer_device_id <= 0 {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "peer_device_id must be positive".into(),
            ..Default::default()
        });
    }
    if req.exposed_lan_cidrs.is_empty() {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "exposed_lan_cidrs is required".into(),
            ..Default::default()
        });
    }
    if req.listen_port <= 0 || req.listen_port > 65535 {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "listen_port must be 1..65535".into(),
            ..Default::default()
        });
    }
    if !req.snat {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "snat=false is not supported".into(),
            ..Default::default()
        });
    }
    if req.listen_ip != "127.0.0.1" {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "listen_ip must be 127.0.0.1".into(),
            ..Default::default()
        });
    }
    if !req.allow_tcp || !req.allow_udp || !req.allow_icmp_echo {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "TCP, UDP, and ICMP echo must all be enabled".into(),
            ..Default::default()
        });
    }
    encode_subnet_router_result(&subnet_router::start_subnet_router(req))
}

fn handle_stop_subnet_router_json(input: &str) -> String {
    let req: StopSubnetRouterInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            return encode_subnet_router_result(&SubnetRouterResult {
                ok: false,
                error: json_err("invalid input json", err),
                ..Default::default()
            })
        }
    };
    if req.handle_id.is_empty() {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "handle_id is required".into(),
            ..Default::default()
        });
    }
    encode_subnet_router_result(&subnet_router::stop_subnet_router(&req.handle_id))
}

fn handle_get_subnet_router_status_json(input: &str) -> String {
    let req: GetSubnetRouterStatusInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            return encode_subnet_router_result(&SubnetRouterResult {
                ok: false,
                error: json_err("invalid input json", err),
                ..Default::default()
            })
        }
    };
    if req.handle_id.is_empty() {
        return encode_subnet_router_result(&SubnetRouterResult {
            ok: false,
            error: "handle_id is required".into(),
            ..Default::default()
        });
    }
    encode_subnet_router_result(&subnet_router::get_subnet_router_status(&req.handle_id))
}

// ============ userspace WireGuard peers ============

fn encode_json(value: &impl serde::Serialize) -> String {
    match serde_json::to_string(value) {
        Ok(s) => s,
        Err(_) => r#"{"ok":false,"error":"failed to encode result"}"#.to_string(),
    }
}

fn handle_start_windows_wg_peer_json(input: &str) -> String {
    let req: StartWindowsWgPeerInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            return encode_json(&WindowsWgPeerResult {
                ok: false,
                error: json_err("invalid input json", err),
                ..Default::default()
            })
        }
    };
    if req.session_id <= 0 || req.peer_device_id <= 0 {
        return encode_json(&WindowsWgPeerResult {
            ok: false,
            error: "session_id and peer_device_id must be positive".into(),
            ..Default::default()
        });
    }
    encode_json(&platform::start_userspace_wg_peer())
}

fn handle_windows_wg_peer_json(input: &str, action: fn() -> WindowsWgPeerResult) -> String {
    let req: WindowsWgPeerHandleInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            return encode_json(&WindowsWgPeerResult {
                ok: false,
                error: json_err("invalid input json", err),
                ..Default::default()
            })
        }
    };
    if req.handle_id.is_empty() {
        return encode_json(&WindowsWgPeerResult {
            ok: false,
            error: "handle_id is required".into(),
            ..Default::default()
        });
    }
    encode_json(&action())
}

fn handle_windows_wg_peer_allowed_json(input: &str) -> String {
    let req: WindowsWgPeerAllowedInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            return encode_json(&WindowsWgPeerResult {
                ok: false,
                error: json_err("invalid input json", err),
                ..Default::default()
            })
        }
    };
    if req.handle_id.is_empty() {
        return encode_json(&WindowsWgPeerResult {
            ok: false,
            error: "handle_id is required".into(),
            ..Default::default()
        });
    }
    encode_json(&platform::set_userspace_wg_peer_allowed())
}

// ============ wgvpn key/IP exchange ============
//
// exmode (aligned with easyp2p EXMODE_*):
//   0 = mutual   active side: broadcast sendData + receive peer
//   1 = waitOnly passive side step 1: only receive, no broadcast
//   2 = reply    passive side step 2: broadcast sendData + receive confirmation

const WGVPN_EXCHANGE_TOPIC_SALT: &str = "wgvpn-kx/";

fn handle_exchange_json(input: &str) -> String {
    let req: ExchangeInput = match serde_json::from_str(input) {
        Ok(req) => req,
        Err(err) => {
            return encode_exchange_result(&ExchangeResult {
                ok: false,
                error: json_err("invalid input json", err),
                ..Default::default()
            })
        }
    };
    if req.token.is_empty() {
        return encode_exchange_result(&ExchangeResult {
            ok: false,
            error: "token is required".into(),
            ..Default::default()
        });
    }
    if !req.role_hint.is_empty() && req.role_hint != "active" && req.role_hint != "passive" {
        return encode_exchange_result(&ExchangeResult {
            ok: false,
            error: format!("unsupported role_hint: {}", req.role_hint),
            ..Default::default()
        });
    }
    let timeout_secs = if req.timeout_secs <= 0 { 60 } else { req.timeout_secs };
    let deadline = std::time::Duration::from_secs(timeout_secs as u64 + 10);
    let timeout = std::time::Duration::from_secs(timeout_secs as u64);

    let result = match runtime::block_on(easyp2p::exchange::mqtt_exchange_payload(
        req.exmode,
        &req.send_data,
        &req.token,
        WGVPN_EXCHANGE_TOPIC_SALT,
        timeout,
        deadline,
    )) {
        Ok(recv) => ExchangeResult {
            ok: true,
            recv_data: recv,
            error: String::new(),
        },
        Err(err) => ExchangeResult {
            ok: false,
            error: err.to_string(),
            recv_data: String::new(),
        },
    };
    encode_exchange_result(&result)
}

fn encode_exchange_result(result: &ExchangeResult) -> String {
    match serde_json::to_string(result) {
        Ok(s) => s,
        Err(_) => r#"{"ok":false,"error":"failed to encode exchange result"}"#.to_string(),
    }
}

// ============ exported C ABI ============

#[no_mangle]
pub extern "C" fn StartUdpTunnel(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_start_udp_tunnel_json(&s)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn StopUdpTunnel(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_stop_udp_tunnel_json(&s)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn StartSubnetRouter(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_start_subnet_router_json(&s)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn StopSubnetRouter(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_stop_subnet_router_json(&s)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn GetSubnetRouterStatus(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_get_subnet_router_status_json(&s)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn GetWgCapabilities(_input: *const c_char) -> *mut c_char {
    alloc_cstring(encode_json(&platform::platform_wg_capabilities()))
}

#[no_mangle]
pub extern "C" fn GenerateWgKeypair(_input: *const c_char) -> *mut c_char {
    alloc_cstring(encode_json(&platform::generate_wg_keypair()))
}

#[no_mangle]
pub extern "C" fn StartWindowsWgPeer(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_start_windows_wg_peer_json(&s)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn StopWindowsWgPeer(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_windows_wg_peer_json(&s, platform::stop_userspace_wg_peer)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn GetWindowsWgPeerStatus(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_windows_wg_peer_json(&s, platform::get_userspace_wg_peer_status)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn SetWindowsWgPeerAllowed(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_windows_wg_peer_allowed_json(&s)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

#[no_mangle]
pub extern "C" fn StopWindowsWgEngine(_input: *const c_char) -> *mut c_char {
    alloc_cstring(encode_json(&platform::stop_userspace_wg_engine()))
}

#[no_mangle]
pub extern "C" fn CleanupWindowsWgPlatform(_input: *const c_char) -> *mut c_char {
    alloc_cstring(encode_json(&platform::cleanup_userspace_wg_platform()))
}

// Generic userspace-WG ABI v2. The Windows-named exports above remain as
// compatibility aliases (kept from the Go ABI).

#[no_mangle]
pub extern "C" fn StartUserspaceWgPeer(input: *const c_char) -> *mut c_char {
    StartWindowsWgPeer(input)
}

#[no_mangle]
pub extern "C" fn StopUserspaceWgPeer(input: *const c_char) -> *mut c_char {
    StopWindowsWgPeer(input)
}

#[no_mangle]
pub extern "C" fn GetUserspaceWgPeerStatus(input: *const c_char) -> *mut c_char {
    GetWindowsWgPeerStatus(input)
}

#[no_mangle]
pub extern "C" fn SetUserspaceWgPeerAllowed(input: *const c_char) -> *mut c_char {
    SetWindowsWgPeerAllowed(input)
}

#[no_mangle]
pub extern "C" fn StopUserspaceWgEngine(input: *const c_char) -> *mut c_char {
    StopWindowsWgEngine(input)
}

#[no_mangle]
pub extern "C" fn CleanupUserspaceWgPlatform(input: *const c_char) -> *mut c_char {
    CleanupWindowsWgPlatform(input)
}

#[no_mangle]
pub extern "C" fn FreeCString(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[no_mangle]
pub extern "C" fn Exchange(input: *const c_char) -> *mut c_char {
    match unsafe { input_to_string(input) } {
        Some(s) => alloc_cstring(handle_exchange_json(&s)),
        None => alloc_cstring(NULL_INPUT.to_string()),
    }
}

// Keep a C-visible marker so accidental double-definition with the Go library
// fails at link time with a clear symbol clash.
#[no_mangle]
pub extern "C" fn P2PremotePunchRsAbiVersion() -> c_int {
    2
}
