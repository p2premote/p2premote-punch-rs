//! Mirrors punchffi/main_test.go against the exported C ABI.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use p2premote_punch::*;

fn call(f: unsafe extern "C" fn(*const c_char) -> *mut c_char, input: &str) -> String {
    let c_input = CString::new(input).unwrap();
    let raw = unsafe { f(c_input.as_ptr()) };
    let out = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
    FreeCString(raw);
    out
}

fn json_str(raw: &str, field: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    v.get(field).cloned().unwrap_or(serde_json::Value::Null).to_string()
}

fn json_bool(raw: &str, field: &str) -> bool {
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    v.get(field).and_then(|f| f.as_bool()).unwrap_or(false)
}

// serde_json is a dev-only dependency for these tests.
#[test]
fn start_udp_tunnel_rejects_invalid_json() {
    let raw = call(StartUdpTunnel, "{");
    assert!(!json_bool(&raw, "ok"));
}

#[test]
fn start_udp_tunnel_requires_token() {
    let raw = call(StartUdpTunnel, r#"{"network":"udp4","timeout_secs":1,"remote_target_port":51820}"#);
    assert!(!json_bool(&raw, "ok"));
    assert_ne!(json_str(&raw, "error"), "\"\"");
}

#[test]
fn start_udp_tunnel_rejects_relay() {
    let raw = call(StartUdpTunnel, r#"{"token":"tok","network":"udp4","remote_target_port":51820,"allow_relay":true}"#);
    assert!(!json_bool(&raw, "ok"));
}

#[test]
fn start_udp_tunnel_rejects_unknown_network() {
    let raw = call(StartUdpTunnel, r#"{"token":"tok","network":"tcp9","remote_target_port":51820}"#);
    assert!(!json_bool(&raw, "ok"));
    let err = json_str(&raw, "error");
    assert!(err.contains("unsupported network"), "unexpected error: {}", err);
}

#[test]
fn start_udp_tunnel_accepts_any_network() {
    // "any" must clear the network gate: pair it with allow_relay so the
    // request still fails offline, but on the relay check (which runs after
    // the network validation).
    let raw = call(StartUdpTunnel, r#"{"token":"tok","network":"any","remote_target_port":51820,"allow_relay":true}"#);
    assert!(!json_bool(&raw, "ok"));
    let err = json_str(&raw, "error");
    assert!(err.contains("relay"), "network gate should accept any, got: {}", err);
}

#[test]
fn start_udp_tunnel_rejects_unknown_traversal_mode() {
    let raw = call(
        StartUdpTunnel,
        r#"{"token":"tok","role_hint":"active","traversal_mode":"fastest","network":"udp4","remote_target_port":51820}"#,
    );
    assert!(!json_bool(&raw, "ok"));
    let err = json_str(&raw, "error");
    assert!(err.contains("traversal_mode"), "unexpected error: {}", err);
}

#[test]
fn null_input_returns_error_json() {
    let raw = StartUdpTunnel(std::ptr::null());
    let out = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
    FreeCString(raw);
    assert_eq!(out, r#"{"ok":false,"error":"input is null"}"#);
}

#[test]
fn stop_udp_tunnel_is_idempotent() {
    let raw = call(StopUdpTunnel, r#"{"handle_id":"missing"}"#);
    assert!(json_bool(&raw, "ok"));
}

#[test]
fn stop_udp_tunnel_requires_handle_id() {
    let raw = call(StopUdpTunnel, r#"{}"#);
    assert!(!json_bool(&raw, "ok"));
}

#[test]
fn start_subnet_router_rejects_missing_routes() {
    let raw = call(StartSubnetRouter, r#"{"session_id":59,"peer_device_id":58,"listen_port":51820}"#);
    assert!(!json_bool(&raw, "ok"));
    assert!(json_str(&raw, "error").contains("exposed_lan_cidrs"));
}

#[test]
fn start_subnet_router_rejects_partial_protocol_set() {
    let raw = call(
        StartSubnetRouter,
        r#"{
            "session_id":59,
            "peer_device_id":58,
            "listen_ip":"127.0.0.1",
            "listen_port":51820,
            "exposed_lan_cidrs":["192.168.10.0/24"],
            "snat":true,
            "allow_tcp":true,
            "allow_udp":false,
            "allow_icmp_echo":true
        }"#,
    );
    assert!(!json_bool(&raw, "ok"));
    assert!(json_str(&raw, "error").contains("must all be enabled"));
}

#[test]
fn start_subnet_router_rejects_bad_listen_ip() {
    let raw = call(
        StartSubnetRouter,
        r#"{"session_id":59,"peer_device_id":58,"listen_ip":"0.0.0.0","listen_port":51820,"exposed_lan_cidrs":["10.0.0.0/8"],"snat":true,"allow_tcp":true,"allow_udp":true,"allow_icmp_echo":true}"#,
    );
    assert!(!json_bool(&raw, "ok"));
    assert!(json_str(&raw, "error").contains("listen_ip"));
}

#[test]
fn stop_subnet_router_is_idempotent() {
    let raw = call(StopSubnetRouter, r#"{"handle_id":"missing"}"#);
    assert!(json_bool(&raw, "ok"));
}

#[test]
fn get_subnet_router_status_requires_handle() {
    let raw = call(GetSubnetRouterStatus, r#"{}"#);
    assert!(!json_bool(&raw, "ok"));
    assert!(json_str(&raw, "error").contains("handle_id"));
}

#[test]
fn wg_capabilities_shape() {
    let raw = call(GetWgCapabilities, "");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(v["abi_version"], serde_json::json!(2));
    assert!(v["platform"].is_string());
}

#[test]
fn keypair_reports_platform_support_state() {
    let raw = call(GenerateWgKeypair, "");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    if cfg!(any(target_os = "linux", target_os = "windows", target_os = "macos")) {
        // The userspace WG data plane is not ported yet: parity with Go's
        // behavior on platforms without it.
        assert_eq!(v["ok"], serde_json::json!(false));
    }
}

#[test]
fn userspace_wg_aliases_match_windows_named_exports() {
    for (userspace, windows) in [
        (StartUserspaceWgPeer as unsafe extern "C" fn(*const c_char) -> *mut c_char, StartWindowsWgPeer as unsafe extern "C" fn(*const c_char) -> *mut c_char),
        (StopUserspaceWgPeer, StopWindowsWgPeer),
        (GetUserspaceWgPeerStatus, GetWindowsWgPeerStatus),
        (SetUserspaceWgPeerAllowed, SetWindowsWgPeerAllowed),
        (StopUserspaceWgEngine, StopWindowsWgEngine),
        (CleanupUserspaceWgPlatform, CleanupWindowsWgPlatform),
    ] {
        let a = call(userspace, r#"{"handle_id":"h","session_id":1,"peer_device_id":1}"#);
        let b = call(windows, r#"{"handle_id":"h","session_id":1,"peer_device_id":1}"#);
        assert_eq!(a, b);
        assert!(!json_bool(&a, "ok"));
    }
}

#[test]
fn exchange_validation() {
    let raw = call(Exchange, r#"{"send_data":"x"}"#);
    assert!(!json_bool(&raw, "ok"));
    assert!(json_str(&raw, "error").contains("token"));
    let raw = call(Exchange, r#"{"token":"t","role_hint":"wrong"}"#);
    assert!(!json_bool(&raw, "ok"));
    assert!(json_str(&raw, "error").contains("role_hint"));
}

#[test]
fn free_c_string_accepts_null() {
    FreeCString(std::ptr::null_mut());
}
