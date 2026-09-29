//! Handle registries for long-lived FFI objects (UDP tunnels).
//! Mirrors punchffi/main.go's `tunnels` map: idempotent stop, handle ids
//! formatted as `udp-<unix-nanos>`.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::types::UdpTunnelResult;

pub struct UdpTunnelEntry {
    pub result: UdpTunnelResult,
    pub stop: Box<dyn Fn() + Send + Sync>,
}

static TUNNELS: Mutex<Option<HashMap<String, UdpTunnelEntry>>> = Mutex::new(None);

pub fn register_udp_tunnel(result: UdpTunnelResult, stop: Box<dyn Fn() + Send + Sync>) -> String {
    let handle_id = format!("udp-{}", crate::runtime::now_unix_nanos());
    let mut guard = TUNNELS.lock().unwrap();
    guard
        .get_or_insert_with(HashMap::new)
        .insert(handle_id.clone(), UdpTunnelEntry { result, stop });
    handle_id
}

/// Remove the handle and stop it. Unknown handles are a no-op (idempotent ok).
pub fn stop_udp_tunnel(handle_id: &str) {
    let mut guard = TUNNELS.lock().unwrap();
    if let Some(map) = guard.as_mut() {
        if let Some(entry) = map.remove(handle_id) {
            (entry.stop)();
        }
    }
}
