//! JSON request/response types for the punchffi C ABI.
//! Field names, types and omitempty semantics mirror punchffi/main.go 1:1.

use serde::{Deserialize, Serialize};

#[allow(dead_code)]
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}
fn is_empty_string(v: &String) -> bool {
    v.is_empty()
}
fn is_empty_vec(v: &Vec<String>) -> bool {
    v.is_empty()
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct UdpTunnelInput {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub role_hint: String,
    #[serde(default)]
    pub traversal_mode: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub timeout_secs: i32,
    #[serde(default)]
    pub bind_ip: String,
    #[serde(default)]
    pub local_listen_ip: String,
    #[serde(default)]
    pub local_listen_port: i32,
    #[serde(default)]
    pub remote_target_ip: String,
    #[serde(default)]
    pub remote_target_port: i32,
    #[serde(default)]
    pub allow_relay: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct StopTunnelInput {
    #[serde(default)]
    pub handle_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpTunnelResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub handle_id: String,
    #[serde(default)]
    pub local_forward_addr: String,
    #[serde(default)]
    pub local_forward_port: i32,
    #[serde(default)]
    pub peer_endpoint: String,
    #[serde(default)]
    pub local_nat_type: String,
    #[serde(default)]
    pub remote_nat_type: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub network: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub selected_traversal: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub transport_mode: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub local_lan_addr: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub local_nat_addr: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub remote_lan_addr: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub remote_nat_addr: String,
    #[serde(default)]
    pub is_client: bool,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub attempts: i32,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub error: String,
}

impl Default for UdpTunnelResult {
    fn default() -> Self {
        Self {
            ok: false,
            handle_id: String::new(),
            local_forward_addr: String::new(),
            local_forward_port: 0,
            peer_endpoint: String::new(),
            local_nat_type: String::new(),
            remote_nat_type: String::new(),
            network: String::new(),
            selected_traversal: String::new(),
            transport_mode: String::new(),
            local_lan_addr: String::new(),
            local_nat_addr: String::new(),
            remote_lan_addr: String::new(),
            remote_nat_addr: String::new(),
            is_client: false,
            attempts: 0,
            error: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StopTunnelResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub error: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[allow(dead_code)]
pub struct StartSubnetRouterInput {
    #[serde(default)]
    pub session_id: i64,
    #[serde(default)]
    pub peer_device_id: i64,
    #[serde(default)]
    pub wg_private_key: String,
    #[serde(default)]
    pub peer_public_key: String,
    #[serde(default)]
    pub tail_ip: String,
    #[serde(default)]
    pub peer_tail_ip: String,
    #[serde(default)]
    pub peer_endpoint: String,
    #[serde(default)]
    pub listen_ip: String,
    #[serde(default)]
    pub listen_port: i32,
    #[serde(default)]
    pub exposed_lan_cidrs: Vec<String>,
    #[serde(default)]
    pub snat: bool,
    #[serde(default)]
    pub allow_tcp: bool,
    #[serde(default)]
    pub allow_udp: bool,
    #[serde(default)]
    pub allow_icmp_echo: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct StopSubnetRouterInput {
    #[serde(default)]
    pub handle_id: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct GetSubnetRouterStatusInput {
    #[serde(default)]
    pub handle_id: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SubnetRouterResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub handle_id: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub lan_mode: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub listen_ip: String,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub listen_port: i32,
    #[serde(default)]
    pub started: bool,
    #[serde(default)]
    pub tcp_sessions: i32,
    #[serde(default)]
    pub udp_sessions: i32,
    #[serde(default)]
    pub wg_rx_packets: i64,
    #[serde(default)]
    pub wg_tx_packets: i64,
    #[serde(default)]
    pub icmp_success: i64,
    #[serde(default)]
    pub icmp_failed: i64,
    #[serde(default)]
    pub rejected_flows: i64,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub last_error: String,
    #[serde(skip_serializing_if = "is_empty_vec")]
    pub advertised_routes: Vec<String>,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub error: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[allow(dead_code)]
pub struct StartWindowsWgPeerInput {
    #[serde(default)]
    pub session_id: i64,
    #[serde(default)]
    pub peer_device_id: i64,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub wg_private_key: String,
    #[serde(default)]
    pub peer_public_key: String,
    #[serde(default)]
    pub local_tail_ip: String,
    #[serde(default)]
    pub peer_tail_ip: String,
    #[serde(default)]
    pub peer_endpoint: String,
    #[serde(default)]
    pub listen_ip: String,
    #[serde(default)]
    pub listen_port: i32,
    #[serde(default)]
    pub routes: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct WindowsWgPeerHandleInput {
    #[serde(default)]
    pub handle_id: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[allow(dead_code)]
pub struct WindowsWgPeerAllowedInput {
    #[serde(default)]
    pub handle_id: String,
    #[serde(default)]
    pub allowed: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct WindowsWgPeerResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub handle_id: String,
    #[serde(default)]
    pub started: bool,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub role: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub local_tail_ip: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub peer_tail_ip: String,
    #[serde(default)]
    pub last_handshake_at: i64,
    #[serde(default)]
    pub rx_bytes: i64,
    #[serde(default)]
    pub tx_bytes: i64,
    #[serde(default)]
    pub rx_packets: i64,
    #[serde(default)]
    pub tx_packets: i64,
    #[serde(default)]
    pub rx_batches: i64,
    #[serde(default)]
    pub tx_batches: i64,
    #[serde(default)]
    pub tcp_sessions: i32,
    #[serde(default)]
    pub udp_sessions: i32,
    #[serde(default)]
    pub icmp_success: i64,
    #[serde(default)]
    pub icmp_failed: i64,
    #[serde(default)]
    pub rejected_flows: i64,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub last_error: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WgCapabilitiesResult {
    pub ok: bool,
    pub abi_version: i32,
    pub platform: String,
    #[serde(default)]
    pub userspace_wg: bool,
    #[serde(default)]
    pub hybrid_tun: bool,
    #[serde(default)]
    pub wintun: bool,
    #[serde(default)]
    pub native_tun: bool,
    #[serde(default)]
    pub netstack_proxy: bool,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub error: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct WgKeypairResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub private_key: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub public_key: String,
    #[serde(skip_serializing_if = "is_empty_string")]
    pub error: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ExchangeInput {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub exmode: i32,
    #[serde(default)]
    pub send_data: String,
    #[serde(default)]
    pub role_hint: String,
    #[serde(default)]
    pub timeout_secs: i32,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ExchangeResult {
    pub ok: bool,
    #[serde(default)]
    pub recv_data: String,
    // Go: `json:"error"` without omitempty.
    pub error: String,
}
