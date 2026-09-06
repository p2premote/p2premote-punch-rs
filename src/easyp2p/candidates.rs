//! Candidate construction/selection from exchanged STUN addresses
//! (p2p.go buildBaseP2PCandidates / SelectRole / SortP2PAddressInfos and
//! lan_probe.go helpers).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use super::netx;

/// PunchingAddressInfo goes over the wire inside exchangeAddressPayload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchingAddressInfo {
    #[serde(rename = "network", default)]
    pub network: String,
    #[serde(rename = "nattype", default)]
    pub nat_type: String,
    #[serde(rename = "lan", default)]
    pub lan: String,
    #[serde(rename = "nat", default)]
    pub nat: String,
}

impl Default for PunchingAddressInfo {
    fn default() -> Self {
        PunchingAddressInfo {
            network: String::new(),
            nat_type: String::new(),
            lan: String::new(),
            nat: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExchangeAddressPayload {
    #[serde(rename = "addrs", default)]
    pub addresses: Vec<PunchingAddressInfo>,
    #[serde(rename = "pk", default)]
    pub pub_key: String,
    #[serde(rename = "caps", skip_serializing_if = "Vec::is_empty", default)]
    pub caps: Vec<String>,
}

/// Internal candidate pair.
#[derive(Debug, Clone, Default)]
pub struct P2PAddressInfo {
    pub network: String,
    pub local_lan: String,
    pub local_nat: String,
    pub local_nat_type: String,
    pub remote_lan: String,
    pub remote_nat: String,
    pub remote_nat_type: String,
    pub lan_probe_only: bool,
    pub remote_udp4_nat_alternatives: Vec<String>,
}

/// p2premote modification: structured traversal diagnostics.
#[derive(Debug, Clone, Default)]
pub struct P2PAttemptDetails {
    pub network: String,
    pub is_client: bool,
    pub local_lan: String,
    pub local_nat: String,
    pub local_nat_type: String,
    pub remote_lan: String,
    pub remote_nat: String,
    pub remote_nat_type: String,
}

pub fn has_cap(caps: &[String], cap: &str) -> bool {
    caps.iter().any(|c| c == cap)
}

// ============ IP helpers ============

pub fn ip_is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ip4_is_private(v4),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn ip4_is_private(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

#[allow(dead_code)]
pub fn ip_is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

#[allow(dead_code)]
pub fn ip_is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// extractIP: host part of "host:port" (bare IPs pass through).
pub fn extract_ip(addr: &str) -> String {
    match netx::split_host_port(addr) {
        Some((host, _)) => host,
        None => {
            if addr.parse::<IpAddr>().is_ok() {
                addr.to_string()
            } else {
                String::new()
            }
        }
    }
}

/// IsSameLAN port of p2p.go: loopback pairs, private-range pairs, same /24 v4
/// fallback, same /64 v6.
pub fn is_same_lan(ip1: &str, ip2: &str) -> bool {
    let parsed1: Option<IpAddr> = ip1.parse().ok();
    let parsed2: Option<IpAddr> = ip2.parse().ok();
    let (Some(a), Some(b)) = (parsed1, parsed2) else {
        return false;
    };

    if a.is_loopback() && b.is_loopback() {
        return true;
    }

    if let (IpAddr::V4(a4), IpAddr::V4(b4)) = (a, b) {
        if ip4_is_private(a4) && ip4_is_private(b4) {
            let (x, y) = (a4.octets(), b4.octets());
            if x[0] == 10 && y[0] == 10 {
                return true;
            }
            if x[0] == 172 && y[0] == 172 && (16..=31).contains(&x[1]) && (16..=31).contains(&y[1]) {
                return x[1] == y[1];
            }
            if x[0] == 192 && x[1] == 168 && y[0] == 192 && y[1] == 168 {
                return true;
            }
        }
        let parts1: Vec<&str> = ip1.split('.').collect();
        let parts2: Vec<&str> = ip2.split('.').collect();
        if parts1.len() == 4 && parts2.len() == 4 {
            return parts1[0] == parts2[0] && parts1[1] == parts2[1] && parts1[2] == parts2[2];
        }
        return false;
    }

    if let (IpAddr::V6(a6), IpAddr::V6(b6)) = (a, b) {
        if ip_is_private(a) && ip_is_private(b) {
            return a6.segments()[..4] == b6.segments()[..4];
        }
    }
    false
}

/// CompareP2PAddresses → (sameNATIP, similarLAN).
pub fn compare_p2p_addresses(info: &P2PAddressInfo) -> (bool, bool) {
    let nat_ip1 = extract_ip(&info.local_nat);
    let nat_ip2 = extract_ip(&info.remote_nat);
    let mut same_nat_ip = !nat_ip1.is_empty() && !nat_ip2.is_empty() && nat_ip1 == nat_ip2;
    if !same_nat_ip {
        same_nat_ip = is_same_lan(&nat_ip1, &nat_ip2);
    }
    let lan_ip1 = extract_ip(&info.local_lan);
    let lan_ip2 = extract_ip(&info.remote_lan);
    let similar_lan = is_same_lan(&lan_ip1, &lan_ip2);
    (same_nat_ip, similar_lan)
}

pub fn both_private_lan(lan_addr1: &str, lan_addr2: &str) -> bool {
    let ip1 = extract_ip(lan_addr1);
    let ip2 = extract_ip(lan_addr2);
    let (Some(p1), Some(p2)): (Option<IpAddr>, Option<IpAddr>) = (ip1.parse().ok(), ip2.parse().ok()) else {
        return false;
    };
    ip_is_private(p1) && ip_is_private(p2)
}

fn is_gateway_with_internal(info: &P2PAddressInfo) -> bool {
    let local_nat_ip = extract_ip(&info.local_nat);
    let remote_nat_ip = extract_ip(&info.remote_nat);
    if local_nat_ip.is_empty() || remote_nat_ip.is_empty() || local_nat_ip != remote_nat_ip {
        return false;
    }
    let local_lan_ip = extract_ip(&info.local_lan);
    let remote_lan_ip = extract_ip(&info.remote_lan);
    let local_is_gateway = local_lan_ip == local_nat_ip;
    let remote_is_gateway = remote_lan_ip == remote_nat_ip;
    if local_is_gateway && !remote_is_gateway {
        return remote_lan_ip.parse::<IpAddr>().map(ip_is_private).unwrap_or(false);
    }
    if remote_is_gateway && !local_is_gateway {
        return local_lan_ip.parse::<IpAddr>().map(ip_is_private).unwrap_or(false);
    }
    false
}

pub fn should_try_lan_probe(in_same_lan: bool, round: i32, info: &P2PAddressInfo) -> bool {
    if in_same_lan {
        return false;
    }
    if round != 1 {
        return false;
    }
    let local_lan_ip = extract_ip(&info.local_lan);
    let remote_lan_ip = extract_ip(&info.remote_lan);
    if local_lan_ip.is_empty() || remote_lan_ip.is_empty() {
        return false;
    }
    if is_gateway_with_internal(info) {
        return true;
    }
    let (Some(lp), Some(rp)): (Option<IpAddr>, Option<IpAddr>) =
        (local_lan_ip.parse().ok(), remote_lan_ip.parse().ok())
    else {
        return false;
    };
    if !ip_is_private(lp) || !ip_is_private(rp) {
        return false;
    }
    if info.local_lan == info.local_nat && info.remote_lan == info.remote_nat {
        return false;
    }
    true
}

// ============ candidate building ============

pub struct LanProbeCandidate {
    pub info: P2PAddressInfo,
    pub local_order: usize,
    pub remote_order: usize,
}

pub struct BuiltCandidates {
    pub final_results: Vec<P2PAddressInfo>,
    pub have_common_network: bool,
}

pub fn build_base_p2p_candidates(
    local_addresses: &[PunchingAddressInfo],
    remote_addresses: &[PunchingAddressInfo],
    peer_supports_lan_probe: bool,
) -> (Vec<LanProbeCandidate>, BuiltCandidates) {
    let mut final_results = Vec::new();
    let mut lan_probe_candidates = Vec::new();
    let mut have_common_network = false;

    for (local_order, my) in local_addresses.iter().enumerate() {
        let network = &my.network;
        for (remote_order, remote) in remote_addresses.iter().enumerate() {
            if &remote.network != network {
                continue;
            }
            have_common_network = true;

            let mut item = P2PAddressInfo {
                network: network.clone(),
                local_lan: my.lan.clone(),
                local_nat: my.nat.clone(),
                local_nat_type: my.nat_type.clone(),
                remote_lan: remote.lan.clone(),
                remote_nat: remote.nat.clone(),
                remote_nat_type: remote.nat_type.clone(),
                lan_probe_only: false,
                remote_udp4_nat_alternatives: Vec::new(),
            };

            if get_nat_type_priority(&my.nat_type) == 0 || get_nat_type_priority(&remote.nat_type) == 0 {
                continue;
            }
            let (same_nat, similar_lan) = compare_p2p_addresses(&item);

            if my.nat_type == "symm" && remote.nat_type == "symm" {
                if !same_nat || !similar_lan {
                    if peer_supports_lan_probe
                        && network.starts_with("tcp")
                        && both_private_lan(&my.lan, &remote.lan)
                    {
                        item.lan_probe_only = true;
                        lan_probe_candidates.push(LanProbeCandidate {
                            info: item,
                            local_order,
                            remote_order,
                        });
                    }
                    continue;
                }
            }

            if network.starts_with("tcp") && (!same_nat || !similar_lan) {
                if my.nat_type != "easy" && remote.nat_type != "easy" {
                    if peer_supports_lan_probe && both_private_lan(&my.lan, &remote.lan) {
                        item.lan_probe_only = true;
                        lan_probe_candidates.push(LanProbeCandidate {
                            info: item,
                            local_order,
                            remote_order,
                        });
                    }
                    continue;
                }
            }

            final_results.push(item);
        }
    }
    (
        lan_probe_candidates,
        BuiltCandidates {
            final_results,
            have_common_network,
        },
    )
}

fn canonical_lan_probe_candidate_key(info: &P2PAddressInfo) -> String {
    let mut local_endpoint = format!(
        "{}\x00{}\x00{}",
        info.local_nat_type, info.local_lan, info.local_nat
    );
    let mut remote_endpoint = format!(
        "{}\x00{}\x00{}",
        info.remote_nat_type, info.remote_lan, info.remote_nat
    );
    if local_endpoint > remote_endpoint {
        std::mem::swap(&mut local_endpoint, &mut remote_endpoint);
    }
    format!("{}\x00{}\x00{}", info.network, local_endpoint, remote_endpoint)
}

pub fn select_lan_probe_candidate(
    mut candidates: Vec<LanProbeCandidate>,
    peer_supports_canonical: bool,
) -> Option<P2PAddressInfo> {
    if candidates.is_empty() {
        return None;
    }
    if !peer_supports_canonical {
        let mut selected = 0usize;
        for (i, candidate) in candidates.iter().enumerate().skip(1) {
            let s = &candidates[selected];
            if candidate.remote_order < s.remote_order
                || (candidate.remote_order == s.remote_order && candidate.local_order < s.local_order)
            {
                selected = i;
            }
        }
        return Some(candidates.swap_remove(selected).info);
    }
    let mut selected_key = canonical_lan_probe_candidate_key(&candidates[0].info);
    let mut selected = 0usize;
    for (i, candidate) in candidates.iter().enumerate().skip(1) {
        let key = canonical_lan_probe_candidate_key(&candidate.info);
        if key < selected_key {
            selected = i;
            selected_key = key;
        }
    }
    Some(candidates.swap_remove(selected).info)
}

// ============ role & priorities ============

pub fn select_role(info: &P2PAddressInfo, local_md5_seed: &str) -> bool {
    // ROLE_DEBUG env parity.
    match std::env::var("ROLE_DEBUG").as_deref() {
        Ok("C") => return true,
        Ok("S") => return false,
        _ => {}
    }
    if info.local_nat_type == "easy" && info.remote_nat_type == "hard" {
        return false;
    } else if info.local_nat_type == "hard" && info.remote_nat_type == "easy" {
        return true;
    } else if info.local_nat_type == "easy" && info.remote_nat_type == "symm" {
        return false;
    } else if info.local_nat_type == "symm" && info.remote_nat_type == "easy" {
        return true;
    } else if info.local_nat_type == "hard" && info.remote_nat_type == "symm" {
        return true;
    } else if info.local_nat_type == "symm" && info.remote_nat_type == "hard" {
        return false;
    }
    // Go compares md5(localLAN+localNAT) vs md5(remoteLAN+remoteNAT) — both
    // sides compute the same two hashes, so the comparison is symmetric.
    let a = super::crypto::calculate_md5(&format!("{}{}", info.local_lan, info.local_nat));
    let b = super::crypto::calculate_md5(&format!("{}{}", info.remote_lan, info.remote_nat));
    let _ = local_md5_seed;
    a <= b
}

pub fn get_network_priority(network: &str) -> i32 {
    match network {
        "tcp6" => 4,
        "tcp4" => 3,
        "udp6" => 2,
        "udp4" => 1,
        _ => 0,
    }
}

pub fn get_nat_type_priority(nat_type: &str) -> i32 {
    match nat_type {
        "easy" => 4,
        "hard" => 3,
        "symm" => 2,
        "relay" => 1,
        _ => 0,
    }
}

pub fn sort_p2p_address_infos(addrs: Vec<P2PAddressInfo>) -> Vec<P2PAddressInfo> {
    let mut sorted = addrs;
    sorted.sort_by(|a, b| {
        let net_a = get_network_priority(&a.network);
        let net_b = get_network_priority(&b.network);
        if net_a != net_b {
            return net_b.cmp(&net_a);
        }
        let nat_a = get_nat_type_priority(&a.local_nat_type) + get_nat_type_priority(&a.remote_nat_type);
        let nat_b = get_nat_type_priority(&b.local_nat_type) + get_nat_type_priority(&b.remote_nat_type);
        if nat_a != nat_b {
            return nat_b.cmp(&nat_a);
        }
        let mut a1 = format!("{}|{}", a.local_nat, a.local_lan);
        let mut a2 = format!("{}|{}", a.remote_nat, a.remote_lan);
        if a1 > a2 {
            std::mem::swap(&mut a1, &mut a2);
        }
        let mut b1 = format!("{}|{}", b.local_nat, b.local_lan);
        let mut b2 = format!("{}|{}", b.remote_nat, b.remote_lan);
        if b1 > b2 {
            std::mem::swap(&mut b1, &mut b2);
        }
        if a1 != b1 {
            return a1.cmp(&b1);
        }
        a2.cmp(&b2)
    });
    sorted
}

pub fn count_unique_public_ips(infos: &[PunchingAddressInfo], ver: &str) -> usize {
    let mut unique: HashSet<String> = HashSet::new();
    for info in infos {
        if !info.network.ends_with(ver) {
            continue;
        }
        if info.nat_type == "relay" {
            continue;
        }
        let host = netx::split_host_port(&info.nat)
            .map(|(h, _)| h)
            .unwrap_or_else(|| info.nat.clone());
        unique.insert(host);
    }
    unique.len()
}

pub fn count_relay_ipv4(infos: &[PunchingAddressInfo]) -> usize {
    let mut unique: HashSet<String> = HashSet::new();
    for info in infos {
        if !info.network.ends_with('4') {
            continue;
        }
        if info.nat_type != "relay" {
            continue;
        }
        let host = netx::split_host_port(&info.nat)
            .map(|(h, _)| h)
            .unwrap_or_else(|| info.nat.clone());
        unique.insert(host);
    }
    unique.len()
}

/// collect per-network unique NAT addresses for udp4 alternatives filling.
pub fn collect_udp4_nat_alternatives(results: &mut [P2PAddressInfo]) {
    let mut remote_udp4_nats: HashMap<String, ()> = HashMap::new();
    for info in results.iter() {
        if info.network == "udp4"
            && !info.lan_probe_only
            && info.local_nat_type != "relay"
            && info.remote_nat_type != "relay"
        {
            remote_udp4_nats.insert(info.remote_nat.clone(), ());
        }
    }
    for info in results.iter_mut() {
        if info.network == "udp4"
            && !info.lan_probe_only
            && info.local_nat_type != "relay"
            && info.remote_nat_type != "relay"
        {
            for addr in remote_udp4_nats.keys() {
                if *addr != info.remote_nat {
                    info.remote_udp4_nat_alternatives.push(addr.clone());
                }
            }
        }
    }
}
