//! Port of punchffi/subnet_router_backend.go: Linux subnet router =
//! ip_forward sysctl + ref-counted iptables chains (P2PREMOTE-FWD /
//! P2PREMOTE-NAT with per-session MASQUERADE rules).

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

use crate::types::{StartSubnetRouterInput, SubnetRouterResult};

const LINUX_FORWARD_CHAIN: &str = "P2PREMOTE-FWD";
const LINUX_NAT_CHAIN: &str = "P2PREMOTE-NAT";

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct IptablesRule {
    pub table: String,
    pub spec: Vec<String>,
}

fn rule_key(rule: &IptablesRule) -> String {
    format!("{}\x00{}", rule.table, rule.spec.join("\x00"))
}

pub fn build_iptables_args(action: &str, rule: &IptablesRule) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    if !rule.table.is_empty() {
        args.push("-t".into());
        args.push(rule.table.clone());
    }
    if rule.spec.is_empty() {
        return args;
    }
    args.push(action.to_string());
    args.extend(rule.spec.iter().cloned());
    args
}

/// defaultRunOutput: combined output, trimmed, with Go-style error text.
fn run_output(name: &str, args: &[&str]) -> std::result::Result<String, String> {
    let output = Command::new(name)
        .args(args)
        .output()
        .map_err(|e| format!("{} {:?} failed: {}", name, args, e))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let text = text.trim().to_string();
    if !output.status.success() {
        if text.is_empty() {
            return Err(format!("{} {:?} failed: {}", name, args, output.status));
        }
        return Err(format!("{} {:?} failed: {}: {}", name, args, output.status, text));
    }
    Ok(text)
}

fn run_command(name: &str, args: &[&str]) -> std::result::Result<(), String> {
    run_output(name, args).map(|_| ())
}

// ============ global router state ============

struct LinuxRouterState {
    sessions: usize,
    ip_forward_original: String,
    ip_forward_changed: bool,
    rules: HashMap<String, usize>,
}

impl LinuxRouterState {
    fn new() -> Self {
        LinuxRouterState {
            sessions: 0,
            ip_forward_original: String::new(),
            ip_forward_changed: false,
            rules: HashMap::new(),
        }
    }
}

static LINUX_ROUTER_STATE: Mutex<Option<LinuxRouterState>> = Mutex::new(None);

struct SubnetRouterHandle {
    result: SubnetRouterResult,
    stop_rules: Vec<IptablesRule>,
}

static SUBNET_ROUTERS: Mutex<Option<HashMap<String, SubnetRouterHandle>>> = Mutex::new(None);

// ============ platform dispatch ============

pub fn start_subnet_router(req: StartSubnetRouterInput) -> SubnetRouterResult {
    if cfg!(target_os = "linux") {
        start_linux_subnet_router(req)
    } else if cfg!(target_os = "macos") {
        SubnetRouterResult {
            ok: false,
            error: "macOS LAN access is managed by the userspace WireGuard peer API".into(),
            ..Default::default()
        }
    } else {
        SubnetRouterResult {
            ok: false,
            error: format!(
                "subnet router backend is not implemented on {}",
                crate::platform::platform_name()
            ),
            ..Default::default()
        }
    }
}

pub fn stop_subnet_router(handle_id: &str) -> SubnetRouterResult {
    let handle = {
        let mut guard = SUBNET_ROUTERS.lock().unwrap();
        guard.as_mut().and_then(|map| map.remove(handle_id))
    };
    if let Some(handle) = handle {
        if cfg!(target_os = "linux") {
            release_linux_subnet_router(&handle.stop_rules);
        }
    }
    SubnetRouterResult {
        ok: true,
        ..Default::default()
    }
}

pub fn get_subnet_router_status(handle_id: &str) -> SubnetRouterResult {
    let guard = SUBNET_ROUTERS.lock().unwrap();
    match guard.as_ref().and_then(|map| map.get(handle_id)) {
        Some(handle) => handle.result.clone(),
        None => SubnetRouterResult {
            ok: false,
            error: "subnet router handle not found".into(),
            ..Default::default()
        },
    }
}

// ============ Linux backend ============

fn start_linux_subnet_router(req: StartSubnetRouterInput) -> SubnetRouterResult {
    let rules = match acquire_linux_subnet_router(&req) {
        Ok(rules) => rules,
        Err(err) => {
            return SubnetRouterResult {
                ok: false,
                error: err,
                ..Default::default()
            }
        }
    };
    let handle_id = format!("subnet-{}", crate::runtime::now_unix_nanos());
    let result = SubnetRouterResult {
        ok: true,
        handle_id: handle_id.clone(),
        lan_mode: "kernel_snat".into(),
        listen_ip: req.listen_ip.clone(),
        listen_port: req.listen_port,
        started: true,
        advertised_routes: req.exposed_lan_cidrs.clone(),
        ..Default::default()
    };
    let mut guard = SUBNET_ROUTERS.lock().unwrap();
    guard.get_or_insert_with(HashMap::new).insert(
        handle_id,
        SubnetRouterHandle {
            result: result.clone(),
            stop_rules: rules,
        },
    );
    result
}

fn parse_cidr(cidr: &str) -> std::result::Result<(), String> {
    let err = || format!("invalid exposed_lan_cidr {:?}: invalid CIDR address", cidr);
    let Some((ip_str, prefix_str)) = cidr.split_once('/') else {
        return Err(err());
    };
    let ip: IpAddr = ip_str.parse().map_err(|_| err())?;
    let prefix: u32 = prefix_str.parse().map_err(|_| err())?;
    let max = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(err());
    }
    Ok(())
}

fn linux_session_rules(req: &StartSubnetRouterInput) -> std::result::Result<Vec<IptablesRule>, String> {
    let peer = format!("{}/32", req.peer_tail_ip);
    let mut out = Vec::new();
    for cidr in &req.exposed_lan_cidrs {
        parse_cidr(cidr)?;
        let comment = format!("p2premote session {} peer {}", req.session_id, req.peer_device_id);
        out.push(IptablesRule {
            table: String::new(),
            spec: vec![
                LINUX_FORWARD_CHAIN.into(),
                "-s".into(), peer.clone(),
                "-d".into(), cidr.clone(),
                "-m".into(), "comment".into(), "--comment".into(), comment.clone(),
                "-j".into(), "ACCEPT".into(),
            ],
        });
        out.push(IptablesRule {
            table: String::new(),
            spec: vec![
                LINUX_FORWARD_CHAIN.into(),
                "-d".into(), peer.clone(),
                "-s".into(), cidr.clone(),
                "-m".into(), "conntrack".into(), "--ctstate".into(), "ESTABLISHED,RELATED".into(),
                "-m".into(), "comment".into(), "--comment".into(), comment.clone(),
                "-j".into(), "ACCEPT".into(),
            ],
        });
        out.push(IptablesRule {
            table: "nat".into(),
            spec: vec![
                LINUX_NAT_CHAIN.into(),
                "-s".into(), peer.clone(),
                "-d".into(), cidr.clone(),
                "-m".into(), "comment".into(), "--comment".into(), comment.clone(),
                "-j".into(), "MASQUERADE".into(),
            ],
        });
    }
    Ok(out)
}

fn ensure_iptables_rule(rule: &IptablesRule) -> std::result::Result<(), String> {
    let check = build_iptables_args("-C", rule);
    let check_refs: Vec<&str> = check.iter().map(|s| s.as_str()).collect();
    if run_command("iptables", &check_refs).is_ok() {
        return Ok(());
    }
    let append = build_iptables_args("-A", rule);
    let append_refs: Vec<&str> = append.iter().map(|s| s.as_str()).collect();
    run_command("iptables", &append_refs)
        .map_err(|e| format!("install iptables rule failed: {}", e))
}

fn insert_iptables_rule(rule: &IptablesRule) -> std::result::Result<(), String> {
    let check = build_iptables_args("-C", rule);
    let check_refs: Vec<&str> = check.iter().map(|s| s.as_str()).collect();
    if run_command("iptables", &check_refs).is_ok() {
        return Ok(());
    }
    // Jump rules must sit at the top of the built-in chain, before any DROP.
    let insert = build_iptables_args("-I", rule);
    let insert_refs: Vec<&str> = insert.iter().map(|s| s.as_str()).collect();
    run_command("iptables", &insert_refs)
        .map_err(|e| format!("install iptables rule failed: {}", e))
}

fn delete_iptables_rule(rule: &IptablesRule) -> std::result::Result<(), String> {
    let delete = build_iptables_args("-D", rule);
    let refs: Vec<&str> = delete.iter().map(|s| s.as_str()).collect();
    run_command("iptables", &refs)
}

fn prepare_linux_router(state: &mut LinuxRouterState) -> std::result::Result<(), String> {
    for key in ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"] {
        let rp_filter = run_output("sysctl", &["-n", key])
            .map_err(|e| format!("read {} failed: {}", key, e))?;
        if rp_filter.trim() == "1" {
            return Err(format!("{}=1 blocks routed WireGuard traffic; set it to 0 or 2", key));
        }
    }
    let ip_forward = run_output("sysctl", &["-n", "net.ipv4.ip_forward"])
        .map_err(|e| format!("read net.ipv4.ip_forward failed: {}", e))?;
    state.ip_forward_original = ip_forward.trim().to_string();
    if state.ip_forward_original != "1" {
        run_command("sysctl", &["-w", "net.ipv4.ip_forward=1"])
            .map_err(|e| format!("enable ip_forward failed: {}", e))?;
        state.ip_forward_changed = true;
    }
    for (table, name, parent) in [("", LINUX_FORWARD_CHAIN, "FORWARD"), ("nat", LINUX_NAT_CHAIN, "POSTROUTING")] {
        let mut create_args: Vec<&str> = Vec::new();
        if !table.is_empty() {
            create_args.push("-t");
            create_args.push(table);
        }
        create_args.extend(["-N", name]);
        let _ = run_command("iptables", &create_args);
        let jump = IptablesRule {
            table: table.to_string(),
            spec: vec![
                parent.to_string(),
                "-m".into(), "comment".into(), "--comment".into(), "p2premote subnet router".into(),
                "-j".into(), name.to_string(),
            ],
        };
        if let Err(err) = insert_iptables_rule(&jump) {
            teardown_linux_router(state);
            return Err(err);
        }
    }
    Ok(())
}

fn teardown_linux_router(state: &mut LinuxRouterState) {
    for jump in [
        IptablesRule {
            table: String::new(),
            spec: vec![
                "FORWARD".into(),
                "-m".into(), "comment".into(), "--comment".into(), "p2premote subnet router".into(),
                "-j".into(), LINUX_FORWARD_CHAIN.into(),
            ],
        },
        IptablesRule {
            table: "nat".into(),
            spec: vec![
                "POSTROUTING".into(),
                "-m".into(), "comment".into(), "--comment".into(), "p2premote subnet router".into(),
                "-j".into(), LINUX_NAT_CHAIN.into(),
            ],
        },
    ] {
        let _ = delete_iptables_rule(&jump);
    }
    let _ = run_command("iptables", &["-F", LINUX_FORWARD_CHAIN]);
    let _ = run_command("iptables", &["-X", LINUX_FORWARD_CHAIN]);
    let _ = run_command("iptables", &["-t", "nat", "-F", LINUX_NAT_CHAIN]);
    let _ = run_command("iptables", &["-t", "nat", "-X", LINUX_NAT_CHAIN]);
    if state.ip_forward_changed {
        let restore = format!("net.ipv4.ip_forward={}", state.ip_forward_original);
        let _ = run_command("sysctl", &["-w", &restore]);
    }
    state.ip_forward_changed = false;
    state.ip_forward_original = String::new();
}

fn acquire_linux_subnet_router(req: &StartSubnetRouterInput) -> std::result::Result<Vec<IptablesRule>, String> {
    if req.peer_tail_ip.parse::<IpAddr>().is_err() {
        return Err(format!("invalid peer_tail_ip: {}", req.peer_tail_ip));
    }
    let rules = linux_session_rules(req)?;
    let mut guard = LINUX_ROUTER_STATE.lock().unwrap();
    let state = guard.get_or_insert_with(LinuxRouterState::new);
    if state.sessions == 0 {
        prepare_linux_router(state)?;
    }
    let mut acquired: Vec<IptablesRule> = Vec::with_capacity(rules.len());
    for rule in rules {
        let key = rule_key(&rule);
        if state.rules.get(&key).copied().unwrap_or(0) == 0 {
            if let Err(err) = ensure_iptables_rule(&rule) {
                for acquired_rule in acquired.iter().rev() {
                    release_linux_rule(state, acquired_rule);
                }
                if state.sessions == 0 {
                    teardown_linux_router(state);
                }
                return Err(err);
            }
        }
        *state.rules.entry(key).or_insert(0) += 1;
        acquired.push(rule);
    }
    state.sessions += 1;
    Ok(acquired)
}

fn release_linux_subnet_router(rules: &[IptablesRule]) {
    let mut guard = LINUX_ROUTER_STATE.lock().unwrap();
    let state = guard.get_or_insert_with(LinuxRouterState::new);
    for rule in rules.iter().rev() {
        release_linux_rule(state, rule);
    }
    if state.sessions > 0 {
        state.sessions -= 1;
    }
    if state.sessions == 0 {
        teardown_linux_router(state);
    }
}

fn release_linux_rule(state: &mut LinuxRouterState, rule: &IptablesRule) {
    let key = rule_key(rule);
    let count = state.rules.get(&key).copied().unwrap_or(0);
    if count <= 1 {
        if count == 1 {
            let _ = delete_iptables_rule(rule);
        }
        state.rules.remove(&key);
    } else {
        state.rules.insert(key, count - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_iptables_args_matches_go() {
        let rule = IptablesRule {
            table: "nat".into(),
            spec: vec![
                "POSTROUTING".into(),
                "-s".into(),
                "100.99.71.2/32".into(),
                "-d".into(),
                "192.168.10.0/24".into(),
                "-j".into(),
                "MASQUERADE".into(),
            ],
        };
        let got = build_iptables_args("-I", &rule);
        let want = "-t nat -I POSTROUTING -s 100.99.71.2/32 -d 192.168.10.0/24 -j MASQUERADE";
        assert_eq!(got.join(" "), want);
    }

    #[test]
    fn session_rules_shape() {
        let req = StartSubnetRouterInput {
            session_id: 59,
            peer_device_id: 58,
            peer_tail_ip: "100.99.71.2".into(),
            exposed_lan_cidrs: vec!["192.168.10.0/24".into()],
            ..Default::default()
        };
        let rules = linux_session_rules(&req).unwrap();
        assert_eq!(rules.len(), 3);
        assert!(rules[2].spec.contains(&"MASQUERADE".to_string()));
        let comment = format!("p2premote session {} peer {}", 59, 58);
        assert!(rules[0].spec.contains(&comment));
    }

    #[test]
    fn invalid_cidr_rejected() {
        let req = StartSubnetRouterInput {
            peer_tail_ip: "100.99.71.2".into(),
            exposed_lan_cidrs: vec!["192.168.10.0".into()],
            ..Default::default()
        };
        assert!(linux_session_rules(&req).is_err());
    }
}
