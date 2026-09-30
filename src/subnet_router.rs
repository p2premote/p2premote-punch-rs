//! Linux subnet router backend (p2premote extension — gonc upstream has no
//! subnet-routing code, so this file is not bound by the line-by-line port
//! discipline; simplified 2026-09-30 with maintainer approval).
//!
//! Set-diff reconcile against the session table:
//! - The session table (`SUBNET_ROUTERS`) is the source of truth. Every
//!   start/stop compares the rule sets derived from the old and new session
//!   lists and applies only the difference — rules needed by surviving
//!   sessions are never touched, so concurrent sessions are not interrupted.
//! - Crash recovery: the first start in a process lifetime flushes both
//!   custom chains first. That flag is only ever set while the table is
//!   empty (fresh process or completed teardown), so the flush can never
//!   disturb live sessions.
//! - ip_forward is enabled on start and deliberately never restored to its
//!   previous value (maintainer decision 2026-09-30); rp_filter is still
//!   preflighted because rp_filter=1 breaks routed WireGuard traffic.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

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

// ============ session table ============

struct SubnetRouterHandle {
    result: SubnetRouterResult,
    /// Session identity/config — the desired state rules are derived from.
    req: StartSubnetRouterInput,
}

static SUBNET_ROUTERS: Mutex<Option<HashMap<String, SubnetRouterHandle>>> = Mutex::new(None);

/// True while the chains may hold rules this process does not track (fresh
/// process, or a teardown that may have failed). The next start flushes the
/// chains once and clears the flag; it is never true alongside live sessions.
static CHAINS_UNTRACKED: AtomicBool = AtomicBool::new(true);

/// Rules of already-tracked sessions. Each was validated at its own start,
/// so failures here are impossible; skipping on error keeps set math sane.
fn tracked_session_rules(map: &HashMap<String, SubnetRouterHandle>) -> Vec<IptablesRule> {
    map.values()
        .flat_map(|handle| linux_session_rules(&handle.req).unwrap_or_default())
        .collect()
}

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
    let mut guard = SUBNET_ROUTERS.lock().unwrap();
    let Some(map) = guard.as_mut() else {
        return SubnetRouterResult {
            ok: true,
            ..Default::default()
        };
    };
    let removed = match map.remove(handle_id) {
        Some(handle) => handle,
        None => {
            return SubnetRouterResult {
                ok: true,
                ..Default::default()
            };
        }
    };
    if !cfg!(target_os = "linux") {
        return SubnetRouterResult {
            ok: true,
            ..Default::default()
        };
    }
    if map.is_empty() {
        teardown_linux_router();
        return SubnetRouterResult {
            ok: true,
            ..Default::default()
        };
    }
    // Diff old set (survivors + removed) against new set (survivors only):
    // exactly the removed session's non-shared rules are deleted and nothing
    // else is touched, so surviving sessions are not interrupted.
    let mut old_rules = tracked_session_rules(map);
    old_rules.extend(linux_session_rules(&removed.req).unwrap_or_default());
    let new_rules = tracked_session_rules(map);
    let _ = apply_rule_diff(&old_rules, &new_rules);
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
    // Validate before touching the host so malformed input leaves no partial rules.
    if req.peer_tail_ip.parse::<IpAddr>().is_err() {
        return SubnetRouterResult {
            ok: false,
            error: format!("invalid peer_tail_ip: {}", req.peer_tail_ip),
            ..Default::default()
        };
    }
    let new_session_rules = match linux_session_rules(&req) {
        Ok(rules) => rules,
        Err(err) => {
            return SubnetRouterResult {
                ok: false,
                error: err,
                ..Default::default()
            };
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
    let map = guard.get_or_insert_with(HashMap::new);
    let first_session = map.is_empty();
    let old_rules = tracked_session_rules(map);
    let mut new_rules = old_rules.clone();
    new_rules.extend(new_session_rules);
    // First start in this process: rules left by a crashed previous process
    // cannot be in old_rules, so flush the chains and start from scratch.
    // The flag is only ever set while the table is empty, so no live session
    // can be affected by this flush.
    if CHAINS_UNTRACKED.swap(false, Ordering::SeqCst) {
        let _ = run_command("iptables", &["-F", LINUX_FORWARD_CHAIN]);
        let _ = run_command("iptables", &["-t", "nat", "-F", LINUX_NAT_CHAIN]);
    }
    // Prepare (chains + jumps + sysctl) runs only on the empty→non-empty
    // transition, like the old sessions==0 gate: a failure here tears down
    // with the table guaranteed empty, so it can never disturb live sessions.
    if first_session {
        if let Err(err) = prepare_linux_router() {
            return SubnetRouterResult {
                ok: false,
                error: err,
                ..Default::default()
            };
        }
    }
    if let Err(err) = apply_rule_diff(&old_rules, &new_rules) {
        return SubnetRouterResult {
            ok: false,
            error: err,
            ..Default::default()
        };
    }
    map.insert(
        handle_id,
        SubnetRouterHandle {
            result: result.clone(),
            req,
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

/// Set difference of rule lists keyed by exact identity. Sessions sharing a
/// rule collapse to one entry, which is what makes stopping one of them leave
/// the shared rule alone — set semantics replace the old refcount table.
fn rule_diff(old: &[IptablesRule], new: &[IptablesRule]) -> (Vec<IptablesRule>, Vec<IptablesRule>) {
    let old_keys: HashSet<String> = old.iter().map(rule_key).collect();
    let new_keys: HashSet<String> = new.iter().map(rule_key).collect();
    let adds = new
        .iter()
        .filter(|rule| !old_keys.contains(&rule_key(rule)))
        .cloned()
        .collect();
    let removes = old
        .iter()
        .filter(|rule| !new_keys.contains(&rule_key(rule)))
        .cloned()
        .collect();
    (adds, removes)
}

/// Adds are strict (a failed install means the session is not served and the
/// caller reports the error); removes are best-effort like the old release
/// path — a leftover is cleaned by the next first-start flush.
fn apply_rule_diff(old: &[IptablesRule], new: &[IptablesRule]) -> std::result::Result<(), String> {
    let (adds, removes) = rule_diff(old, new);
    for rule in &adds {
        ensure_iptables_rule(rule)?;
    }
    for rule in &removes {
        let _ = delete_iptables_rule(rule);
    }
    Ok(())
}

fn ensure_iptables_rule(rule: &IptablesRule) -> std::result::Result<(), String> {
    let check = build_iptables_args("-C", rule);
    let check_refs: Vec<&str> = check.iter().map(|s| s.as_str()).collect();
    if run_command("iptables", &check_refs).is_ok() {
        return Ok(());
    }
    let append = build_iptables_args("-A", &rule);
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

fn prepare_linux_router() -> std::result::Result<(), String> {
    for key in ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"] {
        let rp_filter = run_output("sysctl", &["-n", key])
            .map_err(|e| format!("read {} failed: {}", key, e))?;
        if rp_filter.trim() == "1" {
            return Err(format!("{}=1 blocks routed WireGuard traffic; set it to 0 or 2", key));
        }
    }
    // Enable-only by design: the previous value is neither recorded nor restored.
    run_command("sysctl", &["-w", "net.ipv4.ip_forward=1"])
        .map_err(|e| format!("enable ip_forward failed: {}", e))?;
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
            teardown_linux_router();
            return Err(err);
        }
    }
    Ok(())
}

fn teardown_linux_router() {
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
    // ip_forward stays as-is: enable-only by maintainer decision. Mark the
    // chains untracked so a failed cleanup is retried by the next start.
    CHAINS_UNTRACKED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(peer: &str, cidr: &str) -> StartSubnetRouterInput {
        StartSubnetRouterInput {
            session_id: 59,
            peer_device_id: 58,
            peer_tail_ip: peer.into(),
            exposed_lan_cidrs: vec![cidr.into()],
            ..Default::default()
        }
    }

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

    #[test]
    fn stopping_one_session_only_removes_its_rules() {
        let a = linux_session_rules(&session("100.99.71.2", "192.168.10.0/24")).unwrap();
        let b = linux_session_rules(&session("100.99.71.3", "192.168.10.0/24")).unwrap();
        let old: Vec<IptablesRule> = a.iter().chain(b.iter()).cloned().collect();
        let (adds, removes) = rule_diff(&old, &a);
        assert!(adds.is_empty());
        assert_eq!(removes.len(), b.len());
        let remove_keys: HashSet<String> = removes.iter().map(rule_key).collect();
        for rule in &b {
            assert!(remove_keys.contains(&rule_key(rule)));
        }
        for rule in a.iter() {
            assert!(!remove_keys.contains(&rule_key(rule)));
        }
    }

    #[test]
    fn shared_rules_survive_when_one_sharing_session_stops() {
        // Two identical sessions collapse to one rule set; stopping either
        // leaves the shared rules in place (set semantics, no refcounting).
        let rule_set = linux_session_rules(&session("100.99.71.2", "192.168.10.0/24")).unwrap();
        let old: Vec<IptablesRule> = rule_set.iter().chain(rule_set.iter()).cloned().collect();
        let (adds, removes) = rule_diff(&old, &rule_set);
        assert!(adds.is_empty());
        assert!(removes.is_empty());
    }

    #[test]
    fn starting_a_session_only_adds_its_rules() {
        let a = linux_session_rules(&session("100.99.71.2", "192.168.10.0/24")).unwrap();
        let b = linux_session_rules(&session("100.99.71.3", "10.10.0.0/16")).unwrap();
        let new: Vec<IptablesRule> = a.iter().chain(b.iter()).cloned().collect();
        let (adds, removes) = rule_diff(&a, &new);
        assert!(removes.is_empty());
        assert_eq!(adds.len(), b.len());
    }
}
