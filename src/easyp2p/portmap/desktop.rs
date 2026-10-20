use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock, Weak,
};
use std::time::{Duration, Instant};

#[cfg(target_os = "android")]
use super::android::{search_gateway, Protected as Tokio};
#[cfg(target_os = "android")]
use igd_next::{aio::Gateway, PortMappingProtocol::UDP, SearchOptions};
#[cfg(not(target_os = "android"))]
use igd_next::{
    aio::{
        tokio::{search_gateway, Tokio},
        Gateway,
    },
    PortMappingProtocol::UDP,
    SearchOptions,
};
use tokio::sync::{oneshot, watch};
use tokio::time::{sleep, timeout};

use super::{PunchingAddressInfo, Scope};

const LEASE_SECONDS: u32 = 600;
const DISCOVERY_BUDGET: Duration = Duration::from_millis(1000);
const REQUEST_BUDGET: Duration = Duration::from_millis(700);
const CACHE_TTL: Duration = Duration::from_secs(30);
static ENABLED: AtomicBool = AtomicBool::new(false);
// Last attempt only; live leases take precedence in the diagnostic snapshot.
static LAST_ATTEMPT: AtomicU8 = AtomicU8::new(0);
static CHANGES: OnceLock<watch::Sender<bool>> = OnceLock::new();
static WORKERS: AtomicUsize = AtomicUsize::new(0);

struct WorkerGuard;
impl WorkerGuard {
    fn new() -> Self {
        WORKERS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        WORKERS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub async fn shutdown() {
    set_enabled(false);
    let _ = timeout(Duration::from_secs(2), async {
        while WORKERS.load(Ordering::SeqCst) > 0 {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

fn changes() -> &'static watch::Sender<bool> {
    CHANGES.get_or_init(|| watch::channel(false).0)
}

/// Internal service lifecycle control; not a user preference.
pub fn set_enabled(enabled: bool) {
    if ENABLED.swap(enabled, Ordering::SeqCst) != enabled {
        LAST_ATTEMPT.store(0, Ordering::SeqCst);
        GATEWAYS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .clear();
        changes().send_replace(enabled);
    }
}

type Igd = Gateway<Tokio>;
type Cache = HashMap<Ipv4Addr, (Instant, Option<Igd>)>;
static GATEWAYS: OnceLock<Mutex<Cache>> = OnceLock::new();
static LEASES: OnceLock<tokio::sync::Mutex<HashMap<SocketAddr, Weak<MappingLease>>>> =
    OnceLock::new();

pub fn status() -> &'static str {
    if !enabled() {
        return "disabled";
    }
    if let Some(registry) = LEASES.get() {
        match registry.try_lock() {
            Ok(leases) => {
                let live: Vec<_> = leases
                    .values()
                    .filter_map(Weak::upgrade)
                    .filter(|l| l.active.load(Ordering::SeqCst))
                    .collect();
                if live.iter().any(|l| l.connected.load(Ordering::SeqCst)) {
                    return "connected";
                }
                if !live.is_empty() {
                    return "mapped";
                }
            }
            Err(_) => return "mapping",
        }
    }
    match LAST_ATTEMPT.load(Ordering::SeqCst) {
        1 => "discovering",
        2 => "no_gateway",
        3 => "mapping_failed",
        _ => "idle",
    }
}

pub fn confirm_candidate(leases: &[Arc<MappingLease>], selected_nat: &str) {
    for lease in leases {
        if lease.external.to_string() == selected_nat {
            lease.connected.store(true, Ordering::SeqCst);
        }
    }
}

pub struct Discovery(HashMap<Ipv4Addr, Igd>);

/// SSDP is bound to each actual local interface; no guessed .1 gateways.
/// Runs concurrently with STUN. Cache failures briefly to avoid repeated delays.
pub async fn discover(scope: &Scope, networks: &[String]) -> Discovery {
    if !networks.iter().any(|network| network == "udp4")
        || !ENABLED.load(Ordering::SeqCst)
        || scope.expired()
    {
        return Discovery(HashMap::new());
    }
    #[cfg(target_os = "android")]
    let Some(_discovery_guard) = super::android::DiscoveryGuard::begin() else {
        return Discovery(HashMap::new());
    };
    let interfaces = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|iface| iface.ip());
    discover_interfaces(scope, interfaces, |ip| async move {
        search_gateway(SearchOptions {
            bind_addr: SocketAddr::from((ip, 0)),
            timeout: Some(DISCOVERY_BUDGET),
            ..Default::default()
        })
        .await
        .ok()
    })
    .await
}

async fn discover_interfaces<F, Fut>(
    scope: &Scope,
    interfaces: impl IntoIterator<Item = IpAddr>,
    search: F,
) -> Discovery
where
    F: Fn(Ipv4Addr) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Option<Igd>> + Send + 'static,
{
    LAST_ATTEMPT.store(1, Ordering::SeqCst);
    let ips: HashSet<_> = interfaces
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() => {
                Some(ip)
            }
            _ => None,
        })
        .collect();
    let mut found = HashMap::new();
    let mut tasks = tokio::task::JoinSet::new();
    for ip in ips.into_iter().take(16) {
        let cached = GATEWAYS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .get(&ip)
            .cloned();
        if let Some((at, gateway)) = cached.filter(|(at, _)| at.elapsed() < CACHE_TTL) {
            let _ = at;
            if let Some(gateway) = gateway {
                found.insert(ip, gateway);
            }
            continue;
        }
        let search = search.clone();
        tasks.spawn(async move {
            let gateway = search(ip).await;
            GATEWAYS
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .insert(ip, (Instant::now(), gateway.clone()));
            (ip, gateway)
        });
    }
    let collect = async {
        while let Some(result) = tasks.join_next().await {
            if let Ok((ip, Some(gateway))) = result {
                found.insert(ip, gateway);
            }
        }
    };
    tokio::select! {
        _ = scope.cancelled() => {},
        _ = timeout(scope.bounded_timeout(DISCOVERY_BUDGET + Duration::from_millis(100)), collect) => {},
    }
    if found.is_empty() {
        crate::p2pevent!("upnp: no gateway discovered; using existing candidates");
    }
    LAST_ATTEMPT.store(if found.is_empty() { 2 } else { 0 }, Ordering::SeqCst);
    Discovery(found)
}

/// The worker never owns an Arc to this lease. The final owner closing the
/// channel triggers deletion, including cancellation before candidate exchange.
pub struct MappingLease {
    pub local: SocketAddr,
    pub(super) reserved: Mutex<Option<std::net::UdpSocket>>,
    external: SocketAddr,
    _release: oneshot::Sender<()>,
    active: Arc<AtomicBool>,
    connected: AtomicBool,
}

fn public_v4(ip: IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else {
        return false;
    };
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0 && c == 0))
}

fn next_renewal(
    renewed: bool,
    wan_checked: bool,
    now: Instant,
    valid_until: Instant,
    normal: Duration,
) -> Option<Duration> {
    if renewed && wan_checked {
        return Some(normal);
    }
    let retry = Duration::from_secs(30);
    (now + retry < valid_until).then_some(retry)
}

async fn create(
    local: SocketAddr,
    gateway: Igd,
    interest: &oneshot::Sender<Option<Arc<MappingLease>>>,
) -> Option<Arc<MappingLease>> {
    create_with_period(
        local,
        gateway,
        interest,
        Duration::from_secs(u64::from(LEASE_SECONDS / 2)),
    )
    .await
}

async fn create_with_period(
    local: SocketAddr,
    gateway: Igd,
    interest: &oneshot::Sender<Option<Arc<MappingLease>>>,
    renew_after: Duration,
) -> Option<Arc<MappingLease>> {
    let registry = LEASES.get_or_init(Default::default);
    let mut leases = registry.lock().await;
    if interest.is_closed() || !ENABLED.load(Ordering::SeqCst) {
        return None;
    }
    leases.retain(|_, lease| lease.strong_count() > 0);
    if let Some(lease) = leases.get(&local).and_then(Weak::upgrade) {
        if lease.active.load(Ordering::SeqCst) {
            return Some(lease);
        }
    }
    let reserved = super::super::netx::listen_udp(local, false).ok()?;
    LAST_ATTEMPT.store(3, Ordering::SeqCst);
    let external_ip = match timeout(REQUEST_BUDGET, gateway.get_external_ip()).await {
        Ok(Ok(ip)) => ip,
        error => {
            crate::p2pevent!("upnp: WAN lookup failed local={} result={:?}", local, error);
            return None;
        }
    };
    if !public_v4(external_ip) {
        crate::p2pevent!(
            "upnp: gateway WAN {} is not public; skipping mapping",
            external_ip
        );
        return None;
    }
    // Allocate a free external port, never replace another application's rule.
    // Finite leases are mandatory: permanent-only gateways use STUN fallback.
    let port = match timeout(
        REQUEST_BUDGET,
        gateway.add_any_port(UDP, local, LEASE_SECONDS, "p2pRemote UDP"),
    )
    .await
    {
        Ok(Ok(port)) if port != 0 => port,
        error => {
            crate::p2pevent!(
                "upnp: mapping failed local={} result={:?}; using existing candidates",
                local,
                error
            );
            return None;
        }
    };
    let external = SocketAddr::new(external_ip, port);
    let (release, mut released) = oneshot::channel();
    let active = Arc::new(AtomicBool::new(true));
    let lease = Arc::new(MappingLease {
        local,
        external,
        reserved: Mutex::new(Some(reserved)),
        _release: release,
        active: active.clone(),
        connected: AtomicBool::new(false),
    });
    LAST_ATTEMPT.store(0, Ordering::SeqCst);
    leases.insert(local, Arc::downgrade(&lease));
    let mut setting = changes().subscribe();
    let work = WorkerGuard::new();
    tokio::spawn(async move {
        let _work = work;
        crate::p2pevent!(
            "upnp: mapping created local={} external={} (reachability unverified)",
            local,
            external
        );
        let mut valid_until = Instant::now() + Duration::from_secs(u64::from(LEASE_SECONDS));
        let mut renew_in = renew_after;
        loop {
            if !*setting.borrow() {
                break;
            }
            tokio::select! {
                _ = &mut released => break,
                _ = setting.changed() => break,
                _ = sleep(renew_in) => {
                    let renewed = timeout(REQUEST_BUDGET, gateway.add_port(UDP, port, local, LEASE_SECONDS, "p2pRemote UDP")).await;
                    if matches!(renewed, Ok(Ok(()))) {
                        valid_until = Instant::now() + Duration::from_secs(u64::from(LEASE_SECONDS));
                    }
                    let wan = timeout(REQUEST_BUDGET, gateway.get_external_ip()).await;
                    if matches!(wan, Ok(Ok(ip)) if ip != external.ip()) {
                        crate::p2pevent!("upnp: WAN changed; retiring mapping local={}", local);
                        GATEWAYS.get_or_init(Default::default).lock().unwrap().remove(&match local.ip() { IpAddr::V4(ip) => ip, _ => unreachable!() });
                        break;
                    }
                    let next = next_renewal(matches!(renewed, Ok(Ok(()))), matches!(wan, Ok(Ok(_))), Instant::now(), valid_until, renew_after);
                    if next != Some(renew_after) {
                        crate::p2pevent!("upnp: renewal or WAN check failed local={}; retrying within lease", local);
                    }
                    match next { Some(delay) => renew_in = delay, None => break }
                }
            }
        }
        active.store(false, Ordering::SeqCst);
        let removed = timeout(REQUEST_BUDGET, gateway.remove_port(UDP, port)).await;
        crate::p2pevent!(
            "upnp: mapping released local={} deleted={}",
            local,
            matches!(removed, Ok(Ok(())))
        );
    });
    Some(lease)
}

pub async fn augment(
    scope: &Scope,
    addresses: &mut Vec<PunchingAddressInfo>,
    discovery: Discovery,
) -> Vec<Arc<MappingLease>> {
    if !ENABLED.load(Ordering::SeqCst) || scope.expired() {
        return Vec::new();
    }
    let mut locals = HashSet::new();
    let mut pending = tokio::task::JoinSet::new();
    for candidate in addresses.iter().filter(|a| a.network == "udp4") {
        let Ok(local) = candidate.lan.parse::<SocketAddr>() else {
            continue;
        };
        let IpAddr::V4(ip) = local.ip() else {
            continue;
        };
        if local.port() == 0 || !locals.insert(local) {
            continue;
        }
        let Some(gateway) = discovery.0.get(&ip).cloned() else {
            continue;
        };
        // Do not abort SOAP creation when traversal is cancelled: finish it and
        // drop the resulting lease, so a successful late reply is cleaned up.
        let (tx, rx) = oneshot::channel();
        let work = WorkerGuard::new();
        tokio::spawn(async move {
            let _work = work;
            let lease = create(local, gateway, &tx).await;
            let _ = tx.send(lease);
        });
        pending.spawn(async move { rx.await.ok().flatten() });
    }
    let mut leases = Vec::new();
    let collect = async {
        while let Some(result) = pending.join_next().await {
            if let Ok(Some(lease)) = result {
                if !ENABLED.load(Ordering::SeqCst) {
                    continue;
                }
                let nat = lease.external.to_string();
                if !addresses.iter().any(|a| {
                    a.network == "udp4"
                        && a.lan == lease.local.to_string()
                        && a.nat == nat
                        && a.nat_type == "easy"
                }) {
                    addresses.push(PunchingAddressInfo {
                        network: "udp4".into(),
                        nat_type: "easy".into(),
                        lan: lease.local.to_string(),
                        nat,
                    });
                }
                leases.push(lease);
            }
        }
    };
    tokio::select! {
        _ = scope.cancelled() => {},
        _ = timeout(scope.bounded_timeout(Duration::from_millis(1500)), collect) => {},
    }
    leases
}

#[cfg(test)]
#[path = "desktop_tests.rs"]
mod tests;
