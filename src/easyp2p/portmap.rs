//! Optional desktop-only UPnP. Mobile builds expose inert lifecycle types only.
use super::candidates::PunchingAddressInfo;
use super::Scope;
use std::net::SocketAddr;
use std::sync::Arc;

pub fn enabled() -> bool {
    #[cfg(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    {
        desktop::enabled()
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    )))]
    {
        false
    }
}

/// Give outstanding mapping and deletion requests a bounded shutdown window.
pub async fn shutdown() {
    #[cfg(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    desktop::shutdown().await;
}

pub fn status() -> &'static str {
    #[cfg(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    {
        desktop::status()
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    )))]
    {
        "disabled"
    }
}

pub fn confirm_candidate(leases: &[Arc<MappingLease>], selected_nat: &str) {
    #[cfg(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    {
        desktop::confirm_candidate(leases, selected_nat);
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    )))]
    {
        let _ = (leases, selected_nat);
    }
}

#[cfg(all(
    feature = "port-mapping",
    any(target_os = "windows", target_os = "linux", target_os = "macos")
))]
mod desktop;
#[cfg(all(
    feature = "port-mapping",
    any(target_os = "windows", target_os = "linux", target_os = "macos")
))]
pub use desktop::{discover, set_enabled, Discovery, MappingLease};

#[cfg(not(all(
    feature = "port-mapping",
    any(target_os = "windows", target_os = "linux", target_os = "macos")
)))]
pub struct MappingLease;

#[cfg(not(all(
    feature = "port-mapping",
    any(target_os = "windows", target_os = "linux", target_os = "macos")
)))]
pub struct Discovery;
#[cfg(not(all(
    feature = "port-mapping",
    any(target_os = "windows", target_os = "linux", target_os = "macos")
)))]
pub async fn discover(_: &Scope, _: &[String]) -> Discovery {
    Discovery
}

/// Add ordinary easy UDP4 candidates, preserving the original STUN evidence.
pub async fn augment(
    scope: &Scope,
    addresses: &mut Vec<PunchingAddressInfo>,
    discovery: Discovery,
) -> Vec<Arc<MappingLease>> {
    #[cfg(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    {
        desktop::augment(scope, addresses, discovery).await
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    )))]
    {
        let _ = (scope, addresses, discovery);
        Vec::new()
    }
}

pub fn for_socket(leases: &[Arc<MappingLease>], local: SocketAddr) -> Vec<Arc<MappingLease>> {
    #[cfg(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    {
        leases
            .iter()
            .filter(|lease| lease.local == local)
            .cloned()
            .collect()
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    )))]
    {
        let _ = (leases, local);
        Vec::new()
    }
}

pub fn take_socket(leases: &[Arc<MappingLease>], local: SocketAddr) -> Option<std::net::UdpSocket> {
    #[cfg(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    {
        leases
            .iter()
            .find(|lease| lease.local == local)?
            .reserved
            .lock()
            .unwrap()
            .take()
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    )))]
    {
        let _ = (leases, local);
        None
    }
}

#[cfg(all(
    test,
    not(all(
        feature = "port-mapping",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))
))]
#[path = "portmap/disabled_tests.rs"]
mod disabled_tests;
