//! Optional UPnP for desktop and Android. Unsupported targets expose inert APIs.
use super::candidates::PunchingAddressInfo;
use super::Scope;
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(all(feature = "port-mapping", any(test, target_os = "android")))]
mod android;
#[cfg(all(feature = "port-mapping", target_os = "android"))]
pub use android::set_discovery_hook;

pub fn enabled() -> bool {
    #[cfg(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    ))]
    {
        desktop::enabled()
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    )))]
    {
        false
    }
}

/// Give outstanding mapping and deletion requests a bounded shutdown window.
pub async fn shutdown() {
    #[cfg(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    ))]
    desktop::shutdown().await;
}

pub fn status() -> &'static str {
    #[cfg(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    ))]
    {
        desktop::status()
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    )))]
    {
        "disabled"
    }
}

pub fn confirm_candidate(leases: &[Arc<MappingLease>], selected_nat: &str) {
    #[cfg(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    ))]
    {
        desktop::confirm_candidate(leases, selected_nat);
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    )))]
    {
        let _ = (leases, selected_nat);
    }
}

#[cfg(all(
    feature = "port-mapping",
    any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "android"
    )
))]
mod desktop;
#[cfg(all(
    feature = "port-mapping",
    any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "android"
    )
))]
pub use desktop::{discover, set_enabled, Discovery, MappingLease};

#[cfg(not(all(
    feature = "port-mapping",
    any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "android"
    )
)))]
pub struct MappingLease;

#[cfg(not(all(
    feature = "port-mapping",
    any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "android"
    )
)))]
pub struct Discovery;
#[cfg(not(all(
    feature = "port-mapping",
    any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "android"
    )
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
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    ))]
    {
        desktop::augment(scope, addresses, discovery).await
    }
    #[cfg(not(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    )))]
    {
        let _ = (scope, addresses, discovery);
        Vec::new()
    }
}

pub fn for_socket(leases: &[Arc<MappingLease>], local: SocketAddr) -> Vec<Arc<MappingLease>> {
    #[cfg(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
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
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    )))]
    {
        let _ = (leases, local);
        Vec::new()
    }
}

pub fn take_socket(leases: &[Arc<MappingLease>], local: SocketAddr) -> Option<std::net::UdpSocket> {
    #[cfg(all(
        feature = "port-mapping",
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
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
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
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
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )
    ))
))]
#[path = "portmap/disabled_tests.rs"]
mod disabled_tests;
