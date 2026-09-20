//! Platform capability reporting and userspace-WireGuard stubs.
//!
//! This rewrite currently implements the Linux functionality set. Windows and
//! macOS keep the punch/UDP-tunnel path (it is platform independent) but the
//! userspace WireGuard data plane is not ported yet; its ABI entry points
//! mirror the "unsupported" behavior Go shows on Linux
//! (punchffi/windows_wg_dispatch_nonwindows.go).

#[cfg(feature = "ffi")]
use crate::types::{WgCapabilitiesResult, WgKeypairResult, WindowsWgPeerResult};

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unknown"
    }
}

#[cfg(feature = "ffi")]
pub fn platform_wg_capabilities() -> WgCapabilitiesResult {
    WgCapabilitiesResult {
        ok: true,
        abi_version: 2,
        platform: platform_name().to_string(),
        userspace_wg: false,
        hybrid_tun: false,
        wintun: false,
        native_tun: false,
        netstack_proxy: false,
        error: String::new(),
    }
}

#[cfg(feature = "ffi")]
fn unsupported_userspace_wg() -> WindowsWgPeerResult {
    WindowsWgPeerResult {
        ok: false,
        error: format!(
            "Windows userspace WireGuard is not supported on {}",
            platform_name()
        ),
        ..Default::default()
    }
}

#[cfg(feature = "ffi")]
pub fn generate_wg_keypair() -> WgKeypairResult {
    WgKeypairResult {
        ok: false,
        error: format!(
            "Windows userspace WireGuard is not supported on {}",
            platform_name()
        ),
        ..Default::default()
    }
}

#[cfg(feature = "ffi")]
pub fn start_userspace_wg_peer() -> WindowsWgPeerResult {
    unsupported_userspace_wg()
}

#[cfg(feature = "ffi")]
pub fn stop_userspace_wg_peer() -> WindowsWgPeerResult {
    unsupported_userspace_wg()
}

#[cfg(feature = "ffi")]
pub fn set_userspace_wg_peer_allowed() -> WindowsWgPeerResult {
    unsupported_userspace_wg()
}

#[cfg(feature = "ffi")]
pub fn get_userspace_wg_peer_status() -> WindowsWgPeerResult {
    unsupported_userspace_wg()
}

#[cfg(feature = "ffi")]
pub fn stop_userspace_wg_engine() -> WindowsWgPeerResult {
    unsupported_userspace_wg()
}

#[cfg(feature = "ffi")]
pub fn cleanup_userspace_wg_platform() -> WindowsWgPeerResult {
    unsupported_userspace_wg()
}
