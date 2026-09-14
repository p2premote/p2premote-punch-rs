//! Global socket-protect hook, the Rust port of easyp2p/socketprotect.go.
//!
//! Android embeds this library inside a VpnService: every UDP socket used
//! for NAT punching must be passed to `VpnService.protect(fd)` or its
//! traffic is routed back into the VPN's own TUN device. The mobile
//! binding registers a callback here before starting any exchange.

use std::sync::Mutex;

pub type ProtectFn = Box<dyn Fn(i32) -> bool + Send + Sync>;

static PROTECT_FN: Mutex<Option<ProtectFn>> = Mutex::new(None);

/// Register (or clear with None) the global socket-protect callback.
pub fn set_socket_protect(f: Option<ProtectFn>) {
    *PROTECT_FN.lock().unwrap() = f;
}

/// Best-effort protect of a raw fd. Failures are silently ignored so an
/// unregistered or failing callback never blocks socket usage (parity with
/// the Go implementation's protectUDPConnFd).
pub fn protect_raw_fd(fd: i32) {
    let guard = PROTECT_FN.lock().unwrap();
    if let Some(f) = guard.as_ref() {
        let _ = f(fd);
    }
}

/// Protect a socket before it is bound/connected (Unix: raw fd; other
/// platforms, including Windows, are no-ops like the Go build without the
/// android tag).
#[cfg(unix)]
pub fn protect_socket<S: std::os::fd::AsRawFd>(socket: &S) {
    protect_raw_fd(socket.as_raw_fd());
}

#[cfg(not(unix))]
pub fn protect_socket<S>(_socket: &S) {}
