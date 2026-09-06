//! Global async runtime backing the blocking C ABI.
//!
//! punchffi callers invoke the FFI from arbitrary threads (the desktop client
//! uses tokio spawn_blocking workers) and expect calls to block until done
//! (StartUdpTunnel can run for minutes). A private multi-thread runtime keeps
//! that contract without depending on the host's executor.

use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("p2premote-punch")
            .enable_all()
            .build()
            .expect("failed to build p2premote-punch runtime")
    })
}

/// Run a future to completion on the private runtime, blocking the caller.
pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    runtime().block_on(future)
}

pub fn now_unix_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}
