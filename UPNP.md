# UPnP port mapping

The `port-mapping` feature compiles UPnP IGD support on Windows, macOS, Linux and
Android. It is off by default in this library. The desktop core and Android JNI
enable it automatically at service startup. There is no persisted UPnP setting,
settings API, UI switch or status polling. Other platforms, including iOS,
compile inert implementations even if a caller enables the feature.

Android discovers gateways only while the underlying network is Wi-Fi. A shared,
reference-counted discovery guard holds a Wi-Fi multicast lock during discovery
and releases it on completion or cancellation. Its SSDP and HTTP sockets pass
through the existing VPN protect callback before binding or connecting, including
renewal and deletion requests. The JNI discovery hook must be registered before
enabling mapping. Service shutdown keeps socket protection available during the
bounded cleanup window, then unregisters both callbacks and releases the lock.
Gateway HTTP responses are bounded to 256 KiB; resource URLs must share the
advertising gateway's origin. Android diagnostics also reach the native logcat
callback.

Only UDP4 tunnel ports are mapped. STUN, LAN, IPv6 and TCP candidates remain
available. Automatic mapping policy is not included in peer traversal
preferences. Mapped addresses use the existing `udp4` / `easy` wire format, so a
peer does not need its own UPnP implementation. This describes one candidate's
reachability, not a replacement for the device's STUN NAT classification.

SSDP discovery runs concurrently with STUN, bound to individual local IPv4
interfaces. Discovery is bounded to roughly one second and cached per interface
for 30 seconds, including failures. Mapping collection adds at most 1.5 seconds
within the caller's remaining traversal deadline. Each SOAP operation is bounded
to 700 milliseconds. Unsupported gateways and non-public WAN addresses,
including CGNAT, fall back to existing candidates.

The actual STUN-discovered local port is exclusively reserved before requesting
a mapping, then handed to the UDP puncher. External ports are allocated through
the gateway's free-port operation (with the library's IGDv1 conflict handling).
Mappings request a finite 600-second lease; permanent-only gateways are not
supported. Leases renew halfway through their lifetime. Transient renewal errors
retry within the remaining lease lifetime. A changed WAN address retires the old
mapping and invalidates cached discovery for the interface.

Mapping ownership follows the punched UDP connection and its clones. The last
owner disappearing, a failed traversal, or service shutdown causes
best-effort `DeletePortMapping`. A successful creation reply arriving after
traversal cancellation is also cleaned up. A lost creation reply or abrupt
process termination may leave a temporary rule until its finite lease expires.
Normal desktop service shutdown gives pending creation and deletion workers a
bounded two-second cleanup window before its runtime exits.

Discovery, mapping and connection diagnostics are recorded using the
`upnp:` log prefix. Gateway success alone does not prove public reachability;
the existing peer handshake still determines whether a candidate connects.

Validation:

```sh
cargo test --lib --features port-mapping
cargo test --lib --no-default-features
cargo run --example upnp_probe --no-default-features --features port-mapping
```

Run the deterministic UPnP unit tests and branch-coverage gate with:

```sh
bash scripts/check-upnp-coverage.sh
```

This requires Python, `cargo-llvm-cov` and the Rust 1.94.1 LLVM tools component.
The script opts the coverage process into unstable branch instrumentation and
does not change release build settings. `UPNP_TEST_TOOLCHAIN` can select another
compatible toolchain. It checks the production `portmap.rs`, `portmap/desktop.rs`
and `portmap/android.rs`
files individually, excludes test sources, rejects reports without branch data,
and fails below 90% line or branch coverage. Reports are written to
`target/upnp-coverage/coverage.json` and `target/upnp-coverage/summary.json`.
The feature-disabled unit test is run separately to verify the inert API.

Tests cover discovery filtering, positive/negative caches and expiry, task
failure, cancellation/deadlines, occupied ports, duplicate candidates, late SOAP
replies, malformed replies, WAN lookup and mapping errors/timeouts, invalid or
CGNAT addresses, socket handoff, shared lease ownership, renewal/retry/expiry
decisions, WAN changes, cleanup failures, and bounded shutdown. All gateway
requests use a loopback mock; tests do not create router mappings.

The live probe prints STUN evidence and production candidate results. It also
creates a separate 120-second diagnostic rule on discovered gateways, including
gateways with private WAN addresses, queries the rule, deletes it, and queries
again. Diagnostic rules are never advertised as public candidates. A local test
on 2026-10-19 found hard NAT, an inner WAN in 100.64.0.0/10, successful rule
creation, and confirmed deletion. This router returns malformed namespace XML
for deletion, causing the library to report an invalid response even though a
subsequent lookup confirms the rule is absent. Independent public ingress was
not tested.

The local mock-IGD test covers SOAP port/lease values, exclusive reservation,
reference counting, renewal, deletion, disabling, CGNAT filtering, retention of
STUN candidates, legacy candidate compatibility, and late creation cleanup after
cancellation. Real-router verification should additionally cover desktop/mobile
connections in both initiation directions, network changes, double NAT, and
router-specific lease or port-conflict behavior.
