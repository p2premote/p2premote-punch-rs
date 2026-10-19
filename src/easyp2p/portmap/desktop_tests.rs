use super::*;
use std::collections::VecDeque;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// The service manager is process-wide. Serialize only tests that mutate it;
// pure address/renewal tests can still run in parallel with the rest of the crate.
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn setup() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().await;
    super::super::shutdown().await;
    LEASES.get_or_init(Default::default).lock().await.clear();
    GATEWAYS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .clear();
    set_enabled(true);
    guard
}

#[derive(Clone)]
enum Reply {
    Success(String),
    Fault,
    Malformed,
    Delay,
    Late,
    Close,
}

struct Router {
    gateway: Igd,
    requests: tokio::sync::mpsc::UnboundedReceiver<(String, String)>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Router {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Router {
    async fn new(steps: Vec<(&str, Reply)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, requests) = tokio::sync::mpsc::unbounded_channel();
        let steps: HashMap<String, VecDeque<Reply>> =
            steps
                .into_iter()
                .fold(HashMap::new(), |mut map, (action, reply)| {
                    map.entry(action.to_owned()).or_default().push_back(reply);
                    map
                });
        let steps = Arc::new(Mutex::new(steps));
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let tx = tx.clone();
                let steps = steps.clone();
                connections.spawn(async move {
                    let mut bytes = Vec::new();
                    loop {
                        let mut buf = [0u8; 2048];
                        let Ok(n) = stream.read(&mut buf).await else { return; };
                        if n == 0 { return; }
                        bytes.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&bytes);
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let len: usize = head.lines().find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|s| s.trim().parse().unwrap())).unwrap();
                            if body.len() >= len { break; }
                        }
                    }
                    let request = String::from_utf8(bytes).unwrap();
                    let action = ["GetExternalIPAddress", "AddAnyPortMapping", "AddPortMapping", "DeletePortMapping"].into_iter().find(|a| request.contains(&format!("#{a}"))).unwrap().to_owned();
                    let reply = steps.lock().unwrap().get_mut(&action).and_then(VecDeque::pop_front).unwrap_or_else(|| Reply::Success(match action.as_str() {
                        "GetExternalIPAddress" => "<NewExternalIPAddress>8.8.8.8</NewExternalIPAddress>".into(),
                        "AddAnyPortMapping" => "<NewReservedPort>45678</NewReservedPort>".into(),
                        _ => String::new(),
                    }));
                    let _ = tx.send((action.clone(), request));
                    let body = match reply {
                        Reply::Success(fields) => format!("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">{fields}</u:{action}Response></s:Body></s:Envelope>"),
                        Reply::Fault => "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>".into(),
                        Reply::Malformed => "<broken-response>".into(),
                        Reply::Delay => { std::future::pending::<()>().await; unreachable!() },
                        Reply::Late => {
                            sleep(Duration::from_millis(100)).await;
                            format!("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewReservedPort>45678</NewReservedPort></u:{action}Response></s:Body></s:Envelope>")
                        },
                        Reply::Close => return,
                    };
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let inputs: Vec<String> = [
            "NewRemoteHost",
            "NewExternalPort",
            "NewProtocol",
            "NewInternalPort",
            "NewInternalClient",
            "NewEnabled",
            "NewPortMappingDescription",
            "NewLeaseDuration",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let control_schema = [
            ("AddAnyPortMapping".into(), inputs.clone()),
            ("AddPortMapping".into(), inputs),
            (
                "DeletePortMapping".into(),
                vec![
                    "NewRemoteHost".into(),
                    "NewExternalPort".into(),
                    "NewProtocol".into(),
                ],
            ),
        ]
        .into_iter()
        .collect();
        Self {
            gateway: Gateway {
                addr,
                root_url: "/root".into(),
                control_url: "/control".into(),
                control_schema_url: "/schema".into(),
                control_schema,
                provider: Tokio,
            },
            requests,
            server,
        }
    }

    async fn next(&mut self, expected: &str) -> String {
        let (action, body) = timeout(Duration::from_secs(3), self.requests.recv())
            .await
            .expect("router request timeout")
            .unwrap();
        assert_eq!(action, expected);
        body
    }
}

fn local() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn scope() -> Scope {
    Scope::from_timeout(Duration::from_secs(3))
}
fn address(local: SocketAddr) -> PunchingAddressInfo {
    PunchingAddressInfo {
        network: "udp4".into(),
        lan: local.to_string(),
        nat: "9.9.9.9:12345".into(),
        nat_type: "hard".into(),
    }
}
fn discovery(gateway: &Igd) -> Discovery {
    Discovery(
        [(Ipv4Addr::LOCALHOST, gateway.clone())]
            .into_iter()
            .collect(),
    )
}

#[test]
fn public_address_boundaries() {
    for ip in [
        "0.0.0.0",
        "0.1.2.3",
        "10.1.2.3",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.168.1.1",
        "192.0.0.9",
        "192.0.2.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
    ] {
        assert!(!public_v4(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "100.63.255.255",
        "100.128.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "192.0.1.1",
    ] {
        assert!(public_v4(ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn renewal_success_retry_and_expiry_boundaries() {
    let now = Instant::now();
    let normal = Duration::from_secs(300);
    for (renewed, checked) in [(true, false), (false, true), (false, false)] {
        assert_eq!(
            next_renewal(renewed, checked, now, now + Duration::from_secs(31), normal),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            next_renewal(renewed, checked, now, now + Duration::from_secs(30), normal),
            None
        );
        assert_eq!(next_renewal(renewed, checked, now, now, normal), None);
    }
    assert_eq!(next_renewal(true, true, now, now, normal), Some(normal));
}

#[tokio::test]
async fn status_and_internal_lifecycle_reset() {
    let _guard = setup().await;
    assert_eq!(super::super::status(), "idle");
    assert!(super::super::enabled());
    for (code, expected) in [
        (1, "discovering"),
        (2, "no_gateway"),
        (3, "mapping_failed"),
        (99, "idle"),
    ] {
        LAST_ATTEMPT.store(code, Ordering::SeqCst);
        assert_eq!(status(), expected);
    }
    let lock = LEASES.get().unwrap().lock().await;
    assert_eq!(status(), "mapping");
    drop(lock);
    let mut changes = changes().subscribe();
    set_enabled(true);
    assert!(!changes.has_changed().unwrap());
    set_enabled(false);
    changes.changed().await.unwrap();
    assert_eq!(status(), "disabled");
    assert!(!enabled());
    shutdown().await;
}

#[tokio::test]
async fn discovery_filters_interfaces_deduplicates_and_reuses_positive_and_negative_cache() {
    let _guard = setup().await;
    let router = Router::new(vec![]).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let first: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let second: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let interfaces: Vec<IpAddr> = [
        "127.0.0.1",
        "0.0.0.0",
        "169.254.0.1",
        "::1",
        "10.0.0.2",
        "10.0.0.2",
        "10.0.0.3",
    ]
    .into_iter()
    .map(|s| s.parse().unwrap())
    .collect();
    let gateway = router.gateway.clone();
    let count = calls.clone();
    let result = discover_interfaces(&scope(), interfaces, move |ip| {
        count.fetch_add(1, Ordering::SeqCst);
        let gateway = gateway.clone();
        async move { (ip == first).then_some(gateway) }
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(result.0.len(), 1);
    let count = calls.clone();
    let result = discover_interfaces(
        &scope(),
        [IpAddr::V4(first), IpAddr::V4(second)],
        move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            async { None }
        },
    )
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(result.0.len(), 1);
    GATEWAYS.get().unwrap().lock().unwrap().insert(
        first,
        (Instant::now() - CACHE_TTL - Duration::from_secs(1), None),
    );
    let count = calls.clone();
    assert!(
        discover_interfaces(&scope(), [IpAddr::V4(first)], move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            async { None }
        })
        .await
        .0
        .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(status(), "no_gateway");
    shutdown().await;
}

#[tokio::test]
async fn discovery_early_exits_cancellation_timeout_and_task_failure() {
    let _guard = setup().await;
    // Exercise the public entry point without sending SSDP to the real LAN.
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if let IpAddr::V4(ip) = iface.ip() {
            GATEWAYS
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .insert(ip, (Instant::now(), None));
        }
    }
    assert!(discover(&scope(), &["udp4".into()]).await.0.is_empty());
    assert!(super::super::discover(&scope(), &["tcp4".into()])
        .await
        .0
        .is_empty());
    set_enabled(false);
    assert!(discover(&scope(), &["udp4".into()]).await.0.is_empty());
    set_enabled(true);
    assert!(
        discover(&Scope::from_timeout(Duration::ZERO), &["udp4".into()])
            .await
            .0
            .is_empty()
    );
    let ip: IpAddr = "10.2.3.4".parse().unwrap();
    let cancel = Arc::new(super::super::super::CancelToken::new());
    cancel.cancel();
    assert!(
        discover_interfaces(&scope().with_cancel(cancel), [ip], |_| async {
            std::future::pending().await
        })
        .await
        .0
        .is_empty()
    );
    assert!(discover_interfaces(
        &Scope::from_timeout(Duration::from_millis(10)),
        [ip],
        |_| async { std::future::pending().await }
    )
    .await
    .0
    .is_empty());
    assert!(discover_interfaces(&scope(), [ip], |_| async {
        panic!("simulated discovery task failure")
    })
    .await
    .0
    .is_empty());
    shutdown().await;
}

#[tokio::test]
async fn mapping_reuses_lease_hands_off_exact_socket_and_preserves_ownership() {
    let _guard = setup().await;
    let mut router = Router::new(vec![]).await;
    let local = local();
    let (interest, _rx) = oneshot::channel();
    let lease = create(local, router.gateway.clone(), &interest)
        .await
        .unwrap();
    router.next("GetExternalIPAddress").await;
    let request = router.next("AddAnyPortMapping").await;
    assert!(request.contains(&format!(
        "<NewInternalPort>{}</NewInternalPort>",
        local.port()
    )));
    assert!(request.contains("<NewLeaseDuration>600</NewLeaseDuration>"));
    assert!(std::net::UdpSocket::bind(local).is_err());
    assert_eq!(status(), "mapped");
    confirm_candidate(&[lease.clone()], "8.8.4.4:45678");
    assert_eq!(status(), "mapped");
    super::super::confirm_candidate(&[lease.clone()], "8.8.8.8:45678");
    assert_eq!(status(), "connected");
    let reused = create(local, router.gateway.clone(), &interest)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&lease, &reused));
    assert!(super::super::for_socket(&[lease.clone()], "127.0.0.1:1".parse().unwrap()).is_empty());
    let retained = super::super::for_socket(&[lease.clone()], local);
    assert_eq!(retained.len(), 1);
    assert!(super::super::take_socket(&[lease.clone()], "127.0.0.1:1".parse().unwrap()).is_none());
    let socket = super::super::take_socket(&[lease.clone()], local).unwrap();
    assert_eq!(socket.local_addr().unwrap(), local);
    assert!(super::super::take_socket(&[lease.clone()], local).is_none());
    drop(lease);
    drop(reused);
    assert!(router.requests.try_recv().is_err());
    drop(retained);
    router.next("DeletePortMapping").await;
    drop(socket);
    shutdown().await;
    assert_eq!(WORKERS.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn creation_rejects_closed_interest_disabled_manager_and_occupied_port() {
    let _guard = setup().await;
    let router = Router::new(vec![]).await;
    let (interest, rx) = oneshot::channel();
    drop(rx);
    assert!(create(local(), router.gateway.clone(), &interest)
        .await
        .is_none());
    let (interest, _rx) = oneshot::channel();
    set_enabled(false);
    assert!(create(local(), router.gateway.clone(), &interest)
        .await
        .is_none());
    set_enabled(true);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(create(
        socket.local_addr().unwrap(),
        router.gateway.clone(),
        &interest
    )
    .await
    .is_none());
    shutdown().await;
}

#[tokio::test]
async fn inactive_leases_are_replaced_and_dead_registry_entries_are_pruned() {
    let _guard = setup().await;
    let router = Router::new(vec![]).await;
    let local = local();
    let (interest, _rx) = oneshot::channel();
    let old = create(local, router.gateway.clone(), &interest)
        .await
        .unwrap();
    drop(super::super::take_socket(&[old.clone()], local));
    shutdown().await;
    assert!(!old.active.load(Ordering::SeqCst));
    set_enabled(true);
    let dead = "127.0.0.1:1".parse().unwrap();
    LEASES.get().unwrap().lock().await.insert(dead, Weak::new());
    let new = create(local, router.gateway.clone(), &interest)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&old, &new));
    assert!(!LEASES.get().unwrap().lock().await.contains_key(&dead));
    drop(new);
    drop(old);
    shutdown().await;
}

#[tokio::test]
async fn shutdown_during_creation_does_not_publish_a_late_mapping() {
    let _guard = setup().await;
    let mut router = Router::new(vec![("AddAnyPortMapping", Reply::Late)]).await;
    let gateway = router.gateway.clone();
    let mut addresses = vec![address(local())];
    let task = tokio::spawn(async move {
        let leases = augment(&scope(), &mut addresses, discovery(&gateway)).await;
        (leases.len(), addresses.len())
    });
    router.next("GetExternalIPAddress").await;
    router.next("AddAnyPortMapping").await;
    set_enabled(false);
    assert_eq!(task.await.unwrap(), (0, 1));
    shutdown().await;
    router.next("DeletePortMapping").await;
}

#[tokio::test]
async fn shutdown_is_bounded_even_when_a_worker_has_not_finished() {
    let _guard = setup().await;
    tokio::time::pause();
    let worker = WorkerGuard::new();
    let stopping = tokio::spawn(shutdown());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(3)).await;
    stopping.await.unwrap();
    assert_eq!(WORKERS.load(Ordering::SeqCst), 1);
    drop(worker);
    assert_eq!(WORKERS.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn creation_failure_matrix_keeps_ports_free_and_never_advertises_a_mapping() {
    let _guard = setup().await;
    for (action, reply) in [
        ("GetExternalIPAddress", Reply::Fault),
        ("GetExternalIPAddress", Reply::Malformed),
        ("GetExternalIPAddress", Reply::Close),
        ("GetExternalIPAddress", Reply::Delay),
        (
            "GetExternalIPAddress",
            Reply::Success("<NewExternalIPAddress>100.64.1.2</NewExternalIPAddress>".into()),
        ),
        (
            "GetExternalIPAddress",
            Reply::Success("<NewExternalIPAddress>::1</NewExternalIPAddress>".into()),
        ),
        ("AddAnyPortMapping", Reply::Fault),
        ("AddAnyPortMapping", Reply::Malformed),
        ("AddAnyPortMapping", Reply::Delay),
        (
            "AddAnyPortMapping",
            Reply::Success("<NewReservedPort>0</NewReservedPort>".into()),
        ),
    ] {
        let mut router = Router::new(vec![(action, reply)]).await;
        let local = local();
        let mut addresses = vec![address(local)];
        let leases = augment(&scope(), &mut addresses, discovery(&router.gateway)).await;
        assert!(leases.is_empty(), "{action}");
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].nat_type, "hard");
        assert!(std::net::UdpSocket::bind(local).is_ok());
        assert_eq!(status(), "mapping_failed");
        router.next("GetExternalIPAddress").await;
        if action == "AddAnyPortMapping" {
            router.next(action).await;
        }
        assert!(router.requests.try_recv().is_err());
    }
    shutdown().await;
}

#[tokio::test]
async fn augmentation_filters_bad_candidates_and_deduplicates_mapping_candidates() {
    let _guard = setup().await;
    let mut router = Router::new(vec![]).await;
    let local = local();
    let mut addresses = vec![
        PunchingAddressInfo {
            network: "tcp4".into(),
            ..address(local)
        },
        PunchingAddressInfo {
            lan: "invalid".into(),
            ..address(local)
        },
        PunchingAddressInfo {
            lan: "[::1]:1234".into(),
            ..address(local)
        },
        PunchingAddressInfo {
            lan: "127.0.0.1:0".into(),
            ..address(local)
        },
        PunchingAddressInfo {
            lan: "10.0.0.2:1234".into(),
            ..address(local)
        },
    ];
    assert!(
        augment(&scope(), &mut addresses, discovery(&router.gateway))
            .await
            .is_empty()
    );
    assert!(router.requests.try_recv().is_err());
    set_enabled(false);
    assert!(
        augment(&scope(), &mut addresses, discovery(&router.gateway))
            .await
            .is_empty()
    );
    set_enabled(true);
    assert!(augment(
        &Scope::from_timeout(Duration::ZERO),
        &mut addresses,
        discovery(&router.gateway)
    )
    .await
    .is_empty());
    addresses = vec![address(local), address(local)];
    let leases = super::super::augment(&scope(), &mut addresses, discovery(&router.gateway)).await;
    assert_eq!(leases.len(), 1);
    assert_eq!(addresses.len(), 3);
    assert_eq!(addresses[0].nat_type, "hard");
    assert_eq!(addresses[2].nat, "8.8.8.8:45678");
    let reused = augment(&scope(), &mut addresses, discovery(&router.gateway)).await;
    assert_eq!(reused.len(), 1);
    assert!(Arc::ptr_eq(&leases[0], &reused[0]));
    assert_eq!(addresses.len(), 3);
    router.next("GetExternalIPAddress").await;
    router.next("AddAnyPortMapping").await;
    let peer = vec![PunchingAddressInfo {
        nat_type: "symm".into(),
        lan: "192.168.1.2:1234".into(),
        nat: "1.1.1.1:2345".into(),
        ..address(local)
    }];
    let (_, pairs) =
        super::super::super::candidates::build_base_p2p_candidates(&addresses, &peer, false);
    assert!(pairs
        .final_results
        .iter()
        .any(|p| p.local_nat_type == "easy" && p.remote_nat_type == "symm"));
    drop(leases);
    drop(reused);
    shutdown().await;
    router.next("DeletePortMapping").await;
}

#[tokio::test]
async fn cancellation_and_collection_deadline_clean_up_late_success() {
    let _guard = setup().await;
    for cancel_explicitly in [true, false] {
        let mut router = Router::new(vec![]).await;
        // Hold the registry so the mapping cannot start until collection ends.
        let registry = LEASES.get().unwrap().lock().await;
        let cancel = Arc::new(super::super::super::CancelToken::new());
        let scope = Scope::from_timeout(if cancel_explicitly {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(20)
        })
        .with_cancel(cancel.clone());
        let gateway = router.gateway.clone();
        let mut addresses = vec![address(local())];
        let task =
            tokio::spawn(async move { augment(&scope, &mut addresses, discovery(&gateway)).await });
        tokio::task::yield_now().await;
        if cancel_explicitly {
            cancel.cancel();
        }
        assert!(task.await.unwrap().is_empty());
        drop(registry);
        shutdown().await;
        assert!(
            router.requests.try_recv().is_err(),
            "expired interest must not start mapping"
        );
        set_enabled(true);
    }
    // Cancel after SOAP creation has started, while its reply is pending.
    for late_success in [true, false] {
        let mut router = Router::new(vec![(
            "AddAnyPortMapping",
            if late_success {
                Reply::Late
            } else {
                Reply::Delay
            },
        )])
        .await;
        let cancel = Arc::new(super::super::super::CancelToken::new());
        let context = scope().with_cancel(cancel.clone());
        let gateway = router.gateway.clone();
        let task = tokio::spawn(async move {
            augment(&context, &mut vec![address(local())], discovery(&gateway)).await
        });
        router.next("GetExternalIPAddress").await;
        router.next("AddAnyPortMapping").await;
        cancel.cancel();
        assert!(task.await.unwrap().is_empty());
        shutdown().await;
        if late_success {
            router.next("DeletePortMapping").await;
        }
        assert_eq!(WORKERS.load(Ordering::SeqCst), 0);
        set_enabled(true);
    }
    shutdown().await;
}

#[tokio::test]
async fn renewal_success_wan_change_and_delete_failures_retire_the_lease() {
    let _guard = setup().await;
    let mut router = Router::new(vec![]).await;
    let (interest, _rx) = oneshot::channel();
    let lease = create_with_period(
        local(),
        router.gateway.clone(),
        &interest,
        Duration::from_millis(20),
    )
    .await
    .unwrap();
    router.next("GetExternalIPAddress").await;
    router.next("AddAnyPortMapping").await;
    router.next("AddPortMapping").await;
    router.next("GetExternalIPAddress").await;
    drop(lease);
    shutdown().await;
    router.next("DeletePortMapping").await;
    set_enabled(true);
    for delete in [
        Reply::Success(String::new()),
        Reply::Malformed,
        Reply::Delay,
    ] {
        let mut router = Router::new(vec![
            (
                "GetExternalIPAddress",
                Reply::Success("<NewExternalIPAddress>8.8.8.8</NewExternalIPAddress>".into()),
            ),
            (
                "GetExternalIPAddress",
                Reply::Success("<NewExternalIPAddress>8.8.4.4</NewExternalIPAddress>".into()),
            ),
            ("DeletePortMapping", delete),
        ])
        .await;
        let local = local();
        let (interest, _rx) = oneshot::channel();
        GATEWAYS.get().unwrap().lock().unwrap().insert(
            Ipv4Addr::LOCALHOST,
            (Instant::now(), Some(router.gateway.clone())),
        );
        let lease = create_with_period(
            local,
            router.gateway.clone(),
            &interest,
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        router.next("GetExternalIPAddress").await;
        router.next("AddAnyPortMapping").await;
        router.next("AddPortMapping").await;
        router.next("GetExternalIPAddress").await;
        router.next("DeletePortMapping").await;
        shutdown().await;
        assert!(!lease.active.load(Ordering::SeqCst));
        assert!(!GATEWAYS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .contains_key(&Ipv4Addr::LOCALHOST));
        drop(lease);
        set_enabled(true);
    }
    // One failed renewal must retain the lease for a bounded retry, rather than
    // tearing down a working tunnel immediately.
    for action in ["AddPortMapping", "GetExternalIPAddress"] {
        let steps = if action == "GetExternalIPAddress" {
            vec![
                (
                    action,
                    Reply::Success("<NewExternalIPAddress>8.8.8.8</NewExternalIPAddress>".into()),
                ),
                (action, Reply::Fault),
            ]
        } else {
            vec![(action, Reply::Fault)]
        };
        let mut router = Router::new(steps).await;
        let (interest, _rx) = oneshot::channel();
        let lease = create_with_period(
            local(),
            router.gateway.clone(),
            &interest,
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        router.next("GetExternalIPAddress").await;
        router.next("AddAnyPortMapping").await;
        router.next("AddPortMapping").await;
        router.next("GetExternalIPAddress").await;
        // Shutdown waits for the worker, including any response still in flight.
        assert!(lease.active.load(Ordering::SeqCst));
        drop(lease);
        shutdown().await;
        router.next("DeletePortMapping").await;
        set_enabled(true);
    }
    shutdown().await;
}
