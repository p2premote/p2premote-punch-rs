use super::*;

#[test]
fn url_and_resource_validation() {
    let addr = "192.168.1.1:80".parse().unwrap();
    assert_eq!(endpoint("http://192.168.1.1").unwrap(), (addr, "/".into()));
    assert_eq!(
        endpoint("http://192.168.1.1:80/control").unwrap().1,
        "/control"
    );
    for url in [
        "https://192.168.1.1/",
        "http://router.local/",
        "http://192.168.1.1/\r\nBad: x",
    ] {
        assert!(endpoint(url).is_err());
    }
    assert_eq!(
        resource(addr, "control").unwrap(),
        "http://192.168.1.1:80/control"
    );
    assert!(resource(addr, "http://192.168.2.1/control").is_err());
    assert_eq!(
        resource(addr, "http://192.168.1.1/control").unwrap(),
        "http://192.168.1.1/control"
    );
}

#[test]
fn bounded_http_decodes_content_length_eof_and_chunked_responses() {
    assert!(decode(b"HTTP/1.1 200 OK\r\n", false).unwrap().is_none());
    assert!(decode(b"bad", true).is_err());
    assert!(decode(b"bad\r\n\r\n", true).is_err());
    assert!(decode(&vec![b'a'; 16385], false).is_err());
    assert!(decode(b"HTTP/1.1 nope\r\n\r\n", true).is_err());
    assert_eq!(
        decode(b"HTTP/1.1 200 OK\r\nIgnored\r\n\r\nx", true)
            .unwrap()
            .unwrap(),
        b"x"
    );
    assert!(decode(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        false
    )
    .unwrap()
    .is_none());
    assert!(decode(&vec![0; LIMIT + 1], false).is_err());
    assert!(decode(b"HTTP/1.1 200 OK\r\nContent-Length: bad\r\n\r\n", true).is_err());
    assert!(decode(b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n", true).is_err());
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    assert_eq!(decode(response, false).unwrap().unwrap(), b"abc");
    assert!(decode(&response[..response.len() - 1], false)
        .unwrap()
        .is_none());
    assert!(decode(&response[..response.len() - 1], true).is_err());
    assert_eq!(
        decode(b"HTTP/1.0 200 OK\r\n\r\nabc", true)
            .unwrap()
            .unwrap(),
        b"abc"
    );
    assert!(decode(b"HTTP/1.0 200 OK\r\n\r\nabc", false)
        .unwrap()
        .is_none());
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=x\r\nabc\r\n0\r\n\r\n";
    assert_eq!(decode(response, false).unwrap().unwrap(), b"abc");
    for body in ["X\r\n", "40001\r\n", "1\r\naXX", "2\r\na"] {
        let response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
        assert!(decode(response.as_bytes(), true).is_err());
    }
}

#[test]
fn device_and_action_schema_parse_namespaces_and_only_input_arguments() {
    let xml = Element::parse(b"<root xmlns='urn:test'><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl</controlURL><SCPDURL>/scpd</SCPDURL></service></serviceList></device></root>".as_slice()).unwrap();
    assert_eq!(service(&xml).unwrap(), ("/ctl".into(), "/scpd".into()));
    assert!(service(&Element::parse(b"<root/>".as_slice()).unwrap()).is_none());
    assert!(service(
        &Element::parse(b"<service><serviceType>urn:other</serviceType></service>".as_slice())
            .unwrap()
    )
    .is_none());
    let parsed = schema(b"<scpd><actionList><action><name>AddPortMapping</name><argumentList><argument><name>In</name><direction>in</direction></argument><argument><name>Out</name><direction>out</direction></argument></argumentList></action><action><name>Empty</name></action></actionList></scpd>").unwrap();
    assert_eq!(parsed["AddPortMapping"], vec!["In"]);
    assert!(parsed["Empty"].is_empty());
    assert!(schema(b"<broken").is_err());
    assert!(schema(b"<scpd/>").is_err());
}

#[test]
fn discovery_guard_balances_success_denial_and_absent_hook() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    set_discovery_hook(None);
    assert!(DiscoveryGuard::begin().is_none());
    set_discovery_hook(Some(Box::new(|_| false)));
    assert!(DiscoveryGuard::begin().is_none());
    let count = Arc::new(AtomicUsize::new(0));
    let captured = count.clone();
    set_discovery_hook(Some(Box::new(move |active| {
        if active {
            captured.fetch_add(1, Ordering::SeqCst);
        } else {
            captured.fetch_sub(1, Ordering::SeqCst);
        }
        true
    })));
    let one = DiscoveryGuard::begin().unwrap();
    let two = DiscoveryGuard::begin().unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    drop(one);
    drop(two);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    set_discovery_hook(None);
}

#[tokio::test]
async fn protected_provider_sends_soap_and_reads_chunked_reply() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 4096];
        let n = stream.read(&mut buffer).await.unwrap();
        let request = String::from_utf8_lossy(&buffer[..n]);
        assert!(request.contains("POST /control HTTP/1.1"));
        assert!(request.contains("SOAPAction: \"action\""));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
    });
    assert_eq!(
        Protected::send_async(&format!("http://{addr}/control"), "\"action\"", "<body/>")
            .await
            .unwrap(),
        "abc"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn discovery_uses_protected_transport_and_ignores_invalid_advertisements() {
    let http_server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_server.local_addr().unwrap();
    let http_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = http_server.accept().await.unwrap();
            let mut buffer = [0; 4096];
            let n = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..n]);
            let path = request.split_whitespace().nth(1).unwrap();
            let body = match path {
                "/closed" => continue,
                "/bad" => "<broken",
                "/empty" => "<root/>",
                "/root" => "<root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/control</controlURL><SCPDURL>/schema</SCPDURL></service></serviceList></device></root>",
                "/schema" => "<scpd><actionList><action><name>GetExternalIPAddress</name></action></actionList></scpd>",
                "/control" => "<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body><u:GetExternalIPAddressResponse xmlns:u='urn:schemas-upnp-org:service:WANIPConnection:1'><NewExternalIPAddress>8.8.8.8</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>",
                _ => panic!("unexpected path {path}"),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let ssdp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ssdp_addr = ssdp.local_addr().unwrap();
    let ssdp_task = tokio::spawn(async move {
        let mut buffer = [0; 2048];
        let (n, from) = ssdp.recv_from(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).contains("M-SEARCH"));
        ssdp.send_to(b"HTTP/1.1 200 OK\r\n\r\n", from)
            .await
            .unwrap();
        for location in [
            "https://127.0.0.1/root".to_owned(),
            "http://127.0.0.2/root".to_owned(),
            format!("http://{http_addr}/bad"),
            format!("http://{http_addr}/empty"),
            format!("http://{http_addr}/closed"),
            format!("http://{http_addr}/root"),
        ] {
            ssdp.send_to(
                format!("HTTP/1.1 200 OK\r\nLOCATION: {location}\r\n\r\n").as_bytes(),
                from,
            )
            .await
            .unwrap();
        }
    });
    let gateway = search_gateway(SearchOptions {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        broadcast_address: ssdp_addr,
        timeout: Some(std::time::Duration::from_secs(2)),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(gateway.control_url, "/control");
    assert_eq!(gateway.control_schema_url, "/schema");
    assert!(gateway.control_schema.contains_key("GetExternalIPAddress"));
    assert_eq!(
        gateway.get_external_ip().await.unwrap().to_string(),
        "8.8.8.8"
    );
    ssdp_task.await.unwrap();
    http_task.abort();
    let ssdp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(matches!(
        search_gateway(SearchOptions {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            broadcast_address: ssdp.local_addr().unwrap(),
            timeout: Some(std::time::Duration::from_millis(10)),
            ..Default::default()
        })
        .await,
        Err(SearchError::NoResponseWithinTimeout)
    ));
}
