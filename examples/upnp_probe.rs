//! Live local validation. Creates only finite UDP mappings and deletes them.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[tokio::main]
async fn main() {
    use igd_next::{aio::tokio::search_gateway, PortMappingProtocol::UDP, SearchOptions};
    use p2premote_punch::easyp2p::{candidates::PunchingAddressInfo, portmap, stun, Scope};
    use std::{
        net::{IpAddr, SocketAddr},
        time::Duration,
    };
    use tokio::time::timeout;

    portmap::set_enabled(true);
    let networks = vec!["udp4".to_string()];
    let scope = Scope::from_timeout(Duration::from_secs(12));
    let (results, discovery) = tokio::join!(
        stun::get_networks_public_ips(&scope, &networks, "", Duration::from_millis(2828)),
        portmap::discover(&scope, &networks),
    );
    let mut addresses = Vec::new();
    if let Ok(results) = results {
        for result in &results {
            println!("STUN {result:?}");
        }
        for item in stun::analyze_stun_results(&results) {
            println!(
                "BASELINE network={} lan={} nat={} type={}",
                item.network, item.lan, item.nat, item.nattype
            );
            addresses.push(PunchingAddressInfo {
                network: item.network,
                nat_type: item.nattype,
                lan: item.lan,
                nat: item.nat,
            });
        }
    }
    let before = addresses.len();
    let leases = portmap::augment(&scope, &mut addresses, discovery).await;
    println!(
        "PRODUCTION mappings={} status={}",
        leases.len(),
        portmap::status()
    );
    for item in addresses.iter().skip(before) {
        println!("MAPPED_CANDIDATE {item:?}");
    }
    drop(leases);
    portmap::shutdown().await;

    // Diagnose a private upstream WAN or a slow gateway without advertising it
    // as a reachable candidate. These rules are explicitly removed below.
    let mut ips = std::collections::HashSet::new();
    let mut tasks = tokio::task::JoinSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        let IpAddr::V4(ip) = iface.ip() else {
            continue;
        };
        if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || !ips.insert(ip) {
            continue;
        }
        tasks.spawn(async move {
            let gateway = match search_gateway(SearchOptions {
                bind_addr: SocketAddr::from((ip, 0)),
                timeout: Some(Duration::from_secs(3)),
                ..Default::default()
            })
            .await
            {
                Ok(gateway) => gateway,
                Err(error) => {
                    println!("IGD interface={ip} discovery_failed={error}");
                    return;
                }
            };
            println!(
                "IGD interface={ip} gateway={} control={}",
                gateway.addr, gateway.control_url
            );
            let wan = timeout(Duration::from_secs(2), gateway.get_external_ip()).await;
            println!("IGD interface={ip} WAN={wan:?}");
            let socket = match std::net::UdpSocket::bind((ip, 0)) {
                Ok(s) => s,
                Err(e) => {
                    println!("IGD bind failed {e}");
                    return;
                }
            };
            let local = socket.local_addr().unwrap();
            match timeout(
                Duration::from_secs(2),
                gateway.add_any_port(UDP, local, 120, "p2pRemote live validation"),
            )
            .await
            {
                Ok(Ok(port)) => {
                    println!("IGD RULE_CREATED external_port={port} local={local} lease=120s");
                    println!(
                        "IGD RULE_QUERY_BEFORE {:?}",
                        timeout(Duration::from_secs(2), query_rule(&gateway, port)).await
                    );
                    let removed =
                        timeout(Duration::from_secs(2), gateway.remove_port(UDP, port)).await;
                    println!("IGD RULE_DELETED external_port={port} result={removed:?}");
                    println!(
                        "IGD RULE_QUERY_AFTER {:?}",
                        timeout(Duration::from_secs(2), query_rule(&gateway, port)).await
                    );
                }
                error => println!("IGD RULE_FAILED local={local} result={error:?}"),
            }
        });
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(e) = result {
            println!("DIAGNOSTIC_TASK_FAILED {e}");
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
async fn query_rule(
    gateway: &igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>,
    port: u16,
) -> std::io::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = format!("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetSpecificPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>UDP</NewProtocol></u:GetSpecificPortMappingEntry></s:Body></s:Envelope>");
    let request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetSpecificPortMappingEntry\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", gateway.control_url, gateway.addr, body.len(), body);
    let mut stream = tokio::net::TcpStream::connect(gateway.addr).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut bytes = Vec::new();
    stream.take(65536).read_to_end(&mut bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("Desktop-only diagnostic");
}
