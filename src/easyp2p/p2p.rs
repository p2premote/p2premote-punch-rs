//! Port of Do_autoP2PEx2 + Easy_P2P_MPWithOptions (easyp2p/p2p.go): STUN
//! discovery, encrypted address exchange with ECDH, candidate iteration with
//! MQTT round sync, UDP hole punching.

use std::sync::Arc;
use std::time::Duration;

use super::candidates::{self, ExchangeAddressPayload, P2PAddressInfo, P2PAttemptDetails};
use super::crypto::{self, EcdhKeyPair};
use super::mqtt_signal::{self, MqttSignalSession};
use super::punch_tcp;
use super::punch_udp;
use super::stun;
use super::netx;
use super::{P2pError, Result, Scope, CAP_CANONICAL_LAN_PROBE, CAP_LAN_PROBE, CAP_MULTI_EXIT_UDP_PUNCH, EXMODE_MUTUAL, TOPIC_DESC_SIGNAL};

pub struct P2PSessionContext {
    pub shared_key: [u8; 32],
    /// None in LAN-only mode (no MQTT signaling); Some for Internet traversal.
    pub signal: Option<Arc<MqttSignalSession>>,
    pub local_public_ipv4_count: usize,
}

/// Transport-agnostic punched connection: UDP socket or TCP stream.
pub enum P2PConn {
    Udp(punch_udp::PunchedConn),
    Tcp(punch_tcp::TcpPunchedConn),
}

impl P2PConn {
    pub fn remote_addr(&self) -> String {
        match self {
            P2PConn::Udp(conn) => conn.remote_addr().to_string(),
            P2PConn::Tcp(conn) => conn.remote.to_string(),
        }
    }
}

/// A punched P2P connection plus the diagnostics the FFI reports.
pub struct P2PConnInfo {
    pub conn: P2PConn,
    #[allow(dead_code)]
    pub shared_key: [u8; 32],
    #[allow(dead_code)]
    pub is_client: bool,
    pub networks_used: Vec<String>,
    pub peer_address: String,
    pub local_nat_type: String,
    pub remote_nat_type: String,
    pub local_lan: String,
    pub local_nat: String,
    pub remote_lan: String,
    pub remote_nat: String,
}

pub struct EasyP2PMPOptions {
    pub bind: String,
}

impl Default for EasyP2PMPOptions {
    fn default() -> Self {
        EasyP2PMPOptions { bind: String::new() }
    }
}

pub fn attempt_details(info: Option<&P2PAddressInfo>, sess_ctx: Option<&P2PSessionContext>) -> P2PAttemptDetails {
    let Some(info) = info else {
        return P2PAttemptDetails::default();
    };
    let is_client = match sess_ctx {
        Some(_ctx) => {
            let probe = P2PAddressInfo {
                network: info.network.clone(),
                local_lan: info.local_lan.clone(),
                local_nat: info.local_nat.clone(),
                local_nat_type: info.local_nat_type.clone(),
                remote_lan: info.remote_lan.clone(),
                remote_nat: info.remote_nat.clone(),
                remote_nat_type: info.remote_nat_type.clone(),
                ..Default::default()
            };
            candidates::select_role(&probe, "")
        }
        None => false,
    };
    P2PAttemptDetails {
        network: info.network.clone(),
        is_client,
        local_lan: info.local_lan.clone(),
        local_nat: info.local_nat.clone(),
        local_nat_type: info.local_nat_type.clone(),
        remote_lan: info.remote_lan.clone(),
        remote_nat: info.remote_nat.clone(),
        remote_nat_type: info.remote_nat_type.clone(),
    }
}

/// detect NAT address info via STUN (DetectNATAddressInfoContext, relay-less).
async fn detect_nat_address_info(scope: &Scope, networks: &[String], bind: &str) -> Result<Vec<candidates::PunchingAddressInfo>> {
    crate::p2plog!("    Getting local public IP info via {} STUN servers...", stun::stun_servers().len());
    let results = stun::get_networks_public_ips(scope, networks, bind, Duration::from_millis(2828)).await;
    let all_results = match results {
        Ok(r) => r,
        Err(err) => {
            crate::p2plog!("    Failed to get public IP info: {}", err);
            Vec::new()
        }
    };
    if scope.expired() {
        return Err(P2pError::msg("operation cancelled"));
    }
    let mut addresses = Vec::new();
    for item in stun::analyze_stun_results(&all_results) {
        addresses.push(candidates::PunchingAddressInfo {
            network: item.network,
            nat_type: item.nattype,
            lan: item.lan,
            nat: item.nat,
        });
    }
    if !addresses.is_empty() {
        crate::p2plog!("    Received {} STUN responses", stun::succeeded_stun_results(&all_results));
        for info in &addresses {
            if info.lan == info.nat {
                crate::p2plog!("      {:<5}: {} ({})", info.network, info.nat, info.nat_type);
            } else {
                crate::p2plog!("      {:<5}: LAN={} | NAT={} ({})", info.network, info.lan, info.nat, info.nat_type);
            }
        }
    }
    Ok(addresses)
}

/// Do_autoP2PEx2: STUN + address exchange + candidate build.
pub async fn do_auto_p2p_ex2(
    scope: &Scope,
    networks: &[String],
    bind: &str,
    session_uid: &str,
    timeout: Duration,
    need_shared_key: bool,
    signal: &Arc<MqttSignalSession>,
) -> Result<(Vec<P2PAddressInfo>, P2PSessionContext)> {
    if scope.expired() {
        return Err(P2pError::msg("operation cancelled"));
    }

    signal
        .prepare_topic(scope, "gonc-exchange-address", session_uid)
        .await
        .map_err(|e| P2pError::msg(format!("failed to prepare MQTT address topic: {}", e)))?;
    signal
        .prepare_topic(scope, "gonc-exchange-sync", session_uid)
        .await
        .map_err(|e| P2pError::msg(format!("failed to prepare MQTT sync topic: {}", e)))?;
    if scope.expired() {
        return Err(P2pError::msg("operation cancelled"));
    }

    let my_addresses = detect_nat_address_info(scope, networks, bind).await?;
    if scope.expired() {
        return Err(P2pError::msg("operation cancelled"));
    }

    let mut my_caps = vec![
        CAP_LAN_PROBE.to_string(),
        CAP_CANONICAL_LAN_PROBE.to_string(),
        CAP_MULTI_EXIT_UDP_PUNCH.to_string(),
    ];
    if std::env::var("CAP_MEP_DEBUG").as_deref() == Ok("0") {
        for cap in my_caps.iter_mut() {
            if cap == CAP_MULTI_EXIT_UDP_PUNCH {
                *cap = format!("!{}", cap);
                break;
            }
        }
    }

    let mut keypair: Option<EcdhKeyPair> = None;
    let mut my_payload = ExchangeAddressPayload {
        addresses: my_addresses,
        pub_key: String::new(),
        caps: my_caps.clone(),
    };
    if need_shared_key && !my_payload.addresses.is_empty() {
        let kp = EcdhKeyPair::generate()?;
        my_payload.pub_key = kp.public_b64.clone();
        keypair = Some(kp);
    }
    if scope.expired() {
        return Err(P2pError::msg("operation cancelled"));
    }

    crate::p2plog!("    Exchanging address info with peer via {} MQTT servers...", super::mqtt_broker_servers().len());
    let (remote_payload, _srv_index) = mqtt_signal::secure_exchange_with_session(
        scope,
        signal,
        EXMODE_MUTUAL,
        &my_payload,
        "gonc-exchange-address",
        session_uid,
        timeout,
        None,
    )
    .await?;

    crate::p2pevent!(
        "address exchange complete: session={}, broker_index={}, local_addrs={:?}, remote_addrs={:?}, local_caps={:?}, remote_caps={:?}",
        session_uid,
        _srv_index,
        my_payload.addresses,
        remote_payload.addresses,
        my_payload.caps,
        remote_payload.caps
    );

    if my_payload.addresses.is_empty() || remote_payload.addresses.is_empty() {
        return Err(P2pError::msg("no common usable network types with peer"));
    }

    let mut shared_key = [0u8; 32];
    if need_shared_key {
        let Some(kp) = keypair else {
            return Err(P2pError::msg("missing public key from peer for key exchange"));
        };
        if remote_payload.pub_key.is_empty() {
            return Err(P2pError::msg("missing public key from peer for key exchange"));
        }
        shared_key = kp.shared_key(&remote_payload.pub_key)?;
    }

    let local_supports_multi_exit = candidates::has_cap(&my_payload.caps, CAP_MULTI_EXIT_UDP_PUNCH);
    let peer_supports_multi_exit = candidates::has_cap(&remote_payload.caps, CAP_MULTI_EXIT_UDP_PUNCH);
    let peer_supports_lan_probe = candidates::has_cap(&remote_payload.caps, CAP_LAN_PROBE);
    let peer_supports_canonical = candidates::has_cap(&remote_payload.caps, CAP_CANONICAL_LAN_PROBE);
    let local_public_ipv4_count = candidates::count_unique_public_ips(&my_payload.addresses, "4");
    let local_public_ipv6_count = candidates::count_unique_public_ips(&my_payload.addresses, "6");
    let remote_public_ipv4_count = candidates::count_unique_public_ips(&remote_payload.addresses, "4");
    let remote_public_ipv6_count = candidates::count_unique_public_ips(&remote_payload.addresses, "6");

    let (lan_probe_candidates, mut built) = candidates::build_base_p2p_candidates(
        &my_payload.addresses,
        &remote_payload.addresses,
        peer_supports_lan_probe,
    );
    if let Some(selected) = candidates::select_lan_probe_candidate(lan_probe_candidates, peer_supports_canonical) {
        built.final_results.push(selected);
    }
    if built.final_results.is_empty() {
        if !built.have_common_network {
            return Err(P2pError::msg("no common usable network types with peer"));
        }
        return Err(P2pError::msg("no usable NAT types with peer"));
    }

    candidates::collect_udp4_nat_alternatives(&mut built.final_results);

    if local_supports_multi_exit && peer_supports_multi_exit {
        let both_have_ipv6 = local_public_ipv6_count > 0 && remote_public_ipv6_count > 0;
        let either_has_multi_ipv4 = local_public_ipv4_count > 1 || remote_public_ipv4_count > 1;
        if !both_have_ipv6 && either_has_multi_ipv4 {
            let has_valid_udp4 = built.final_results.iter().any(|info| {
                info.network == "udp4"
                    && !info.lan_probe_only
                    && info.local_nat_type != "relay"
                    && info.remote_nat_type != "relay"
            });
            if has_valid_udp4 {
                built
                    .final_results
                    .retain(|info| info.network != "tcp4" || info.lan_probe_only);
            }
        }
    }

    let sess_ctx = P2PSessionContext {
        shared_key,
        signal: Some(signal.clone()),
        local_public_ipv4_count,
    };
    let sorted = candidates::sort_p2p_address_infos(built.final_results);
    crate::p2pevent!(
        "candidate selection: session={}, candidates={:?}, local_public_ipv4_count={}, remote_public_ipv4_count={}, local_public_ipv6_count={}, remote_public_ipv6_count={}",
        session_uid,
        sorted,
        local_public_ipv4_count,
        remote_public_ipv4_count,
        local_public_ipv6_count,
        remote_public_ipv6_count
    );
    Ok((sorted, sess_ctx))
}

/// Mqtt_P2P_Round_Sync: exchange "C<n>"/"S<n>" markers before each round.
pub async fn mqtt_p2p_round_sync(
    scope: &Scope,
    session_uid: &str,
    sess_signal: &Arc<MqttSignalSession>,
    is_client: bool,
    round: i32,
    timeout: Duration,
) -> Result<()> {
    let (msg_send, msg_need) = if is_client {
        (format!("C{}", round), format!("S{}", round))
    } else {
        (format!("S{}", round), format!("C{}", round))
    };
    crate::p2plog!("    Exchanging sync message for P2P round {} ...", round);
    let filter_need = msg_need.clone();
    let filter: Arc<dyn Fn(&String) -> std::result::Result<bool, String> + Send + Sync> =
        Arc::new(move |msg: &String| Ok(msg == &filter_need));
    let (msg_recv, _) = mqtt_signal::secure_exchange_with_session::<String>(
        scope,
        sess_signal,
        EXMODE_MUTUAL,
        &msg_send,
        "gonc-exchange-sync",
        session_uid,
        timeout,
        Some(filter),
    )
    .await
    .map_err(|e| P2pError::msg(format!("failed to exchange sync message: {}", e)))?;
    if msg_recv != msg_need {
        return Err(P2pError::msg(format!(
            "expected message '{}', but got '{}'",
            msg_need, msg_recv
        )));
    }
    Ok(())
}

pub fn generate_random_ports(count: usize) -> Vec<u16> {
    let mut rng = rand::thread_rng();
    let mut used: HashSet<u16> = HashSet::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    while ports.len() < count {
        let port: u16 = rand::Rng::gen_range(&mut rng, 1024..65535);
        if used.insert(port) {
            ports.push(port);
        }
    }
    ports
}

use std::collections::HashSet;

/// Easy_P2P_MPWithOptions: full traversal pipeline. TCP candidates
/// (tcp4/tcp6) go to the TCP simultaneous-open state machine, everything else
/// to the UDP puncher.
pub async fn easy_p2p_mp_with_options(
    scope: &Scope,
    network: &str,
    session_uid: &str,
    options: EasyP2PMPOptions,
) -> Result<P2PConnInfo> {
    let networks_to_try_stun = stun::networks_for_stun(network)?;

    crate::p2plog!("=== Checking NAT reachability ===");

    let local_bind_ip = if options.bind.is_empty() {
        String::new()
    } else {
        netx::split_host_port(&options.bind).map(|(h, _)| h).unwrap_or_default()
    };
    let client_id = crypto::mqtt_generate_client_id(TOPIC_DESC_SIGNAL, session_uid);
    let signal = MqttSignalSession::new(scope, &client_id, &local_bind_ip)
        .await
        .map_err(|e| P2pError::msg(format!("failed to prepare MQTT signal session: {}", e)))?;

    let (p2p_infos, sess_ctx) = do_auto_p2p_ex2(
        scope,
        &networks_to_try_stun,
        &options.bind,
        session_uid,
        Duration::from_secs(25),
        true,
        &signal,
    )
    .await
    .map_err(|e| P2pError::msg(format!("failed to exchange address info: {}", e)))?;

    if scope.expired() {
        return Err(P2pError::msg("operation cancelled"));
    }

    let mut round: i32 = 0;
    let mut role: i32 = 0; // 0 unknown, 1 client, 2 server
    let mut networks_used: Vec<String> = Vec::new();
    #[allow(unused_mut)]
    let mut selected: Option<&P2PAddressInfo> = None;
    let max_rounds = 5;

    let infos = p2p_infos;
    let mut index = 0usize;
    while index < infos.len() {
        let p2p_info = &infos[index];
        if scope.expired() {
            return Err(P2pError::msg("operation cancelled"));
        }
        selected = Some(p2p_info);
        // FFI path: relay candidates never exist (allow_relay=false).
        round += 1;
        crate::p2pevent!(
            "candidate round start: session={}, round={}, network={}, local_lan={}, local_nat={}({}), remote_lan={}, remote_nat={}({}), lan_probe_only={}, remote_nat_alternatives={:?}",
            session_uid,
            round,
            p2p_info.network,
            p2p_info.local_lan,
            p2p_info.local_nat,
            p2p_info.local_nat_type,
            p2p_info.remote_lan,
            p2p_info.remote_nat,
            p2p_info.remote_nat_type,
            p2p_info.lan_probe_only,
            p2p_info.remote_udp4_nat_alternatives
        );

        let outcome = if p2p_info.network.starts_with("tcp") {
            punch_tcp::auto_p2p_tcp_nat_traversal(
                scope,
                &p2p_info.network,
                session_uid,
                p2p_info,
                &sess_ctx,
                round,
            )
            .await
            .map(|(conn, is_role_client)| (P2PConn::Tcp(conn), is_role_client))
        } else {
            punch_udp::auto_p2p_udp_nat_traversal(
                scope,
                &p2p_info.network,
                session_uid,
                p2p_info,
                &sess_ctx,
                round,
            )
            .await
            .map(|(conn, is_role_client)| (P2PConn::Udp(conn), is_role_client))
        };

        match outcome {
            Ok((punched, is_role_client)) => {
                if role == 0 {
                    role = if is_role_client { 1 } else { 2 };
                }
                networks_used.push(p2p_info.network.clone());
                let conn_info = P2PConnInfo {
                    peer_address: punched.remote_addr(),
                    conn: punched,
                    shared_key: sess_ctx.shared_key,
                    is_client: role == 1,
                    networks_used,
                    local_nat_type: p2p_info.local_nat_type.clone(),
                    remote_nat_type: p2p_info.remote_nat_type.clone(),
                    local_lan: p2p_info.local_lan.clone(),
                    local_nat: p2p_info.local_nat.clone(),
                    remote_lan: p2p_info.remote_lan.clone(),
                    remote_nat: p2p_info.remote_nat.clone(),
                };
                return Ok(conn_info);
            }
            Err(err) => {
                crate::p2pevent!(
                    "candidate round failed: session={}, round={}, network={}, deadline_expired={}, remaining_ms={}, error={}",
                    session_uid,
                    round,
                    p2p_info.network,
                    scope.expired(),
                    scope.remaining().as_millis(),
                    err
                );
                if scope.expired() {
                    return Err(P2pError::msg("operation cancelled"));
                }
                crate::p2plog!("ERROR: {}", err);
                if err.is_unretryable() || round >= max_rounds {
                    break;
                }
                scope.sleep_until_deadline(Duration::from_secs(1)).await;
            }
        }
        index += 1;
    }

    Err(P2pError::msg("direct P2P connection failed")
        .with_details(attempt_details(selected, Some(&sess_ctx))))
}
