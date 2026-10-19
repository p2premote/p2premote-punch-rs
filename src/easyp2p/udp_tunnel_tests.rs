use super::super::signal::{ExternalSignalSession, SendFuture, SessionIdentity, WireSender};
use super::*;

struct NoNetwork;
impl WireSender for NoNetwork {
    fn send(&self, _: String, _: std::time::Instant) -> SendFuture<'_> {
        Box::pin(async { panic!("invalid inputs must not send signaling") })
    }
}
fn call(id: &str, token: &str) -> Arc<SignalCall> {
    ExternalSignalSession::new(
        SessionIdentity {
            connection_id: "input-check".into(),
            attempt_id: "attempt".into(),
            local_device_id: 1,
            peer_device_id: 2,
        },
        Arc::new(NoNetwork),
    )
    .unwrap()
    .register_call(id, token, Duration::from_secs(5))
    .unwrap()
}
fn request() -> UdpTunnelInput {
    UdpTunnelInput {
        token: "valid-token-123456".into(),
        role_hint: "active".into(),
        traversal_mode: "lan".into(),
        network: "udp4".into(),
        remote_target_port: 41118,
        ..Default::default()
    }
}

#[tokio::test]
async fn invalid_public_inputs_fail_before_network_io() {
    for variant in 0..11 {
        let mut req = request();
        let expected = match variant {
            0 => {
                req.token.clear();
                ErrorCode::NativeInputInvalidArgument
            }
            1 => {
                req.role_hint = "invalid".into();
                ErrorCode::NativeInputInvalidArgument
            }
            2 => {
                req.traversal_mode = "invalid".into();
                ErrorCode::TraversalPlanNegotiationInvalidPayload
            }
            3 => {
                req.role_hint.clear();
                ErrorCode::NativeInputInvalidArgument
            }
            4 => {
                req.network = "invalid".into();
                ErrorCode::NativeInputInvalidArgument
            }
            5 => {
                req.allow_relay = true;
                ErrorCode::NativeInputInvalidArgument
            }
            6 => {
                req.remote_target_port = 0;
                ErrorCode::NativeInputInvalidArgument
            }
            7 => {
                req.remote_target_port = -1;
                ErrorCode::NativeInputInvalidArgument
            }
            8 => {
                req.remote_target_port = 65536;
                ErrorCode::NativeInputInvalidArgument
            }
            9 => {
                req.role_hint = "passive".into();
                req.remote_target_port = 0;
                ErrorCode::NativeInputInvalidArgument
            }
            _ => {
                req.role_hint.clear();
                req.traversal_mode = "internet".into();
                req.network.clear();
                req.remote_target_port = 0;
                ErrorCode::NativeInputInvalidArgument
            }
        };
        let error = start_udp_tunnel_with_signal(req, Duration::from_secs(1), None)
            .await
            .err()
            .expect("must reject invalid request");
        assert_eq!(error.code(), expected, "input case {variant}");
    }
}

#[tokio::test]
async fn mismatched_external_context_never_sends_or_starts_native_probe() {
    for id in ["network/1", "wg-config"] {
        for token_matches in [false, true] {
            if id == "network/1" && token_matches {
                continue;
            }
            let mut req = request();
            req.local_listen_ip = "127.0.0.1".into();
            req.remote_target_ip = "127.0.0.1".into();
            req.timeout_secs = if token_matches { 1 } else { 0 };
            let signal = call(
                id,
                if token_matches {
                    &req.token
                } else {
                    "another-token-123"
                },
            );
            let error = start_udp_tunnel_with_signal(req, Duration::from_secs(1), Some(signal))
                .await
                .err()
                .unwrap();
            assert_eq!(error.code(), ErrorCode::NativeInputInvalidArgument);
            assert_eq!(error.to_string(), "signal_context_mismatch");
        }
    }
}

#[test]
fn capability_matrix_rejects_conflicts_and_requires_mutual_lan_support() {
    let modes = ["auto", "internet", "lan"];
    let expected = [
        [Some("lan"), Some("internet"), Some("lan")],
        [Some("internet"), Some("internet"), None],
        [Some("lan"), None, Some("lan")],
    ];
    for (i, left) in modes.iter().enumerate() {
        for (j, right) in modes.iter().enumerate() {
            let local = TraversalCapability {
                version: 1,
                mode: (*left).into(),
                supports_lan: true,
            };
            let remote = TraversalCapability {
                version: 1,
                mode: (*right).into(),
                supports_lan: true,
            };
            match expected[i][j] {
                Some(mode) => {
                    assert_eq!(select_negotiated_traversal(&local, &remote).unwrap(), mode)
                }
                None => assert_eq!(
                    select_negotiated_traversal(&local, &remote)
                        .unwrap_err()
                        .code(),
                    ErrorCode::TraversalPlanNegotiationInvalidPayload
                ),
            }
        }
    }
    for (left, right) in [(true, false), (false, true), (false, false)] {
        for mode in ["lan", "auto"] {
            let local = TraversalCapability {
                version: 1,
                mode: mode.into(),
                supports_lan: left,
            };
            let remote = TraversalCapability {
                version: 1,
                mode: "auto".into(),
                supports_lan: right,
            };
            let result = select_negotiated_traversal(&local, &remote);
            if mode == "lan" {
                assert_eq!(
                    result.unwrap_err().code(),
                    ErrorCode::TraversalPlanNegotiationInvalidPayload
                );
            } else {
                assert_eq!(result.unwrap(), "internet");
            }
        }
    }
    let local = TraversalCapability {
        version: 1,
        mode: "auto".into(),
        supports_lan: true,
    };
    for (version, mode) in [(0, "auto"), (1, ""), (1, "bad")] {
        let remote = TraversalCapability {
            version,
            mode: mode.into(),
            supports_lan: true,
        };
        assert_eq!(
            select_negotiated_traversal(&local, &remote)
                .unwrap_err()
                .code(),
            ErrorCode::TraversalPlanNegotiationInvalidPayload
        );
    }
    for (input, expected) in [
        ("", "internet"),
        ("auto", "auto"),
        ("lan", "lan"),
        ("internet", "internet"),
    ] {
        assert_eq!(normalize_traversal_mode(input).unwrap(), expected);
    }
}

#[test]
fn failure_diagnostics_preserve_cause_and_available_address_evidence() {
    let error = P2pError::new(ErrorCode::TraversalPunchTimeout, "probe failed").with_details(
        super::super::candidates::P2PAttemptDetails {
            network: "udp4".into(),
            is_client: true,
            local_lan: "10.0.0.1:1".into(),
            local_nat: "203.0.113.1:2".into(),
            local_nat_type: "hard".into(),
            remote_lan: "192.168.0.1:3".into(),
            remote_nat: "198.51.100.1:4".into(),
            remote_nat_type: "symm".into(),
        },
    );
    let failure = udp_tunnel_error(3, &error, "all attempts exhausted");
    assert_eq!(failure.code(), ErrorCode::TraversalPunchTimeout);
    let result = failure.tunnel_result.unwrap();
    assert!(!result.ok);
    assert_eq!(result.attempts, 3);
    assert!(result.is_client);
    assert_eq!(result.network, "udp4");
    assert_eq!(result.local_nat_type, "hard");
    assert_eq!(result.remote_nat_type, "symm");
    assert_eq!(result.local_lan_addr, "10.0.0.1:1");
    assert_eq!(result.remote_nat_addr, "198.51.100.1:4");
    assert_eq!(result.error_code, "traversal.punch.timeout");
    let plain = StartError::from(P2pError::new(ErrorCode::SignalSendTimeout, "send failed"));
    assert_eq!(plain.code(), ErrorCode::SignalSendTimeout);
    assert!(std::error::Error::source(&plain).is_some());
    let mut source: &dyn std::error::Error = &plain;
    while source.to_string() != "send failed" {
        source = source
            .source()
            .expect("original diagnostic retained in source chain");
    }
    let result = plain.tunnel_result.unwrap();
    assert!(result.network.is_empty());
    assert!(result.error.contains("send failed"));
}

#[tokio::test]
async fn internet_mode_skips_capability_exchange_and_invalid_role_does_not_send() {
    let scope=Scope::from_timeout(Duration::from_secs(1));
    let decision=coordinate_traversal_mode(&scope,"internet","","unused",None).await.unwrap();
    assert_eq!(decision.selected_traversal,"internet");
    let session=ExternalSignalSession::new(SessionIdentity {connection_id:"input-check".into(),attempt_id:"attempt".into(),local_device_id:1,peer_device_id:2},Arc::new(NoNetwork)).unwrap();
    let call=session.register_call("network/1","valid-token-123456",Duration::from_secs(1)).unwrap();
    let error=exchange_role_payload(&scope,"invalid-role","valid-token-123456","capability",&false,scope.remaining(),Some(call)).await.unwrap_err();
    assert_eq!(error.code(),ErrorCode::TraversalPlanNegotiationInvalidPayload);
}
