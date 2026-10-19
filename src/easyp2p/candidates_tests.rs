use super::*;

fn address(network: &str, nat_type: &str, lan: &str, nat: &str) -> PunchingAddressInfo {
    PunchingAddressInfo {
        network: network.into(),
        nat_type: nat_type.into(),
        lan: lan.into(),
        nat: nat.into(),
    }
}
fn pair(network: &str, left: &str, right: &str) -> P2PAddressInfo {
    P2PAddressInfo {
        network: network.into(),
        local_lan: "10.1.0.2:1000".into(),
        local_nat: "203.0.113.1:2000".into(),
        local_nat_type: left.into(),
        remote_lan: "192.168.0.2:3000".into(),
        remote_nat: "198.51.100.1:4000".into(),
        remote_nat_type: right.into(),
        ..Default::default()
    }
}
fn reverse(info: &P2PAddressInfo) -> P2PAddressInfo {
    P2PAddressInfo {
        local_lan: info.remote_lan.clone(),
        local_nat: info.remote_nat.clone(),
        local_nat_type: info.remote_nat_type.clone(),
        remote_lan: info.local_lan.clone(),
        remote_nat: info.local_nat.clone(),
        remote_nat_type: info.local_nat_type.clone(),
        ..info.clone()
    }
}

#[test]
fn candidate_matrix_keeps_same_lan_and_filters_internet_pairs() {
    let kinds = ["easy", "hard", "symm", "relay", "invalid"];
    let udp = ["11110", "11110", "11010", "11110", "00000"];
    let tcp = ["11110", "10000", "10000", "10000", "00000"];
    for network in ["udp4", "tcp4"] {
        for same_lan in [false, true] {
            for (i, left) in kinds.iter().enumerate() {
                for (j, right) in kinds.iter().enumerate() {
                    let local = address(network, left, "10.0.0.2:1000", "203.0.113.1:2000");
                    let remote = address(
                        network,
                        right,
                        if same_lan {
                            "10.0.0.3:3000"
                        } else {
                            "192.168.0.2:3000"
                        },
                        if same_lan {
                            "203.0.113.1:4000"
                        } else {
                            "198.51.100.1:4000"
                        },
                    );
                    let (probes, built) = build_base_p2p_candidates(&[local], &[remote], true);
                    let accepted = if same_lan {
                        i < 4 && j < 4
                    } else {
                        (if network == "udp4" { udp[i] } else { tcp[i] }).as_bytes()[j] == b'1'
                    };
                    assert!(built.have_common_network);
                    assert_eq!(
                        built.final_results.len(),
                        usize::from(accepted),
                        "{network} {left}/{right} same_lan={same_lan}"
                    );
                    if !probes.is_empty() {
                        assert_eq!(network, "tcp4");
                        assert!(!accepted);
                        assert!(probes[0].info.lan_probe_only);
                        assert_eq!((probes[0].local_order, probes[0].remote_order), (0, 0));
                    }
                }
            }
        }
    }
    let local = address("udp4", "easy", "10.0.0.2:1", "203.0.113.1:2");
    let remote = address("udp6", "easy", "[fd00::1]:1", "[2001:db8::1]:2");
    let (probes, built) = build_base_p2p_candidates(&[local], &[remote], false);
    assert!(!built.have_common_network);
    assert!(probes.is_empty() && built.final_results.is_empty());
}

#[test]
fn tcp_lan_probe_requires_peer_capability_and_private_addresses() {
    for supports in [false, true] {
        for private in [false, true] {
            let a = address("tcp4", "hard", "10.0.0.2:1", "203.0.113.1:2");
            let b = address(
                "tcp4",
                "hard",
                if private {
                    "192.168.0.2:1"
                } else {
                    "198.51.100.2:1"
                },
                "198.51.100.1:2",
            );
            let (probe, built) = build_base_p2p_candidates(&[a], &[b], supports);
            assert!(built.final_results.is_empty());
            assert_eq!(probe.len(), usize::from(supports && private));
        }
    }
}

#[test]
fn private_and_lan_address_boundaries_are_explicit() {
    for (ip, expected) in [
        ("10.255.0.1", true),
        ("172.15.0.1", false),
        ("172.16.0.1", true),
        ("172.31.0.1", true),
        ("172.32.0.1", false),
        ("192.168.0.1", true),
        ("192.169.0.1", false),
        ("8.8.8.8", false),
        ("fc00::1", true),
        ("fd00::1", true),
        ("fe80::1", false),
        ("::1", false),
    ] {
        assert_eq!(ip_is_private(ip.parse().unwrap()), expected, "{ip}");
    }
    for (a, b, expected) in [
        ("127.0.0.1", "127.0.0.2", true),
        ("10.1.2.3", "10.9.8.7", true),
        ("172.16.0.1", "172.16.5.2", true),
        ("172.16.0.1", "172.17.0.1", false),
        ("192.168.0.1", "192.168.99.1", true),
        ("203.0.113.1", "203.0.113.2", true),
        ("203.0.113.1", "203.0.114.1", false),
        ("fd00:1:2:3::1", "fd00:1:2:3::2", true),
        ("fd00:1:2:3::1", "fd00:1:2:4::1", false),
        ("2001:db8::1", "2001:db8::2", false),
        ("10.0.0.1", "fd00::1", false),
        ("bad", "10.0.0.1", false),
        ("10.0.0.1", "bad", false),
    ] {
        assert_eq!(is_same_lan(a, b), expected, "{a} {b}");
        assert_eq!(is_same_lan(b, a), expected);
    }
    for (input, expected) in [
        ("10.0.0.1:42", "10.0.0.1"),
        ("[fd00::1]:42", "fd00::1"),
        ("fd00::1", "fd00::1"),
        ("10.0.0.1", "10.0.0.1"),
        ("invalid", ""),
    ] {
        assert_eq!(extract_ip(input), expected);
    }
    assert!(!both_private_lan("bad", "10.0.0.1:1"));
    assert!(!both_private_lan("host:1", "10.0.0.1:1"));
    assert!(!both_private_lan("10.0.0.1:1", "8.8.8.8:1"));
}

#[test]
fn lan_probe_is_bounded_to_first_round_and_gateway_exception() {
    let base = pair("udp4", "easy", "hard");
    assert!(should_try_lan_probe(false, 1, &base));
    assert!(!should_try_lan_probe(true, 1, &base));
    assert!(!should_try_lan_probe(false, 2, &base));
    for (local, remote) in [
        ("bad", "10.0.0.1:1"),
        ("host:1", "10.0.0.1:1"),
        ("8.8.8.8:1", "10.0.0.1:1"),
        ("10.0.0.1:1", "8.8.8.8:1"),
    ] {
        let info = P2PAddressInfo {
            local_lan: local.into(),
            remote_lan: remote.into(),
            ..base.clone()
        };
        assert!(!should_try_lan_probe(false, 1, &info));
    }
    let mut direct = base.clone();
    direct.local_nat = direct.local_lan.clone();
    direct.remote_nat = direct.remote_lan.clone();
    assert!(!should_try_lan_probe(false, 1, &direct));
    let gateway = P2PAddressInfo {
        local_lan: "203.0.113.1:2".into(),
        local_nat: "203.0.113.1:2".into(),
        remote_nat: "203.0.113.1:3".into(),
        ..base
    };
    assert!(should_try_lan_probe(false, 1, &gateway));
    assert!(should_try_lan_probe(false, 1, &reverse(&gateway)));
}

#[test]
fn selected_roles_are_complementary_and_lan_candidate_choice_is_symmetric() {
    for (left, right, expected) in [
        ("easy", "hard", false),
        ("hard", "easy", true),
        ("easy", "symm", false),
        ("symm", "easy", true),
        ("hard", "symm", true),
        ("symm", "hard", false),
    ] {
        let info = pair("udp4", left, right);
        assert_eq!(select_role(&info), expected);
        assert_eq!(select_role(&reverse(&info)), !expected);
    }
    let a = pair("tcp4", "hard", "hard");
    let mut b = a.clone();
    b.local_lan = "10.1.0.3:1000".into();
    assert_ne!(select_role(&a), select_role(&reverse(&a)));
    let candidates = |reversed: bool| {
        vec![
            LanProbeCandidate {
                info: if reversed { reverse(&a) } else { a.clone() },
                local_order: 1,
                remote_order: 0,
            },
            LanProbeCandidate {
                info: if reversed { reverse(&b) } else { b.clone() },
                local_order: 0,
                remote_order: 0,
            },
        ]
    };
    assert!(select_lan_probe_candidate(vec![], true).is_none());
    let legacy = select_lan_probe_candidate(candidates(false), false).unwrap();
    assert_eq!(legacy.local_lan, b.local_lan);
    let left = select_lan_probe_candidate(candidates(false), true).unwrap();
    let right = select_lan_probe_candidate(candidates(true), true).unwrap();
    assert_eq!(left.local_lan, right.remote_lan);
    assert_eq!(left.remote_nat, right.local_nat);
}

#[test]
fn public_ip_count_and_alternatives_skip_ineligible_candidates() {
    let addrs = vec![
        address("udp4", "easy", "", "203.0.113.1:1"),
        address("tcp4", "hard", "", "203.0.113.1:2"),
        address("udp4", "relay", "", "198.51.100.1:1"),
        address("udp6", "easy", "", "[fd00::1]:1"),
        address("udp4", "easy", "", "198.51.100.2"),
    ];
    assert_eq!(count_unique_public_ips(&addrs, "4"), 2);
    assert_eq!(count_unique_public_ips(&addrs, "6"), 1);
    assert!(has_cap(&["lan".into()], "lan"));
    assert!(!has_cap(&[], "lan"));
    let a = pair("udp4", "easy", "easy");
    let mut b = a.clone();
    b.remote_nat = "198.51.100.2:4000".into();
    let mut relay = a.clone();
    relay.local_nat_type = "relay".into();
    let mut remote_relay = a.clone();
    remote_relay.remote_nat_type = "relay".into();
    let mut probe = a.clone();
    probe.lan_probe_only = true;
    let tcp = pair("tcp4", "easy", "easy");
    let mut infos = vec![a, b, relay, remote_relay, probe, tcp];
    collect_udp4_nat_alternatives(&mut infos);
    assert_eq!(
        infos[0].remote_udp4_nat_alternatives,
        vec![infos[1].remote_nat.clone()]
    );
    assert_eq!(
        infos[1].remote_udp4_nat_alternatives,
        vec![infos[0].remote_nat.clone()]
    );
    assert!(infos[2..]
        .iter()
        .all(|i| i.remote_udp4_nat_alternatives.is_empty()));
}

#[test]
fn sorted_candidates_prefer_network_then_nat_and_are_peer_symmetric() {
    let mut infos = vec![
        pair("udp4", "easy", "easy"),
        pair("tcp4", "hard", "hard"),
        pair("tcp6", "easy", "easy"),
        pair("udp6", "easy", "easy"),
        pair("tcp4", "easy", "easy"),
    ];
    let mut tied = infos[4].clone();
    tied.local_lan = "10.1.0.1:1".into();
    infos.push(tied);
    let sorted = sort_p2p_address_infos(infos.clone());
    assert_eq!(
        sorted
            .iter()
            .map(|i| i.network.as_str())
            .collect::<Vec<_>>(),
        vec!["tcp6", "tcp4", "tcp4", "tcp4", "udp6", "udp4"]
    );
    assert_eq!(sorted[1].local_nat_type, "easy");
    assert_eq!(sorted[3].local_nat_type, "hard");
    let reversed = sort_p2p_address_infos(infos.iter().map(reverse).collect());
    for (a, b) in sorted.iter().zip(&reversed) {
        assert_eq!(a.local_lan, b.remote_lan);
        assert_eq!(a.remote_nat, b.local_nat);
    }
    assert_eq!(get_network_priority("invalid"), 0);
    assert_eq!(get_nat_type_priority("invalid"), 0);
}

#[test]
fn incomplete_and_conflicting_address_evidence_is_not_invented() {
    assert!(rejected_attempt_details(&[], &[]).network.is_empty());
    let local = vec![
        address("udp4", "hard", "10.0.0.1:1", "1.1.1.1:1"),
        address("udp4", "symm", "10.0.0.2:1", "1.1.1.1:2"),
        address("tcp4", "easy", "10.0.0.1:3", "1.1.1.1:3"),
    ];
    let remote = vec![address("udp4", "invalid", "192.168.0.1:1", "8.8.8.8:1")];
    let evidence = rejected_attempt_details(&local, &remote);
    assert_eq!(evidence.network, "udp4");
    assert!(evidence.local_nat_type.is_empty());
    assert!(evidence.remote_nat_type.is_empty());
    let base = pair("udp4", "hard", "symm");
    for (left, right) in [("", "8.8.8.8:1"), ("1.1.1.1:1", ""), ("bad", "bad")] {
        let info = P2PAddressInfo {
            local_nat: left.into(),
            remote_nat: right.into(),
            ..base.clone()
        };
        assert!(!compare_p2p_addresses(&info).0);
        assert!(!is_gateway_with_internal(&info));
    }
    assert!(!both_private_lan("8.8.8.8:1", "10.0.0.1:1"));
    assert!(!is_same_lan("127.0.0.1", "10.0.0.1"));
    assert!(!is_same_lan("fd00::1", "2001:4860::1"));
    assert!(!is_same_lan("10.0.0.1", "172.16.0.1"));
    assert!(!is_same_lan("172.16.0.1", "192.168.0.1"));
    assert!(!is_same_lan("192.168.0.1", "10.0.0.1"));
    assert!(!is_same_lan("1.1.1.1", "8.8.8.8"));
    let gateway = P2PAddressInfo {
        local_nat: "1.1.1.1:1".into(),
        remote_nat: "1.1.1.1:2".into(),
        local_lan: "1.1.1.1:1".into(),
        remote_lan: "host:1".into(),
        ..base.clone()
    };
    assert!(!is_gateway_with_internal(&gateway));
    assert!(!is_gateway_with_internal(&reverse(&gateway)));
    assert!(!should_try_lan_probe(
        false,
        1,
        &P2PAddressInfo {
            remote_lan: "".into(),
            ..base.clone()
        }
    ));
    let a = address("tcp4", "symm", "10.0.0.1:1", "1.1.1.1:1");
    let b = address("tcp4", "symm", "192.168.0.1:1", "8.8.8.8:1");
    assert!(build_base_p2p_candidates(&[a], &[b], false).0.is_empty());
}

#[test]
fn legacy_probe_selection_prioritizes_remote_order_before_local_order() {
    let make = |local_order, remote_order, port| LanProbeCandidate {
        local_order,
        remote_order,
        info: P2PAddressInfo {
            local_lan: format!("10.0.0.1:{port}"),
            ..pair("tcp4", "hard", "hard")
        },
    };
    let chosen = select_lan_probe_candidate(
        vec![make(0, 2, 1), make(2, 0, 2), make(1, 0, 3), make(3, 1, 4)],
        false,
    )
    .unwrap();
    assert_eq!(chosen.local_lan, "10.0.0.1:3");
    let reversed = reverse(&pair("tcp4", "hard", "hard"));
    let sorted = sort_p2p_address_infos(vec![reversed.clone(), reversed]);
    assert_eq!(sorted.len(), 2);
}
