use super::*;

const TXID: [u8; 12] = [0x42; 12];
fn response(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut result = vec![0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    result.extend(TXID);
    result.extend(kind.to_be_bytes());
    result.extend((value.len() as u16).to_be_bytes());
    result.extend(value);
    while result.len() % 4 != 0 {
        result.push(0);
    }
    let len = (result.len() - 20) as u16;
    result[2..4].copy_from_slice(&len.to_be_bytes());
    result
}

#[test]
fn mapped_address_decodes_v4_v6_and_both_attribute_encodings() {
    for ip in [
        "1.2.3.4".parse::<IpAddr>().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
    ] {
        for xor in [false, true] {
            let bytes = match ip {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            let mut value = vec![0, if ip.is_ipv4() { 1 } else { 2 }];
            value.extend((65000u16 ^ if xor { 0x2112 } else { 0 }).to_be_bytes());
            let mut mask = vec![0x21, 0x12, 0xa4, 0x42];
            mask.extend(TXID);
            value.extend(
                bytes
                    .iter()
                    .enumerate()
                    .map(|(i, b)| if xor { *b ^ mask[i] } else { *b }),
            );
            let message = response(if xor { 0x0020 } else { 0x0001 }, &value);
            assert_eq!(
                parse_mapped_address(&message, &TXID),
                Some(SocketAddr::new(ip, 65000))
            );
        }
    }
}

#[test]
fn malformed_stun_frames_cannot_supply_a_mapped_address() {
    let valid = response(ATTR_MAPPED_ADDRESS, &[0, 1, 0x13, 0x88, 1, 2, 3, 4]);
    for len in 0..valid.len() {
        assert!(
            parse_mapped_address(&valid[..len], &TXID).is_none(),
            "truncated at {len}"
        );
    }
    for offset in [0usize, 4, 8] {
        let mut bad = valid.clone();
        bad[offset] ^= 1;
        assert!(
            parse_mapped_address(&bad, &TXID).is_none(),
            "corrupt header at {offset}"
        );
    }
    for kind in [ATTR_MAPPED_ADDRESS, ATTR_XOR_MAPPED_ADDRESS] {
        for family in [0, 2, 3] {
            assert!(
                parse_mapped_address(&response(kind, &[0, family, 0, 1, 1, 2, 3, 4]), &TXID)
                    .is_none()
            );
        }
        assert!(parse_mapped_address(&response(kind, &[0, 1, 0, 1]), &TXID).is_none());
    }
    assert!(parse_mapped_address(&response(0x9999, &[0, 1, 0, 1, 1, 2, 3, 4]), &TXID).is_none());
    let mut padded = response(0x9999, &[1]);
    padded.extend_from_slice(&valid[20..]);
    let len = (padded.len() - 20) as u16;
    padded[2..4].copy_from_slice(&len.to_be_bytes());
    assert_eq!(
        parse_mapped_address(&padded, &TXID).unwrap().to_string(),
        "1.2.3.4:5000"
    );
}

#[test]
fn nat_validation_rejects_non_public_and_server_addresses() {
    let server: SocketAddr = "1.1.1.1:3478".parse().unwrap();
    for ip in [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "255.255.255.255",
        "0.0.0.0",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "::",
        "fe80::1",
        "ff02::1",
        "fd00::1",
    ] {
        assert!(
            validate_nat_ip(ip.parse().unwrap(), server).is_err(),
            "{ip}"
        );
    }
    assert!(validate_nat_ip("1.1.1.1".parse().unwrap(), server)
        .unwrap_err()
        .contains("same as STUN"));
    assert!(validate_nat_ip("8.8.8.8".parse().unwrap(), server).is_ok());
    assert!(validate_nat_ip("2001:4860:4860::8888".parse().unwrap(), server).is_ok());
}

#[test]
fn network_aliases_have_stable_probe_order_and_reject_unknown_names() {
    for (input, expected) in [
        ("any", vec!["tcp6", "tcp4", "udp4"]),
        ("any6", vec!["tcp6"]),
        ("any4", vec!["tcp4", "udp4"]),
        ("tcp", vec!["tcp6", "tcp4"]),
        ("udp", vec!["udp6", "udp4"]),
        ("tcp4", vec!["tcp4"]),
        ("tcp6", vec!["tcp6"]),
        ("udp4", vec!["udp4"]),
        ("udp6", vec!["udp6"]),
    ] {
        assert_eq!(networks_for_stun(input).unwrap(), expected);
    }
    assert_eq!(
        networks_for_stun("quic").unwrap_err().code(),
        ErrorCode::TraversalNatDetectionIoFailed
    );
}

#[test]
fn nat_classification_groups_network_interface_and_public_ip_independently() {
    let make = |network: &str, local: &str, nat: &str, err: Option<&str>| StunResult {
        index: 0,
        network: network.into(),
        local: local.into(),
        nat: nat.into(),
        err: err.map(str::to_owned),
    };
    let results = vec![
        make("udp4", "10.0.0.1:1000", "1.1.1.1:2000", None),
        make("udp4", "10.0.0.1:1000", "1.1.1.1:2000", None),
        make("tcp4", "10.0.0.1:1000", "1.1.1.1:1000", None),
        make("udp4", "10.0.0.1:1000", "8.8.8.8:3000", None),
        make("udp4", "10.0.0.2:1000", "1.1.1.1:4000", None),
        make("udp4", "10.0.0.2:1000", "1.1.1.1:4001", None),
        make("udp4", "10.0.0.1:1000", "1.1.1.1:9999", Some("timeout")),
    ];
    assert_eq!(succeeded_stun_results(&results), 6);
    let classified = analyze_stun_results(&results);
    assert_eq!(
        classified
            .iter()
            .map(|r| r.nattype.as_str())
            .collect::<Vec<_>>(),
        vec!["hard", "easy", "hard", "symm"]
    );
    assert_eq!(classified[1].network, "tcp4");
    assert_eq!(classified[3].lan, "10.0.0.2:1000");
    assert_eq!(classified[0].nat, "1.1.1.1:2000");
    assert!(analyze_stun_results(&[]).is_empty());
    assert!(analyze_stun_results(&[make("udp4", "10.0.0.1:1", "", Some("failed"))]).is_empty());
}
