use super::*;

#[tokio::test]
async fn feature_disabled_has_no_mapping_side_effects_and_preserves_candidates() {
    assert!(!enabled());
    assert_eq!(status(), "disabled");
    let scope = Scope::from_timeout(std::time::Duration::from_secs(1));
    let discovered = discover(&scope, &["udp4".into()]).await;
    let mut candidates = vec![PunchingAddressInfo {
        network: "udp4".into(),
        nat_type: "hard".into(),
        lan: "192.168.1.2:1234".into(),
        nat: "8.8.8.8:4321".into(),
    }];
    let leases = augment(&scope, &mut candidates, discovered).await;
    assert!(leases.is_empty());
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].nat_type, "hard");
    assert_eq!(candidates[0].nat, "8.8.8.8:4321");
    let local = "192.168.1.2:1234".parse().unwrap();
    assert!(for_socket(&leases, local).is_empty());
    assert!(take_socket(&leases, local).is_none());
    confirm_candidate(&leases, "8.8.8.8:4321");
    shutdown().await;
    assert!(!enabled());
}
