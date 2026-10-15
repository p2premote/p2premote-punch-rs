//! Port of MQTT_ExchangePayload (easyp2p/p2p.go:2805) — the WGVPN key/IP
//! exchange FFI ("wgvpn-kx/" salt prefix).

use std::time::Duration;

#[cfg(feature = "legacy-mqtt")]
use super::crypto;
#[cfg(feature = "legacy-mqtt")]
use super::mqtt_signal::{self, MqttSignalSession};
use super::{P2pError, Result};
#[cfg(feature = "legacy-mqtt")]
use super::{Scope, EXMODE_MUTUAL, EXMODE_PUBLISH_ONLY, EXMODE_WAIT_ONLY};

/// exmode: 0=mutual, 1=wait only, 2=reply after receiving the active peer.
#[cfg(feature = "legacy-mqtt")]
pub async fn mqtt_exchange_payload(
    exmode: i32,
    send_data: &str,
    session_uid: &str,
    salt_prefix: &str,
    timeout: Duration,
    budget: Duration,
) -> Result<String> {
    if session_uid.is_empty() {
        return Err(P2pError::msg("sessionUid is required"));
    }
    if !(EXMODE_MUTUAL..=EXMODE_PUBLISH_ONLY).contains(&exmode) {
        return Err(P2pError::msg(format!(
            "unsupported exchange mode: {}",
            exmode
        )));
    }

    let topic_salt = format!(
        "{}{}",
        salt_prefix,
        crypto::derive_key_for_topic(salt_prefix, session_uid)
    );
    let client_id = crypto::mqtt_generate_client_id("WG", session_uid);
    let scope = Scope::from_timeout(budget);
    let signal = MqttSignalSession::new(&scope, &client_id).await?;

    if exmode == EXMODE_PUBLISH_ONLY {
        // Legacy reply mode: wait for the active peer's repeated payload, then
        // publish the response on the same broker.
        let (recv_data, broker_index) = mqtt_signal::secure_exchange_with_session::<String>(
            &scope,
            &signal,
            EXMODE_WAIT_ONLY,
            &send_data.to_string(),
            &topic_salt,
            session_uid,
            timeout,
            None,
        )
        .await?;
        mqtt_signal::mqtt_secure_publish_with_session::<String>(
            &scope,
            &signal,
            &send_data.to_string(),
            &topic_salt,
            session_uid,
            timeout,
            broker_index,
        )
        .await?;
        return Ok(recv_data);
    }

    let (recv_data, _) = mqtt_signal::secure_exchange_with_session::<String>(
        &scope,
        &signal,
        exmode,
        &send_data.to_string(),
        &topic_salt,
        session_uid,
        timeout,
        None,
    )
    .await?;
    Ok(recv_data)
}

#[cfg(not(feature = "legacy-mqtt"))]
pub async fn mqtt_exchange_payload(
    _exmode: i32,
    _send_data: &str,
    _session_uid: &str,
    _salt_prefix: &str,
    _timeout: Duration,
    _budget: Duration,
) -> Result<String> {
    Err(P2pError::msg("legacy_mqtt_disabled"))
}

pub async fn exchange_with_signal(
    exmode: i32,
    send_data: &str,
    session_uid: &str,
    timeout: Duration,
    call: std::sync::Arc<super::signal::SignalCall>,
) -> Result<String> {
    if !call.matches_uid(session_uid) || call.call_id() != "wg-config" {
        return Err(P2pError::msg("signal_context_mismatch"));
    }
    call.exchange(
        exmode,
        &send_data.to_string(),
        "wg_config",
        0,
        &call.scope(timeout),
        timeout,
    )
    .await
}
