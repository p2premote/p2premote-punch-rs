//! Port of MqttWait / MQTTHello (easyp2p/p2p.go): the wake-up channel that
//! lets a long-running waiter be woken by an initiator before punching.
//! Messages: "SYN@<tid>" / "ACK@<tid>" where tid = 10 random chars + the
//! HelloPayload suffix ";k1=v1|App::Param" (the leading control segment is
//! the random part; parse skips it as the real topic salt).

use std::sync::Arc;
use std::time::Duration;

use super::crypto;
use super::mqtt_signal::{self, MqttSignalSession};
use super::{P2pError, Result, Scope, EXMODE_MUTUAL, EXMODE_WAIT_ONLY, TOPIC_DESC_SIGNAL};

const WAIT_TOPIC_INNER_SALT: &str = "mqtt-topic-gonc-wait";
const WAIT_TOPIC_PREFIX: &str = "nat-exchange-wait/";
const ACK_PUBLISH_TIMEOUT: Duration = Duration::from_secs(15);
/// Go's MqttWait/MQTTHello close the session 5s after returning so late
/// ACKs/retransmits still land.
const SESSION_LINGER: Duration = Duration::from_secs(5);

pub fn wake_topic_salt(session_uid: &str) -> String {
    format!(
        "{}{}",
        WAIT_TOPIC_PREFIX,
        crypto::derive_key_for_topic(WAIT_TOPIC_INNER_SALT, session_uid)
    )
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HelloPayload {
    pub control: Vec<String>,
    pub app: String,
    pub param: String,
}

impl HelloPayload {
    /// ";k1=v1;k2=v2|App::Param" — empty when nothing is set.
    pub fn to_suffix(&self) -> String {
        let mut out = String::new();
        if !self.control.is_empty() {
            out.push(';');
            out.push_str(&self.control.join(";"));
        }
        if !self.app.is_empty() {
            out.push('|');
            out.push_str(&self.app);
            out.push_str("::");
            out.push_str(&self.param);
        }
        out
    }

    /// Parse a received tid tail; the first control segment is the peer's
    /// random salt and is returned separately.
    pub fn parse_from(s: &str) -> (HelloPayload, String) {
        let (control_part, app_part) = match s.split_once('|') {
            Some((c, a)) => (c, Some(a)),
            None => (s, None),
        };
        let mut control = Vec::new();
        let mut salt = String::new();
        for (i, seg) in control_part.split(';').enumerate() {
            if i == 0 {
                salt = seg.to_string();
            } else if !seg.is_empty() {
                control.push(seg.to_string());
            }
        }
        let (app, param) = match app_part {
            Some(a) => match a.split_once("::") {
                Some((app, param)) => (app.to_string(), param.to_string()),
                None => (a.to_string(), String::new()),
            },
            None => (String::new(), String::new()),
        };
        (HelloPayload { control, app, param }, salt)
    }

    pub fn set_control_value(&mut self, key: &str, val: &str) {
        self.control.push(format!("{}={}", key, val));
    }

    pub fn get_control_value(&self, key: &str) -> Option<String> {
        let key = key.to_ascii_lowercase();
        for entry in &self.control {
            if let Some((k, v)) = entry.split_once('=') {
                if k.to_ascii_lowercase() == key {
                    return Some(v.to_string());
                }
            }
        }
        None
    }
}

fn random_tid(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rand::Rng::gen_range(&mut rng, 0..CHARSET.len())] as char)
        .collect()
}

/// MqttWaitSession: wait for "SYN@<tid>" and ACK it on the broker it arrived
/// on. The returned session stays open for the caller to reuse as the P2P
/// signaling session. `_local_ip` is a gonc-parity placeholder: rumqttc
/// cannot bind the MQTT source address.
pub async fn mqtt_wait_session(
    scope: &Scope,
    session_uid: &str,
    _local_ip: &str,
    timeout: Duration,
) -> Result<(String, Arc<MqttSignalSession>)> {
    let topic_salt = wake_topic_salt(session_uid);
    let client_id = crypto::mqtt_generate_client_id(TOPIC_DESC_SIGNAL, session_uid);
    let signal = MqttSignalSession::new(scope, &client_id).await?;

    let filter: Arc<dyn Fn(&String) -> std::result::Result<bool, String> + Send + Sync> =
        Arc::new(|data: &String| Ok(data.starts_with("SYN@")));
    let result: Result<String> = async {
        let (recv, srv_index) = mqtt_signal::secure_exchange_with_session::<String>(
            scope,
            &signal,
            EXMODE_WAIT_ONLY,
            &String::new(),
            &topic_salt,
            session_uid,
            timeout,
            Some(filter),
        )
        .await?;
        let Some(tid) = recv.strip_prefix("SYN@") else {
            return Err(P2pError::msg("not the expected message"));
        };
        let tid = tid.to_string();
        crate::p2plog!("wait: received event, publishing ACK on broker #{}", srv_index);
        mqtt_signal::mqtt_secure_publish_with_session::<String>(
            scope,
            &signal,
            &format!("ACK@{}", tid),
            &topic_salt,
            session_uid,
            ACK_PUBLISH_TIMEOUT,
            srv_index,
        )
        .await?;
        Ok(tid)
    }
    .await;

    match result {
        Ok(tid) => Ok((tid, signal)),
        Err(err) => {
            signal.close();
            Err(err)
        }
    }
}

/// MQTTHelloSession: burst "SYN@<tid>" until the byte-equal "ACK@<tid>"
/// arrives.
pub async fn mqtt_hello_session(
    scope: &Scope,
    session_uid: &str,
    _local_ip: &str,
    hello_payload: &HelloPayload,
    timeout: Duration,
) -> Result<(String, Arc<MqttSignalSession>)> {
    let topic_salt = wake_topic_salt(session_uid);
    let client_id = crypto::mqtt_generate_client_id(TOPIC_DESC_SIGNAL, session_uid);
    let signal = MqttSignalSession::new(scope, &client_id).await?;

    let tid = format!("{}{}", random_tid(10), hello_payload.to_suffix());
    let msg_syn = format!("SYN@{}", tid);
    let msg_ack = format!("ACK@{}", tid);

    let filter: Arc<dyn Fn(&String) -> std::result::Result<bool, String> + Send + Sync> =
        Arc::new(|data: &String| Ok(data.starts_with("ACK@")));
    let result: Result<()> = async {
        let (recv, _srv_index) = mqtt_signal::secure_exchange_with_session::<String>(
            scope,
            &signal,
            EXMODE_MUTUAL,
            &msg_syn,
            &topic_salt,
            session_uid,
            timeout,
            Some(filter),
        )
        .await?;
        if recv != msg_ack {
            return Err(P2pError::msg("not the expected message"));
        }
        Ok(())
    }
    .await;

    match result {
        Ok(()) => Ok((tid, signal)),
        Err(err) => {
            signal.close();
            Err(err)
        }
    }
}

/// MqttWait: convenience wrapper that closes the session 5s after returning.
pub async fn mqtt_wait(scope: &Scope, session_uid: &str, local_ip: &str, timeout: Duration) -> Result<String> {
    let (tid, signal) = mqtt_wait_session(scope, session_uid, local_ip, timeout).await?;
    tokio::spawn(async move {
        tokio::time::sleep(SESSION_LINGER).await;
        signal.close();
    });
    Ok(tid)
}

/// MQTTHello: convenience wrapper that closes the session 5s after returning.
pub async fn mqtt_hello(
    scope: &Scope,
    session_uid: &str,
    local_ip: &str,
    hello_payload: &HelloPayload,
    timeout: Duration,
) -> Result<String> {
    let (tid, signal) = mqtt_hello_session(scope, session_uid, local_ip, hello_payload, timeout).await?;
    tokio::spawn(async move {
        tokio::time::sleep(SESSION_LINGER).await;
        signal.close();
    });
    Ok(tid)
}

#[cfg(test)]
mod tests {
    use super::HelloPayload;

    #[test]
    fn hello_payload_suffix_and_parse_roundtrip() {
        let mut payload = HelloPayload::default();
        assert_eq!(payload.to_suffix(), "");
        payload.set_control_value("cs", "tls");
        payload.set_control_value("lan", "1");
        payload.app = "br".to_string();
        payload.param = "x".to_string();
        assert_eq!(payload.to_suffix(), ";cs=tls;lan=1|br::x");

        // The tid tail = random salt + suffix; parse recovers salt + payload.
        let tid = format!("abc123XYZ0{}", payload.to_suffix());
        let (parsed, salt) = HelloPayload::parse_from(&tid);
        assert_eq!(salt, "abc123XYZ0");
        assert_eq!(parsed.get_control_value("cs").as_deref(), Some("tls"));
        assert_eq!(parsed.get_control_value("CS").as_deref(), Some("tls"));
        assert_eq!(parsed.get_control_value("lan").as_deref(), Some("1"));
        assert!(parsed.get_control_value("missing").is_none());
        assert_eq!(parsed.app, "br");
        assert_eq!(parsed.param, "x");
    }

    #[test]
    fn hello_payload_bare_salt() {
        let (parsed, salt) = HelloPayload::parse_from("abcdefghij");
        assert_eq!(salt, "abcdefghij");
        assert!(parsed.control.is_empty());
        assert_eq!(parsed.app, "");
    }

    #[test]
    fn hello_payload_control_only_and_app_without_param() {
        let (parsed, salt) = HelloPayload::parse_from("abcdefghij;cs=ss");
        assert_eq!(salt, "abcdefghij");
        assert_eq!(parsed.get_control_value("cs").as_deref(), Some("ss"));
        assert_eq!(parsed.app, "");

        let (parsed, _) = HelloPayload::parse_from("abcdefghij|br");
        assert_eq!(parsed.app, "br");
        assert_eq!(parsed.param, "");
    }
}
