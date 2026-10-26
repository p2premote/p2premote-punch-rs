//! Application-owned signaling. MQTT remains the legacy backend; an external
//! session sends through the application's already-authorized WebSocket.
use crate::error::ErrorCode;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

#[cfg(feature = "legacy-mqtt")]
use super::mqtt_signal::{self, MqttSignalSession};
use super::{
    crypto::{self, SecurePayload},
    CancelToken, P2pError, Result, Scope, EXMODE_MUTUAL, EXMODE_PUBLISH_ONLY, EXMODE_WAIT_ONLY,
};

pub const WS_TRANSPORT: &str = "ws-v1";
pub const MQTT_TRANSPORT: &str = "mqtt-legacy";
pub const CAP_NATIVE_RETRY: &str = "ws-native-retry-v1";
pub const MAX_DATA_BYTES: usize = 16 * 1024;
const MAX_INBOX_BYTES: usize = 128 * 1024;
const MAX_INBOX_MESSAGES: usize = 32;
const MAX_SEEN: usize = 128;
const MAX_CALLS: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportOffer {
    pub version: u8,
    pub supported: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportSelection {
    pub version: u8,
    pub selected: String,
}

// Combined with serde(default), these functions distinguish omission from null.
pub fn deserialize_offer<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<TransportOffer>, D::Error> {
    TransportOffer::deserialize(d).map(Some)
}
pub fn deserialize_selection<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<TransportSelection>, D::Error> {
    TransportSelection::deserialize(d).map(Some)
}

impl TransportOffer {
    pub fn local(ws_enabled: bool) -> Self {
        let mut supported = Vec::new();
        if ws_enabled {
            supported.push(WS_TRANSPORT.into());
        }
        #[cfg(feature = "legacy-mqtt")]
        supported.push(MQTT_TRANSPORT.into());
        Self {
            version: 1,
            supported,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.supported.is_empty()
            || self.supported.len() > 8
            || self.supported.iter().any(|s| !valid_id(s))
            || self
                .supported
                .iter()
                .enumerate()
                .any(|(i, s)| self.supported[..i].contains(s))
        {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            ));
        }
        Ok(())
    }
    pub fn select(
        &self,
        peer: Option<&Self>,
        traversal_v2: bool,
    ) -> Result<Option<TransportSelection>> {
        self.validate()?;
        let Some(peer) = peer else {
            if self.supported.iter().any(|s| s == MQTT_TRANSPORT) {
                return Ok(None);
            }
            return Err(P2pError::new(
                ErrorCode::SignalTransportSelectPeerUpgradeRequired,
                "peer_upgrade_required",
            ));
        };
        peer.validate()?;
        let selected = if traversal_v2
            && self.supported.iter().any(|s| s == WS_TRANSPORT)
            && peer.supported.iter().any(|s| s == WS_TRANSPORT)
        {
            WS_TRANSPORT
        } else if self.supported.iter().any(|s| s == MQTT_TRANSPORT)
            && peer.supported.iter().any(|s| s == MQTT_TRANSPORT)
        {
            MQTT_TRANSPORT
        } else {
            return Err(P2pError::new(
                ErrorCode::SignalTransportSelectPeerUpgradeRequired,
                "peer_upgrade_required",
            ));
        };
        Ok(Some(TransportSelection {
            version: 1,
            selected: selected.into(),
        }))
    }
    pub fn validate_selection(
        &self,
        selected: Option<&TransportSelection>,
        traversal_v2: bool,
    ) -> Result<bool> {
        self.validate()?;
        let Some(selected) = selected else {
            if self.supported.iter().any(|s| s == MQTT_TRANSPORT) {
                return Ok(false);
            }
            return Err(P2pError::new(
                ErrorCode::SignalTransportSelectPeerUpgradeRequired,
                "peer_upgrade_required",
            ));
        };
        if selected.version != 1
            || !self.supported.contains(&selected.selected)
            || !matches!(selected.selected.as_str(), WS_TRANSPORT | MQTT_TRANSPORT)
            || (selected.selected == WS_TRANSPORT && !traversal_v2)
        {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            ));
        }
        Ok(selected.selected == WS_TRANSPORT)
    }
}

pub type SendFuture<'a> =
    Pin<Box<dyn Future<Output = std::result::Result<(), crate::error::AppError>> + Send + 'a>>;
/// Success means the server accepted its target send queue, not peer receipt.
pub trait WireSender: Send + Sync {
    fn send(&self, data: String, deadline: Instant) -> SendFuture<'_>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionIdentity {
    pub connection_id: String,
    pub attempt_id: String,
    pub local_device_id: i64,
    pub peer_device_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalFrame {
    pub version: u8,
    pub attempt_id: String,
    pub call_id: String,
    pub channel: String,
    pub step: u8,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub probe_attempt: u8,
    pub message_id: String,
    pub packet: SecurePayload,
}
#[derive(Serialize, Deserialize)]
struct WireFrame {
    #[serde(rename = "type")]
    kind: String,
    #[serde(flatten)]
    frame: SignalFrame,
}
#[derive(Serialize, Deserialize, PartialEq)]
struct Binding {
    #[serde(rename = "type")]
    kind: String,
    version: u8,
    connection_id: String,
    source_device_id: i64,
    target_device_id: i64,
    attempt_id: String,
    call_id: String,
    channel: String,
    step: u8,
    #[serde(default, skip_serializing_if = "is_zero")]
    probe_attempt: u8,
    message_id: String,
}
#[derive(Serialize, Deserialize)]
struct Sealed {
    binding: Binding,
    value: Value,
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct Slot {
    channel: String,
    step: u8,
    probe_attempt: u8,
}
struct CallState {
    inbox: HashMap<Slot, VecDeque<Value>>,
    seen: HashMap<String, [u8; 32]>,
    received: HashMap<Slot, Value>,
    inbox_count: usize,
    inbox_bytes: usize,
    failure: Option<P2pError>,
}

pub struct ExternalSignalSession {
    identity: SessionIdentity,
    sender: Arc<dyn WireSender>,
    calls: Mutex<HashMap<String, Arc<SignalCall>>>,
    used_calls: Mutex<HashSet<String>>,
    closed: Arc<CancelToken>,
}

/// One configuration exchange or application network round. Native retries
/// use separate authenticated mailbox slots within the same round deadline.
pub struct SignalCall {
    identity: SessionIdentity,
    sender: Arc<dyn WireSender>,
    session_closed: Arc<CancelToken>,
    call_id: String,
    uid: String,
    key: [u8; 32],
    deadline: Instant,
    cancel: Arc<CancelToken>,
    notify: Notify,
    state: Mutex<CallState>,
    sending: tokio::sync::Semaphore,
    native_retry: std::sync::atomic::AtomicBool,
    probe_attempt: std::sync::atomic::AtomicU8,
}

fn is_zero(value: &u8) -> bool {
    *value == 0
}

fn receive_timeout_code(channel: &str) -> ErrorCode {
    match channel {
        "wg_config" => ErrorCode::TraversalKeyExchangeTimeout,
        "addresses" => ErrorCode::TraversalAddressExchangeTimeout,
        "traversal_mode" => ErrorCode::TraversalPlanNegotiationTimeout,
        _ => ErrorCode::TraversalRoundSyncTimeout,
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_graphic())
}
fn valid_call(id: &str) -> bool {
    id == "wg-config"
        || id
            .strip_prefix("network/")
            .map(|s| {
                s.parse::<u8>()
                    .map(|n| n > 0 && n <= 5 && n.to_string() == s)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
}
fn valid_slot(call: &str, channel: &str, step: u8) -> bool {
    if call == "wg-config" {
        return channel == "wg_config" && step == 0;
    }
    match channel {
        "traversal_mode" | "lan_outcome" | "addresses" => step == 0,
        "candidate_sync" => (1..=5).contains(&step),
        _ => false,
    }
}

impl ExternalSignalSession {
    pub fn new(identity: SessionIdentity, sender: Arc<dyn WireSender>) -> Result<Arc<Self>> {
        if !valid_id(&identity.connection_id)
            || !valid_id(&identity.attempt_id)
            || identity.local_device_id <= 0
            || identity.peer_device_id <= 0
            || identity.local_device_id == identity.peer_device_id
        {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveContextMismatch,
                "signal_context_mismatch",
            ));
        }
        Ok(Arc::new(Self {
            identity,
            sender,
            calls: Mutex::new(HashMap::new()),
            used_calls: Mutex::new(HashSet::new()),
            closed: Arc::new(CancelToken::new()),
        }))
    }
    pub fn register_call(
        self: &Arc<Self>,
        call_id: &str,
        uid: &str,
        budget: Duration,
    ) -> Result<Arc<SignalCall>> {
        if !valid_call(call_id)
            || uid.len() < 16
            || uid.len() > 132
            || budget.is_zero()
            || budget > Duration::from_secs(300)
        {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveContextMismatch,
                "signal_context_mismatch",
            ));
        }
        if self.closed.is_cancelled() {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveCancelled,
                "signal_cancelled",
            ));
        }
        let mut calls = self.calls.lock().unwrap();
        let mut used = self.used_calls.lock().unwrap();
        if used.contains(call_id) || used.len() >= MAX_CALLS {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveContextMismatch,
                "duplicate_signal_call",
            ));
        }
        let call = Arc::new(SignalCall {
            identity: self.identity.clone(),
            sender: self.sender.clone(),
            session_closed: self.closed.clone(),
            call_id: call_id.into(),
            uid: uid.into(),
            key: crypto::derive_key("mqtt-exchange-gonc-v2.2.0", uid),
            deadline: Instant::now() + budget,
            cancel: Arc::new(CancelToken::new()),
            notify: Notify::new(),
            state: Mutex::new(CallState {
                inbox: HashMap::new(),
                seen: HashMap::new(),
                received: HashMap::new(),
                inbox_count: 0,
                inbox_bytes: 0,
                failure: None,
            }),
            sending: tokio::sync::Semaphore::new(16),
            native_retry: std::sync::atomic::AtomicBool::new(false),
            probe_attempt: std::sync::atomic::AtomicU8::new(0),
        });
        calls.insert(call_id.into(), call.clone());
        used.insert(call_id.into());
        Ok(call)
    }
    pub fn lookup_call(&self, id: &str) -> Option<Arc<SignalCall>> {
        self.calls.lock().unwrap().get(id).cloned()
    }
    pub fn close_call(&self, id: &str) {
        if let Some(call) = self.calls.lock().unwrap().remove(id) {
            call.cancel();
        }
    }
    pub fn close(&self) {
        self.closed.cancel();
        let calls = std::mem::take(&mut *self.calls.lock().unwrap());
        for call in calls.into_values() {
            call.cancel();
        }
    }
    pub fn deliver_json(&self, connection: &str, source: i64, json: &str) -> Result<()> {
        if json.len() > MAX_DATA_BYTES {
            return Err(P2pError::new(
                ErrorCode::SignalReceivePayloadTooLarge,
                "signal_payload_too_large",
            ));
        }
        let wire: WireFrame = serde_json::from_str(json).map_err(|_| {
            P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            )
        })?;
        if wire.kind != "punch_signal" {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            ));
        }
        self.deliver(connection, source, wire.frame)
    }
    pub fn deliver(&self, connection: &str, source: i64, frame: SignalFrame) -> Result<()> {
        if self.closed.is_cancelled() {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveStaleFrame,
                "stale_signal_frame",
            ));
        }
        if connection != self.identity.connection_id
            || source != self.identity.peer_device_id
            || frame.attempt_id != self.identity.attempt_id
        {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveContextMismatch,
                "signal_context_mismatch",
            ));
        }
        let calls = self.calls.lock().unwrap();
        let call = calls.get(&frame.call_id).ok_or_else(|| {
            P2pError::new(ErrorCode::SignalReceiveStaleFrame, "stale_signal_frame")
        })?;
        if serde_json::to_vec(&frame)?.len() + 24 > MAX_DATA_BYTES {
            return Err(P2pError::new(
                ErrorCode::SignalReceivePayloadTooLarge,
                "signal_payload_too_large",
            ));
        }
        // Serialize ingress across calls so the attempt-wide limits cannot race.
        let (mut messages, mut bytes, mut seen) = (0, 0, 0);
        for registered in calls.values() {
            let state = registered.state.lock().unwrap();
            messages += state.inbox_count;
            bytes += state.inbox_bytes;
            seen += state.seen.len();
        }
        let result = call.deliver(frame, messages, bytes, seen);
        if let Err(error) = &result {
            call.fail(error);
        }
        result
    }
}

impl Drop for ExternalSignalSession {
    fn drop(&mut self) {
        self.closed.cancel();
        for call in self.calls.get_mut().unwrap().values() {
            call.cancel();
        }
    }
}

impl SignalCall {
    pub fn set_peer_native_retry(&self, supported: bool) {
        self.native_retry
            .store(supported, std::sync::atomic::Ordering::Release);
    }

    pub fn native_retry_supported(&self) -> bool {
        self.native_retry.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(super) fn begin_probe_attempt(&self, attempt: u8) {
        self.probe_attempt
            .store(attempt, std::sync::atomic::Ordering::Release);
    }

    pub fn scope(&self, budget: Duration) -> Scope {
        Scope::from_timeout(budget)
            .with_deadline(self.deadline)
            .with_cancel(self.cancel.clone())
    }
    pub fn cancel(&self) {
        self.cancel.cancel();
        self.notify.notify_waiters();
    }
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
    pub fn matches_uid(&self, uid: &str) -> bool {
        self.uid == uid
    }
    fn fail(&self, error: &P2pError) {
        self.state
            .lock()
            .unwrap()
            .failure
            .get_or_insert_with(|| error.clone());
        self.cancel();
    }
    /// Report a signal failure separately from an ordinary native punch timeout.
    pub fn failure(&self) -> Option<P2pError> {
        self.state.lock().unwrap().failure.clone().or_else(|| {
            (self.cancel.is_cancelled() || self.session_closed.is_cancelled())
                .then(|| P2pError::new(ErrorCode::SignalReceiveCancelled, "signal cancelled"))
        })
    }
    fn check(&self) -> Result<()> {
        if let Some(error) = self.failure() {
            return Err(error);
        }
        if Instant::now() >= self.deadline {
            return Err(P2pError::new(
                ErrorCode::SignalSendTimeout,
                "signal_delivery_timeout",
            ));
        }
        Ok(())
    }
    fn binding(&self, frame: &SignalFrame, outgoing: bool) -> Binding {
        let id = &self.identity;
        Binding {
            kind: "punch_signal".into(),
            version: 1,
            connection_id: id.connection_id.clone(),
            source_device_id: if outgoing {
                id.local_device_id
            } else {
                id.peer_device_id
            },
            target_device_id: if outgoing {
                id.peer_device_id
            } else {
                id.local_device_id
            },
            attempt_id: frame.attempt_id.clone(),
            call_id: frame.call_id.clone(),
            channel: frame.channel.clone(),
            step: frame.step,
            probe_attempt: frame.probe_attempt,
            message_id: frame.message_id.clone(),
        }
    }
    fn deliver(
        &self,
        frame: SignalFrame,
        inbox_count: usize,
        inbox_bytes: usize,
        seen_count: usize,
    ) -> Result<()> {
        self.check()?;
        if frame.version != 1
            || !valid_id(&frame.message_id)
            || !valid_slot(&frame.call_id, &frame.channel, frame.step)
            || (frame.probe_attempt > 0
                && (!self.native_retry_supported()
                    || !matches!(frame.channel.as_str(), "addresses" | "candidate_sync")))
        {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            ));
        }
        if frame.packet.nonce.len() > 32 || frame.packet.data.len() > MAX_DATA_BYTES {
            return Err(P2pError::new(
                ErrorCode::SignalReceivePayloadTooLarge,
                "signal_payload_too_large",
            ));
        }
        use base64::Engine;
        if crypto::b64()
            .decode(&frame.packet.nonce)
            .map(|v| v.len())
            .ok()
            != Some(12)
        {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            ));
        }
        let plain = crypto::decrypt_aes(&self.key, &frame.packet).map_err(|_| {
            P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            )
        })?;
        let sealed: Sealed = serde_json::from_slice(&plain).map_err(|_| {
            P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            )
        })?;
        if sealed.binding != self.binding(&frame, false) {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveContextMismatch,
                "signal_context_mismatch",
            ));
        }
        let hash: [u8; 32] =
            Sha256::digest(format!("{}:{}", frame.packet.nonce, frame.packet.data).as_bytes())
                .into();
        let slot = Slot {
            channel: frame.channel,
            step: frame.step,
            probe_attempt: frame.probe_attempt,
        };
        let bytes = serde_json::to_vec(&sealed.value)?.len();
        let mut state = self.state.lock().unwrap();
        if let Some(previous) = state.seen.get(&frame.message_id) {
            return if previous == &hash {
                Ok(())
            } else {
                Err(P2pError::new(
                    ErrorCode::SignalReceiveInvalidFrame,
                    "signal_protocol_invalid",
                ))
            };
        }
        if state.received.contains_key(&slot) || state.inbox.contains_key(&slot) {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            ));
        }
        if seen_count >= MAX_SEEN
            || inbox_count >= MAX_INBOX_MESSAGES
            || inbox_bytes + bytes > MAX_INBOX_BYTES
        {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveQueueFull,
                "signal_queue_full",
            ));
        }
        state.seen.insert(frame.message_id, hash);
        state.inbox.entry(slot).or_default().push_back(sealed.value);
        state.inbox_count += 1;
        state.inbox_bytes += bytes;
        drop(state);
        self.notify.notify_waiters();
        Ok(())
    }
    async fn receive(&self, slot: &Slot, deadline: Instant) -> Result<Value> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.check()?;
            {
                let mut state = self.state.lock().unwrap();
                if let Some(value) = state.inbox.get_mut(slot).and_then(|q| q.pop_front()) {
                    state.inbox_count -= 1;
                    state.inbox_bytes -= serde_json::to_vec(&value)?.len();
                    state.received.insert(slot.clone(), value.clone());
                    return Ok(value);
                }
            }
            tokio::select! {
                _ = &mut notified => {},
                _ = self.cancel.cancelled() => return self.check().and(Err(P2pError::new(ErrorCode::SignalReceiveCancelled, "signal_cancelled"))),
                _ = tokio::time::sleep_until(deadline.into()) => return Err(P2pError::new(receive_timeout_code(&slot.channel), "signal receive timeout")),
            }
        }
    }
    async fn send_value(&self, slot: &Slot, value: Value, deadline: Instant) -> Result<()> {
        self.check()?;
        let _permit = self
            .sending
            .try_acquire()
            .map_err(|_| P2pError::new(ErrorCode::SignalReceiveQueueFull, "signal_queue_full"))?;
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let mut frame = SignalFrame {
            version: 1,
            attempt_id: self.identity.attempt_id.clone(),
            call_id: self.call_id.clone(),
            channel: slot.channel.clone(),
            step: slot.step,
            probe_attempt: slot.probe_attempt,
            message_id: crypto::hex(&random),
            packet: SecurePayload {
                nonce: String::new(),
                data: String::new(),
            },
        };
        let sealed = Sealed {
            binding: self.binding(&frame, true),
            value,
        };
        frame.packet = crypto::encrypt_aes(&self.key, &serde_json::to_vec(&sealed)?)?;
        let data = serde_json::to_string(&WireFrame {
            kind: "punch_signal".into(),
            frame,
        })?;
        if data.len() > MAX_DATA_BYTES {
            return Err(P2pError::new(
                ErrorCode::SignalReceivePayloadTooLarge,
                "signal_payload_too_large",
            ));
        }
        tokio::select! {
            result = tokio::time::timeout_at(deadline.into(), self.sender.send(data, deadline)) =>
                result.map_err(|_| P2pError::new(ErrorCode::SignalSendTimeout, "signal_delivery_timeout"))?.map_err(P2pError::from),
            _ = self.cancel.cancelled() => self.check().and(Err(P2pError::new(ErrorCode::SignalReceiveCancelled, "signal_cancelled"))),
        }
    }
    pub async fn exchange<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        mode: i32,
        value: &T,
        channel: &str,
        step: u8,
        scope: &Scope,
        timeout: Duration,
    ) -> Result<T> {
        let result = self
            .exchange_inner(mode, value, channel, step, scope, timeout)
            .await;
        if let Err(error) = &result {
            self.fail(error);
        }
        result
    }

    async fn exchange_inner<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        mode: i32,
        value: &T,
        channel: &str,
        step: u8,
        scope: &Scope,
        timeout: Duration,
    ) -> Result<T> {
        self.check()?;
        if !valid_slot(&self.call_id, channel, step) {
            return Err(P2pError::new(
                ErrorCode::SignalReceiveContextMismatch,
                "signal_context_mismatch",
            ));
        }
        let deadline = (Instant::now() + timeout)
            .min(scope.deadline)
            .min(self.deadline);
        let slot = Slot {
            channel: channel.into(),
            step,
            probe_attempt: if matches!(channel, "addresses" | "candidate_sync") {
                self.probe_attempt
                    .load(std::sync::atomic::Ordering::Acquire)
            } else {
                0
            },
        };
        let remote = match mode {
            EXMODE_MUTUAL => {
                let (_, remote) = tokio::try_join!(
                    self.send_value(&slot, serde_json::to_value(value)?, deadline),
                    self.receive(&slot, deadline)
                )?;
                remote
            }
            EXMODE_WAIT_ONLY => self.receive(&slot, deadline).await?,
            EXMODE_PUBLISH_ONLY => {
                let remote = self
                    .state
                    .lock()
                    .unwrap()
                    .received
                    .get(&slot)
                    .cloned()
                    .ok_or_else(|| {
                        P2pError::new(
                            ErrorCode::SignalReceiveContextMismatch,
                            "signal_reply_without_request",
                        )
                    })?;
                self.send_value(&slot, serde_json::to_value(value)?, deadline)
                    .await?;
                remote
            }
            _ => {
                return Err(P2pError::new(
                    ErrorCode::SignalReceiveInvalidFrame,
                    "signal_protocol_invalid",
                ))
            }
        };
        serde_json::from_value(remote).map_err(|_| {
            P2pError::new(
                ErrorCode::SignalReceiveInvalidFrame,
                "signal_protocol_invalid",
            )
        })
    }
}

pub enum SignalSession {
    #[cfg(feature = "legacy-mqtt")]
    Mqtt(Arc<MqttSignalSession>),
    External(Arc<SignalCall>),
}
pub type PayloadFilter<T> =
    Option<Arc<dyn Fn(&T) -> std::result::Result<bool, String> + Send + Sync>>;
impl SignalSession {
    pub(crate) fn check_failure(&self) -> Result<()> {
        match self {
            Self::External(call) => match call.failure() {
                Some(error) => Err(error),
                None => Ok(()),
            },
            #[cfg(feature = "legacy-mqtt")]
            Self::Mqtt(_) => Ok(()),
        }
    }
    pub async fn new(
        scope: &Scope,
        client_id: &str,
        external: Option<Arc<SignalCall>>,
    ) -> Result<Arc<Self>> {
        if let Some(call) = external {
            call.check()?;
            return Ok(Arc::new(Self::External(call)));
        }
        #[cfg(feature = "legacy-mqtt")]
        {
            return Ok(Arc::new(Self::Mqtt(
                MqttSignalSession::new(scope, client_id).await?,
            )));
        }
        #[cfg(not(feature = "legacy-mqtt"))]
        {
            let _ = (scope, client_id);
            Err(P2pError::new(
                ErrorCode::SignalTransportSelectPeerUpgradeRequired,
                "legacy_mqtt_disabled",
            ))
        }
    }
    pub fn transport(&self) -> &'static str {
        match self {
            Self::External(_) => WS_TRANSPORT,
            #[cfg(feature = "legacy-mqtt")]
            Self::Mqtt(_) => MQTT_TRANSPORT,
        }
    }
    pub async fn prepare_topic(&self, scope: &Scope, salt: &str, uid: &str) -> Result<()> {
        #[cfg(not(feature = "legacy-mqtt"))]
        let _ = (scope, salt);
        match self {
            Self::External(call) => {
                if !call.matches_uid(uid) {
                    return Err(P2pError::new(
                        ErrorCode::SignalReceiveContextMismatch,
                        "signal_context_mismatch",
                    ));
                }
                call.check()
            }
            #[cfg(feature = "legacy-mqtt")]
            Self::Mqtt(session) => session.prepare_topic(scope, salt, uid).await,
        }
    }
    pub async fn secure_exchange<T: Serialize + serde::de::DeserializeOwned + 'static>(
        &self,
        scope: &Scope,
        mode: i32,
        data: &T,
        salt: &str,
        uid: &str,
        timeout: Duration,
        filter: PayloadFilter<T>,
    ) -> Result<(T, i32)> {
        match self {
            #[cfg(feature = "legacy-mqtt")]
            Self::Mqtt(session) => {
                mqtt_signal::secure_exchange_with_session(
                    scope, session, mode, data, salt, uid, timeout, filter,
                )
                .await
            }
            Self::External(call) => {
                let result: Result<(T, i32)> = async {
                    if !call.matches_uid(uid) {
                        return Err(P2pError::new(
                            ErrorCode::SignalReceiveContextMismatch,
                            "signal_context_mismatch",
                        ));
                    }
                    let (channel, step) = channel_for(salt, data)?;
                    let value = call
                        .exchange(mode, data, channel, step, scope, timeout)
                        .await?;
                    if let Some(filter) = filter {
                        if !filter(&value).map_err(|message| {
                            P2pError::new(ErrorCode::SignalSendDisconnected, message)
                        })? {
                            return Err(P2pError::new(
                                ErrorCode::SignalReceiveInvalidFrame,
                                "signal_protocol_invalid",
                            ));
                        }
                    }
                    Ok((value, -1))
                }
                .await;
                if let Err(error) = &result {
                    call.fail(error);
                }
                result
            }
        }
    }
    pub async fn secure_publish<T: Serialize + serde::de::DeserializeOwned + 'static>(
        &self,
        scope: &Scope,
        data: &T,
        salt: &str,
        uid: &str,
        timeout: Duration,
        broker: i32,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "legacy-mqtt")]
            Self::Mqtt(session) => {
                mqtt_signal::mqtt_secure_publish_with_session(
                    scope, session, data, salt, uid, timeout, broker,
                )
                .await?;
                Ok(())
            }
            Self::External(_) => {
                let _ = broker;
                self.secure_exchange(scope, EXMODE_PUBLISH_ONLY, data, salt, uid, timeout, None)
                    .await
                    .map(|_| ())
            }
        }
    }
}
fn channel_for<T: Serialize>(salt: &str, data: &T) -> Result<(&'static str, u8)> {
    match salt {
        "gonc-exchange-address" => Ok(("addresses", 0)),
        "wgvpn-traversal-capability-v1" => Ok(("traversal_mode", 0)),
        "wgvpn-lan-outcome-v1" => Ok(("lan_outcome", 0)),
        "gonc-exchange-sync" => {
            let value = serde_json::to_value(data)?;
            let text = value.as_str().ok_or_else(|| {
                P2pError::new(
                    ErrorCode::SignalReceiveInvalidFrame,
                    "signal_protocol_invalid",
                )
            })?;
            if !matches!(text.as_bytes().first(), Some(b'C') | Some(b'S')) {
                return Err(P2pError::new(
                    ErrorCode::SignalReceiveInvalidFrame,
                    "signal_protocol_invalid",
                ));
            }
            let step = text[1..].parse::<u8>().map_err(|_| {
                P2pError::new(
                    ErrorCode::SignalReceiveInvalidFrame,
                    "signal_protocol_invalid",
                )
            })?;
            if !(1..=5).contains(&step) {
                return Err(P2pError::new(
                    ErrorCode::SignalReceiveInvalidFrame,
                    "signal_protocol_invalid",
                ));
            }
            Ok(("candidate_sync", step))
        }
        salt if salt.starts_with("wgvpn-kx/") => Ok(("wg_config", 0)),
        _ => Err(P2pError::new(
            ErrorCode::SignalReceiveInvalidFrame,
            "signal_protocol_invalid",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Bridge {
        target: Mutex<Option<std::sync::Weak<ExternalSignalSession>>>,
        source: i64,
        sent: Mutex<Vec<String>>,
        lose_ack: std::sync::atomic::AtomicBool,
        invalid_sync: std::sync::atomic::AtomicBool,
    }
    impl WireSender for Bridge {
        fn send(&self, data: String, _: Instant) -> SendFuture<'_> {
            Box::pin(async move {
                let mut wire: WireFrame = serde_json::from_str(&data).unwrap();
                let data = if wire.frame.channel == "candidate_sync"
                    && self
                        .invalid_sync
                        .swap(false, std::sync::atomic::Ordering::Relaxed)
                {
                    wire.frame.version = 2;
                    serde_json::to_string(&wire).unwrap()
                } else {
                    data
                };
                self.sent.lock().unwrap().push(data.clone());
                let peer = self
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|w| w.upgrade())
                    .unwrap();
                peer.deliver_json("connection", self.source, &data)
                    .map_err(|e| e.app_error())?;
                if self
                    .lose_ack
                    .swap(false, std::sync::atomic::Ordering::Relaxed)
                {
                    Err(crate::error::AppError::new(
                        ErrorCode::SignalSendTimeout,
                        "signal_server_ack_timeout",
                    ))
                } else {
                    Ok(())
                }
            })
        }
    }
    fn pair() -> (
        Arc<ExternalSignalSession>,
        Arc<ExternalSignalSession>,
        Arc<Bridge>,
        Arc<Bridge>,
    ) {
        let ab = Arc::new(Bridge {
            target: Mutex::new(None),
            source: 1,
            sent: Mutex::new(Vec::new()),
            lose_ack: std::sync::atomic::AtomicBool::new(false),
            invalid_sync: std::sync::atomic::AtomicBool::new(false),
        });
        let ba = Arc::new(Bridge {
            target: Mutex::new(None),
            source: 2,
            sent: Mutex::new(Vec::new()),
            lose_ack: std::sync::atomic::AtomicBool::new(false),
            invalid_sync: std::sync::atomic::AtomicBool::new(false),
        });
        let a = ExternalSignalSession::new(
            SessionIdentity {
                connection_id: "connection".into(),
                attempt_id: "attempt".into(),
                local_device_id: 1,
                peer_device_id: 2,
            },
            ab.clone(),
        )
        .unwrap();
        let b = ExternalSignalSession::new(
            SessionIdentity {
                connection_id: "connection".into(),
                attempt_id: "attempt".into(),
                local_device_id: 2,
                peer_device_id: 1,
            },
            ba.clone(),
        )
        .unwrap();
        *ab.target.lock().unwrap() = Some(Arc::downgrade(&b));
        *ba.target.lock().unwrap() = Some(Arc::downgrade(&a));
        (a, b, ab, ba)
    }
    #[tokio::test]
    async fn native_retry_exchanges_fresh_addresses_and_sync_without_consuming_old_slots() {
        let (a, b, ab, _) = pair();
        let ac = a
            .register_call("network/2", "abcdefghijklmnop", Duration::from_secs(10))
            .unwrap();
        let bc = b
            .register_call("network/2", "abcdefghijklmnop", Duration::from_secs(10))
            .unwrap();
        ac.set_peer_native_retry(true);
        bc.set_peer_native_retry(true);
        let scope = Scope::from_timeout(Duration::from_secs(10));
        for attempt in 0..2 {
            ac.begin_probe_attempt(attempt);
            bc.begin_probe_attempt(attempt);
            let left = format!("left-{attempt}");
            let right = format!("right-{attempt}");
            let (ar, br) = tokio::join!(
                ac.exchange(
                    EXMODE_MUTUAL,
                    &left,
                    "addresses",
                    0,
                    &scope,
                    scope.remaining()
                ),
                bc.exchange(
                    EXMODE_MUTUAL,
                    &right,
                    "addresses",
                    0,
                    &scope,
                    scope.remaining()
                ),
            );
            assert_eq!(ar.unwrap(), right);
            assert_eq!(br.unwrap(), left);
            let client_sync = "C1".to_string();
            let server_sync = "S1".to_string();
            let (ar, br) = tokio::join!(
                ac.exchange(
                    EXMODE_MUTUAL,
                    &client_sync,
                    "candidate_sync",
                    1,
                    &scope,
                    scope.remaining()
                ),
                bc.exchange(
                    EXMODE_MUTUAL,
                    &server_sync,
                    "candidate_sync",
                    1,
                    &scope,
                    scope.remaining()
                ),
            );
            assert_eq!(ar.unwrap(), "S1");
            assert_eq!(br.unwrap(), "C1");
        }
        let sent = ab.sent.lock().unwrap();
        let first: Value = serde_json::from_str(&sent[0]).unwrap();
        assert!(first.get("probe_attempt").is_none());
        // Delayed delivery of an original message cannot fill a retry slot.
        b.deliver_json("connection", 1, &sent[0]).unwrap();
        let retry: Value = serde_json::from_str(&sent[2]).unwrap();
        assert_eq!(retry["probe_attempt"], 1);
        let mut relabelled: SignalFrame = serde_json::from_value(retry).unwrap();
        relabelled.probe_attempt = 2;
        assert!(bc.deliver(relabelled, 0, 0, 0).is_err());
        assert!(ac.failure().is_none());
        assert!(bc.failure().is_none());
    }

    #[tokio::test]
    async fn native_retry_loop_retries_only_with_peer_support_and_stops_on_terminal_error() {
        for supported in [false, true] {
            let (a, _b, _, _) = pair();
            let call = a
                .register_call("network/2", "abcdefghijklmnop", Duration::from_secs(10))
                .unwrap();
            call.set_peer_native_retry(supported);
            let scope = Scope::from_timeout(Duration::from_secs(10));
            let mut invoked = 0;
            let (_, attempts, error) = super::super::udp_tunnel::establish_internet_udp_p2p_with(
                &scope,
                "udp4",
                Some(call.clone()),
                || {
                    invoked += 1;
                    let code = if invoked == 1 {
                        ErrorCode::TraversalPunchTimeout
                    } else {
                        ErrorCode::NativeInputInvalidArgument
                    };
                    std::future::ready(Err(P2pError::new(code, "probe failed")))
                },
            )
            .await;
            assert_eq!(attempts, if supported { 2 } else { 1 });
            assert_eq!(invoked, attempts);
            assert_eq!(
                error.unwrap().code(),
                if supported {
                    ErrorCode::NativeInputInvalidArgument
                } else {
                    ErrorCode::TraversalPunchTimeout
                }
            );
            assert!(call.failure().is_none());
        }
    }

    #[tokio::test]
    async fn native_retry_loop_returns_second_attempt_connection() {
        let (a, _b, _, _) = pair();
        let call = a
            .register_call("network/2", "abcdefghijklmnop", Duration::from_secs(10))
            .unwrap();
        call.set_peer_native_retry(true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = listener.local_addr().unwrap();
        let (stream, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(remote), listener.accept());
        let (_peer, _) = accepted.unwrap();
        let mut connection = Some(super::super::p2p::P2PConnInfo {
            conn: super::super::p2p::P2PConn::Tcp(super::super::punch_tcp::TcpPunchedConn {
                stream: stream.unwrap(),
                remote,
            }),
            shared_key: [0; 32],
            is_client: true,
            networks_used: vec!["tcp4".into()],
            peer_address: remote.to_string(),
            local_nat_type: "easy".into(),
            remote_nat_type: "hard".into(),
            local_lan: String::new(),
            local_nat: String::new(),
            remote_lan: String::new(),
            remote_nat: String::new(),
        });
        let scope = Scope::from_timeout(Duration::from_secs(10));
        let mut invoked = 0;
        let (result, attempts, error) = super::super::udp_tunnel::establish_internet_udp_p2p_with(
            &scope,
            "tcp4",
            Some(call),
            || {
                invoked += 1;
                std::future::ready(if invoked == 1 {
                    Err(P2pError::new(
                        ErrorCode::TraversalPunchTimeout,
                        "probe timed out",
                    ))
                } else {
                    Ok(connection.take().unwrap())
                })
            },
        )
        .await;
        assert_eq!(attempts, 2);
        assert_eq!(result.unwrap().peer_address, remote.to_string());
        assert!(error.is_none());
    }

    #[test]
    fn selects_ws_only_with_v2_and_rejects_null() {
        let ws = TransportOffer {
            version: 1,
            supported: vec![WS_TRANSPORT.into()],
        };
        assert_eq!(
            ws.select(Some(&ws), true).unwrap().unwrap().selected,
            WS_TRANSPORT
        );
        assert!(ws.select(Some(&ws), false).is_err());
        assert!(ws.select(None, true).is_err());
        #[derive(Deserialize)]
        struct Message {
            #[serde(default, deserialize_with = "deserialize_offer")]
            signal_transport: Option<TransportOffer>,
        }
        assert!(serde_json::from_str::<Message>(r#"{"signal_transport":null}"#).is_err());
        assert!(serde_json::from_str::<Message>("{}")
            .unwrap()
            .signal_transport
            .is_none());
        let bad = TransportOffer {
            version: 1,
            supported: vec![WS_TRANSPORT.into(), WS_TRANSPORT.into()],
        };
        assert!(bad.validate().is_err());
    }

    #[cfg(feature = "legacy-mqtt")]
    #[test]
    fn transition_selects_mqtt_for_legacy_or_disabled_peer_only_before_exchange() {
        let both = TransportOffer::local(true);
        let legacy = TransportOffer::local(false);
        assert!(both.select(None, true).unwrap().is_none());
        assert!(!both.validate_selection(None, true).unwrap());
        assert_eq!(
            both.select(Some(&legacy), true).unwrap().unwrap().selected,
            MQTT_TRANSPORT
        );
        assert_eq!(
            legacy.select(Some(&both), true).unwrap().unwrap().selected,
            MQTT_TRANSPORT
        );
        assert_eq!(
            both.select(Some(&both), false).unwrap().unwrap().selected,
            MQTT_TRANSPORT
        );
        let ws = TransportSelection {
            version: 1,
            selected: WS_TRANSPORT.into(),
        };
        assert!(legacy.validate_selection(Some(&ws), true).is_err());
        let unknown = TransportOffer {
            version: 2,
            supported: vec![MQTT_TRANSPORT.into()],
        };
        assert!(both.select(Some(&unknown), true).is_err());
    }
    #[tokio::test]
    async fn lan_probe_expiry_does_not_poison_outcome_signaling() {
        use super::super::udp_tunnel::{exchange_role_payload, tunnel_budgets};
        let (a, b, _, _) = pair();
        let (total, probe) =
            tunnel_budgets(Duration::from_secs(2), Duration::from_millis(20), true);
        let ac = a
            .register_call("network/1", "abcdefghijklmnop", total)
            .unwrap();
        let bc = b
            .register_call("network/1", "abcdefghijklmnop", total)
            .unwrap();
        let scope_a = ac.scope(total);
        let scope_b = bc.scope(total);
        let probe_scope = scope_a.child(probe.unwrap());
        probe_scope
            .sleep_until_deadline(probe_scope.remaining())
            .await;
        assert!(probe_scope.expired());
        assert!(!scope_a.expired());
        let failed = false;
        let (ar, br) = tokio::join!(
            exchange_role_payload(
                &scope_a,
                "active",
                "abcdefghijklmnop",
                "wgvpn-lan-outcome-v1",
                &failed,
                scope_a.remaining(),
                Some(ac.clone())
            ),
            exchange_role_payload(
                &scope_b,
                "passive",
                "abcdefghijklmnop",
                "wgvpn-lan-outcome-v1",
                &failed,
                scope_b.remaining(),
                Some(bc.clone())
            )
        );
        assert!(!ar.unwrap());
        assert!(!br.unwrap());
        assert!(ac.failure().is_none());
        assert!(bc.failure().is_none());
        a.close_call("network/1");
        b.close_call("network/1");
        assert!(a
            .register_call("network/2", "next-round-token", Duration::from_secs(1))
            .is_ok());
        assert!(b
            .register_call("network/2", "next-round-token", Duration::from_secs(1))
            .is_ok());
    }

    #[test]
    fn lan_coordination_budget_is_bounded_and_legacy_timing_is_unchanged() {
        use super::super::udp_tunnel::tunnel_budgets;
        let one = Duration::from_secs(1);
        assert_eq!(
            tunnel_budgets(Duration::from_secs(100), one, true),
            (Duration::from_secs(11), Some(one))
        );
        assert_eq!(
            tunnel_budgets(Duration::from_millis(500), one, true),
            (Duration::from_millis(500), Some(one))
        );
        assert_eq!(
            tunnel_budgets(Duration::from_secs(100), one, false),
            (one, None)
        );
        let six = Duration::from_secs(6);
        assert_eq!(
            tunnel_budgets(Duration::from_secs(100), six, false),
            (six, None)
        );
    }

    #[tokio::test]
    async fn mutual_has_two_data_messages_and_no_peer_ack() {
        let (a, b, ab, ba) = pair();
        let ac = a
            .register_call("network/2", "abcdefghijklmnop", Duration::from_secs(2))
            .unwrap();
        let bc = b
            .register_call("network/2", "abcdefghijklmnop", Duration::from_secs(2))
            .unwrap();
        let scope = Scope::from_timeout(Duration::from_secs(2));
        let (c, s) = ("C1".to_string(), "S1".to_string());
        let (ar, br) = tokio::join!(
            ac.exchange(
                EXMODE_MUTUAL,
                &c,
                "candidate_sync",
                1,
                &scope,
                scope.remaining()
            ),
            bc.exchange(
                EXMODE_MUTUAL,
                &s,
                "candidate_sync",
                1,
                &scope,
                scope.remaining()
            )
        );
        assert_eq!(ar.unwrap(), "S1");
        assert_eq!(br.unwrap(), "C1");
        assert_eq!(ab.sent.lock().unwrap().len(), 1);
        assert_eq!(ba.sent.lock().unwrap().len(), 1);
        let original = ab.sent.lock().unwrap()[0].clone();
        b.deliver_json("connection", 1, &original).unwrap();
        assert_eq!(bc.state.lock().unwrap().inbox_count, 0);
        assert!(b.deliver_json("other", 1, &original).is_err());
        b.close_call("network/2");
        assert!(b.deliver_json("connection", 1, &original).is_err());
        a.close();
        b.close();
    }
    #[tokio::test]
    async fn config_wait_then_reply_consumes_request_once() {
        let (a, b, _, _) = pair();
        let ac = a
            .register_call("wg-config", "abcdefghijklmnop-kx", Duration::from_secs(2))
            .unwrap();
        let bc = b
            .register_call("wg-config", "abcdefghijklmnop-kx", Duration::from_secs(2))
            .unwrap();
        let scope = Scope::from_timeout(Duration::from_secs(2));
        let request = "request".to_string();
        let active = ac.exchange(
            EXMODE_MUTUAL,
            &request,
            "wg_config",
            0,
            &scope,
            scope.remaining(),
        );
        let passive = async {
            let request: String = bc
                .exchange(
                    EXMODE_WAIT_ONLY,
                    &String::new(),
                    "wg_config",
                    0,
                    &scope,
                    scope.remaining(),
                )
                .await
                .unwrap();
            assert_eq!(request, "request");
            bc.exchange(
                EXMODE_PUBLISH_ONLY,
                &"response".to_string(),
                "wg_config",
                0,
                &scope,
                scope.remaining(),
            )
            .await
            .unwrap()
        };
        let (reply, request): (_, String) = tokio::join!(active, passive);
        assert_eq!(reply.unwrap(), "response");
        assert_eq!(request, "request");
        a.close();
        b.close();
    }

    #[tokio::test]
    async fn lost_server_ack_fails_once_and_preserves_the_cause() {
        let (a, b, ab, _) = pair();
        ab.lose_ack
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let ac = a
            .register_call("network/1", "abcdefghijklmnop", Duration::from_secs(4))
            .unwrap();
        let bc = b
            .register_call("network/1", "abcdefghijklmnop", Duration::from_secs(4))
            .unwrap();
        let scope = ac.scope(Duration::from_secs(4));
        let (request, response) = ("C1".to_string(), "S1".to_string());
        let (ar, _br) = tokio::join!(
            ac.exchange(
                EXMODE_MUTUAL,
                &request,
                "candidate_sync",
                1,
                &scope,
                scope.remaining()
            ),
            bc.exchange(
                EXMODE_MUTUAL,
                &response,
                "candidate_sync",
                1,
                &scope,
                scope.remaining()
            )
        );
        assert_eq!(ar.unwrap_err().to_string(), "signal_server_ack_timeout");
        assert_eq!(
            ac.check().unwrap_err().to_string(),
            "signal_server_ack_timeout"
        );
        let sent = ab.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
    }

    #[tokio::test]
    async fn native_deadline_alone_is_not_a_signal_failure() {
        let (a, _, _, _) = pair();
        let call = a
            .register_call("network/1", "abcdefghijklmnop", Duration::from_millis(1))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(
            call.check().unwrap_err().to_string(),
            "signal_delivery_timeout"
        );
        let signal = SignalSession::External(call.clone());
        signal.check_failure().unwrap();
        assert!(call.failure().is_none());
        call.fail(&P2pError::new(
            ErrorCode::SignalReceiveInvalidFrame,
            "signal_protocol_invalid",
        ));
        assert_eq!(
            signal.check_failure().unwrap_err().to_string(),
            "signal_protocol_invalid"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires live STUN and real UDP sockets"]
    async fn external_candidate_protocol_failure_survives_native_cancellation() {
        let (a, b, ab, _) = pair();
        ab.invalid_sync
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let token = "invalid-candidate-protocol-token";
        let ac = a
            .register_call("network/1", token, Duration::from_secs(15))
            .unwrap();
        let bc = b
            .register_call("network/1", token, Duration::from_secs(15))
            .unwrap();
        let request = |role: &str| crate::types::UdpTunnelInput {
            token: token.into(),
            role_hint: role.into(),
            traversal_mode: "internet".into(),
            network: "udp4".into(),
            timeout_secs: 10,
            local_listen_ip: "127.0.0.1".into(),
            remote_target_ip: "127.0.0.1".into(),
            remote_target_port: 9,
            ..Default::default()
        };
        let (left, right) = tokio::join!(
            crate::api::start_udp_tunnel_with_signal(
                request("active"),
                Duration::from_secs(10),
                ac
            ),
            crate::api::start_udp_tunnel_with_signal(
                request("passive"),
                Duration::from_secs(10),
                bc.clone()
            )
        );
        assert_eq!(
            right.unwrap_err().code(),
            ErrorCode::SignalReceiveInvalidFrame
        );
        assert_eq!(
            bc.check().unwrap_err().to_string(),
            "signal_protocol_invalid"
        );
        if let Ok(tunnel) = left {
            crate::api::stop_udp_tunnel(&tunnel.handle_id);
        }
    }

    #[tokio::test]
    async fn encrypted_context_cannot_be_relabelled_as_another_candidate() {
        let (a, b, ab, _) = pair();
        let ac = a
            .register_call("network/1", "abcdefghijklmnop", Duration::from_secs(2))
            .unwrap();
        b.register_call("network/1", "abcdefghijklmnop", Duration::from_secs(2))
            .unwrap();
        ac.send_value(
            &Slot {
                channel: "candidate_sync".into(),
                step: 1,
                probe_attempt: 0,
            },
            serde_json::json!("C1"),
            ac.deadline,
        )
        .await
        .unwrap();
        let mut wire: WireFrame = serde_json::from_str(&ab.sent.lock().unwrap()[0]).unwrap();
        wire.frame.step = 2;
        assert_eq!(
            b.deliver("connection", 1, wire.frame)
                .unwrap_err()
                .to_string(),
            "signal_context_mismatch"
        );
    }
    #[tokio::test]
    async fn cancellation_wakes_exchange_without_waiting_for_deadline() {
        let (a, _, _, _) = pair();
        let call = a
            .register_call("wg-config", "abcdefghijklmnop", Duration::from_secs(30))
            .unwrap();
        let scope = Scope::from_timeout(Duration::from_secs(30));
        let empty = String::new();
        let waiting = call.exchange(
            EXMODE_WAIT_ONLY,
            &empty,
            "wg_config",
            0,
            &scope,
            scope.remaining(),
        );
        let cancelling = async {
            tokio::task::yield_now().await;
            a.close();
        };
        let (result, _) = tokio::join!(waiting, cancelling);
        assert_eq!(
            result.unwrap_err().code(),
            ErrorCode::SignalReceiveCancelled
        );
    }

    #[test]
    fn closed_call_cannot_reopen_and_accept_old_ciphertext() {
        let (a, _, _, _) = pair();
        a.register_call("network/1", "abcdefghijklmnop", Duration::from_secs(1))
            .unwrap();
        a.close_call("network/1");
        assert!(a
            .register_call("network/1", "abcdefghijklmnop", Duration::from_secs(1))
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires live STUN and real UDP sockets"]
    async fn external_udp_tunnel_carries_both_directions_without_mqtt() {
        tunnel_roundtrip("internet", "udp4").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires live STUN and real TCP sockets"]
    async fn external_tcp_tunnel_carries_both_directions_without_mqtt() {
        tunnel_roundtrip("internet", "tcp4").await;
    }

    async fn tunnel_roundtrip(mode: &str, network: &str) {
        let (a, b, ab, ba) = pair();
        let uid = format!("lan-test-{}", rand::random::<u64>());
        let ac = a
            .register_call("network/1", &uid, Duration::from_secs(75))
            .unwrap();
        let bc = b
            .register_call("network/1", &uid, Duration::from_secs(75))
            .unwrap();
        let local_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = |role: &str, port: u16| crate::types::UdpTunnelInput {
            token: uid.clone(),
            role_hint: role.into(),
            traversal_mode: mode.into(),
            network: network.into(),
            timeout_secs: 60,
            local_listen_ip: "127.0.0.1".into(),
            remote_target_ip: "127.0.0.1".into(),
            remote_target_port: port as i32,
            ..Default::default()
        };
        let left_request = request("active", local_a.local_addr().unwrap().port());
        let right_request = request("passive", local_b.local_addr().unwrap().port());
        let (left, right) = tokio::join!(
            crate::api::start_udp_tunnel_with_signal(left_request, Duration::from_secs(60), ac),
            crate::api::start_udp_tunnel_with_signal(right_request, Duration::from_secs(60), bc)
        );
        let left = left.expect("active LAN tunnel");
        let right = right.expect("passive LAN tunnel");
        async fn receive_payload(socket: &tokio::net::UdpSocket, expected: &[u8]) {
            tokio::time::timeout(Duration::from_secs(3), async {
                let mut buffer = [0u8; 2048];
                loop {
                    let (n, _) = socket.recv_from(&mut buffer).await.unwrap();
                    // Existing post-punch probes can reach the mock WG socket.
                    if &buffer[..n] == expected {
                        return;
                    }
                }
            })
            .await
            .expect("business payload timeout");
        }
        local_a
            .send_to(b"a-to-b", &left.local_forward_addr)
            .await
            .unwrap();
        receive_payload(&local_b, b"a-to-b").await;
        local_b
            .send_to(b"b-to-a", &right.local_forward_addr)
            .await
            .unwrap();
        receive_payload(&local_a, b"b-to-a").await;
        if mode == "lan" {
            assert_eq!(ab.sent.lock().unwrap().len(), 2);
            assert_eq!(ba.sent.lock().unwrap().len(), 2);
        }
        crate::api::stop_udp_tunnel(&left.handle_id);
        crate::api::stop_udp_tunnel(&right.handle_id);
        for endpoint in [&left.local_forward_addr, &right.local_forward_addr] {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if tokio::net::UdpSocket::bind(endpoint).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("stopped tunnel retained its forward socket");
        }
        a.close();
        b.close();
    }
}
