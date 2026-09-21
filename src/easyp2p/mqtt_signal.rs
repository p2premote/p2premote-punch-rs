//! Port of easyp2p/mqtt_signal.go: a multi-broker MQTT signaling session.
//!
//! Connects every configured broker concurrently (paho parity: auto-reconnect,
//! retry until success), keeps a desired-subscription set so late/reconnected
//! brokers resubscribe, and provides the `exchange` primitive (burst
//! re-publish, self-echo filtering, per-topic waiters with pending queue).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use tokio::sync::mpsc;

use super::crypto::{self, SecurePayload};
use super::{CancelToken, P2pError, Result, Scope, EXMODE_MUTUAL, EXMODE_PUBLISH_ONLY, EXMODE_WAIT_ONLY, TOPIC_DESC_SIGNAL};

pub const MQTT_NO_PREFERRED_BROKER: i32 = -1;

const MQTT_PUBLISH_SETTLE_WINDOW: Duration = Duration::from_millis(500);
const MQTT_PREFERRED_BROKER_WINDOW: Duration = Duration::from_millis(800);
const MQTT_PUBLISH_KEEP_ALIVE: Duration = Duration::from_secs(5);
const MQTT_PUBLISH_TICKER_INTERVAL: Duration = Duration::from_secs(2);

const MQTT_PUBLISH_BURST_DELAYS: &[Duration] = &[
    Duration::from_millis(200),
    Duration::from_millis(800),
    Duration::from_secs(2),
];

pub type MessageHandler = Arc<dyn Fn(&str) -> std::result::Result<bool, String> + Send + Sync>;

#[derive(Clone)]
pub struct BrokerConfig {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone)]
struct RecvPayload {
    data: String,
    index: usize,
}

/// ParseMQTTServerV3: "tcp://[user:pass@]host:port" → broker config.
/// The Go version keeps query params for tls/insecure; the default brokers
/// are plain tcp so only userinfo is honored here.
pub fn parse_mqtt_server(input: &str) -> Result<BrokerConfig> {
    let (scheme, rest) = match input.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("tcp", input),
    };
    let rest = match rest.split_once('?') {
        Some((r, _)) => r,
        None => rest,
    };
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| P2pError::msg(format!("invalid broker address: {}", input)))?;
    let port: u16 = port
        .parse()
        .map_err(|_| P2pError::msg(format!("invalid broker port: {}", input)))?;
    let (username, password) = match userinfo {
        Some(u) => match u.split_once(':') {
            Some((user, pass)) => (Some(user.to_string()), Some(pass.to_string())),
            None => (Some(u.to_string()), None),
        },
        None => (None, None),
    };
    Ok(BrokerConfig {
        url: format!("{}://{}:{}", scheme, host, port),
        host: host.to_string(),
        port,
        username,
        password,
    })
}

#[allow(dead_code)]
pub struct ExchangeOutcome {
    pub data: String,
    pub index: i32,
    pub keep_alive: bool,
}

struct Waiter {
    self_payload: String,
    handler: Option<MessageHandler>,
    recv_tx: mpsc::Sender<RecvPayload>,
    err_tx: mpsc::Sender<String>,
}

#[derive(Default)]
struct SessionState {
    connected: HashMap<usize, AsyncClient>,
    subscriptions: HashMap<String, u8>,
    subscribed: HashMap<String, HashSet<usize>>,
    waiters: HashMap<String, HashMap<u64, Arc<Waiter>>>,
    pending: HashMap<String, RecvPayload>,
    closed: bool,
}


pub struct MqttSignalSession {
    brokers: Vec<BrokerConfig>,
    cancel: CancelToken,
    state: Mutex<SessionState>,
    next_waiter_id: std::sync::atomic::AtomicU64,
    connected_once: AtomicBool,
}

impl MqttSignalSession {
    /// NewMQTTSignalSession: connect all brokers concurrently; succeeds when at
    /// least one broker is connected. Fails only if none connect within scope.
    pub async fn new(
        scope: &Scope,
        client_id: &str,
        _local_ip: &str,
    ) -> Result<Arc<MqttSignalSession>> {
        let mut brokers = Vec::new();
        for server in super::mqtt_broker_servers() {
            brokers.push(parse_mqtt_server(&server)?);
        }
        if brokers.is_empty() {
            return Err(P2pError::msg("no MQTT broker servers configured"));
        }
        let client_id = if client_id.is_empty() {
            crypto::mqtt_generate_client_id(TOPIC_DESC_SIGNAL, "mqtt-signal-session")
        } else {
            client_id.to_string()
        };

        let session = Arc::new(MqttSignalSession {
            brokers,
            cancel: CancelToken::new(),
            state: Mutex::new(SessionState::default()),
            next_waiter_id: std::sync::atomic::AtomicU64::new(1),
            connected_once: AtomicBool::new(false),
        });

        {
            let (fail_tx, mut fail_rx) = mpsc::channel(session.brokers.len());
            let (ready_tx, mut ready_rx) = mpsc::channel::<()>(session.brokers.len());
            for (index, config) in session.brokers.iter().enumerate() {
                let s = session.clone();
                let config = config.clone();
                let client_id = client_id.clone();
                let fail_tx = fail_tx.clone();
                let ready_tx = ready_tx.clone();
                tokio::spawn(async move {
                    s.broker_loop(config, index, client_id, fail_tx, ready_tx).await;
                });
            }
            drop(fail_tx);
            drop(ready_tx);

            // Wait until: first broker ready (Go's `ready` channel), all
            // brokers failed their first connection attempt, or the caller
            // scope expires.
            let mut failures = 0usize;
            loop {
                if session.has_connected_client() {
                    break;
                }
                if scope.expired() || session.cancel.is_cancelled() {
                    break;
                }
                tokio::select! {
                    _ = scope.sleep_until_deadline(scope.remaining()) => {},
                    _ = session.cancel.cancelled() => {},
                    _ = ready_rx.recv() => break,
                    _ = fail_rx.recv() => {
                        failures += 1;
                        if failures >= session.brokers.len() {
                            break;
                        }
                    }
                }
            }
        }

        if !session.has_connected_client() {
            session.close();
            return Err(P2pError::msg("failed to connect to any MQTT broker"));
        }
        Ok(session)
    }

    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }

    #[allow(dead_code)]
    pub fn cancel_token(&self) -> &CancelToken {
        &self.cancel
    }

    pub fn close(&self) {
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return;
            }
            state.closed = true;
            state.connected.clear();
        }
        self.cancel.cancel();
    }

    async fn broker_loop(
        self: &Arc<Self>,
        config: BrokerConfig,
        index: usize,
        client_id: String,
        fail_tx: mpsc::Sender<()>,
        ready_tx: mpsc::Sender<()>,
    ) {
        let mut opts = MqttOptions::new(client_id.clone(), config.host.clone(), config.port);
        opts.set_keep_alive(Duration::from_secs(30));
        opts.set_clean_session(true);
        if let (Some(user), Some(pass)) = (&config.username, &config.password) {
            opts.set_credentials(user.clone(), pass.clone());
        }
        let (client, mut eventloop) = AsyncClient::new(opts, 64);
        let mut reported_failure = false;

        loop {
            if self.cancel.is_cancelled() {
                let _ = client.disconnect().await;
                return;
            }
            match tokio::time::timeout(Duration::from_secs(30), eventloop.poll()).await {
                Err(_elapsed) => {
                    // poll timeout: loop again (keeps the task cancellable).
                }
                Ok(Err(_err)) => {
                    if !reported_failure {
                        reported_failure = true;
                        let _ = fail_tx.try_send(());
                    }
                    self.mark_disconnected(index);
                    // rumqttc reconnects on the next poll.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Ok(Ok(event)) => match event {
                    Event::Incoming(Packet::ConnAck(_)) => {
                        crate::p2plog!("[MQTT-DIAG] broker#{} ConnAck", index);
                        self.mark_connected(index, client.clone());
                        let _ = ready_tx.try_send(()); // wake the constructor (Go: ready <- struct{}{})
                        if !reported_failure {
                            reported_failure = true;
                            self.connected_once.store(true, Ordering::SeqCst);
                        }
                        // paho parity: OnConnect → resubscribe everything.
                        let desired = self.desired_subscriptions();
                        for (topic, qos) in desired {
                            let ok = self.subscribe_client(index, &client, &topic, qos).await;
                            crate::p2plog!("[MQTT-DIAG] broker#{} resubscribe {} -> {}", index, topic, ok);
                        }
                    }
                    Event::Incoming(Packet::Publish(publish)) => {
                        let payload = String::from_utf8_lossy(&publish.payload).into_owned();
                        crate::p2plog!(
                            "[MQTT-DIAG] broker#{} incoming topic={} len={}",
                            index,
                            publish.topic,
                            payload.len()
                        );
                        self.dispatch_message(&publish.topic, index, payload);
                    }
                    _ => {}
                },
            }
        }
    }

    fn has_connected_client(&self) -> bool {
        !self.state.lock().unwrap().connected.is_empty()
    }

    fn desired_subscriptions(&self) -> Vec<(String, u8)> {
        self.state
            .lock()
            .unwrap()
            .subscriptions
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    fn mark_connected(&self, index: usize, client: AsyncClient) {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        state.connected.insert(index, client);
    }

    fn mark_disconnected(&self, index: usize) {
        self.state.lock().unwrap().connected.remove(&index);
    }

    fn connected_clients(&self) -> Vec<(usize, AsyncClient)> {
        self.state
            .lock()
            .unwrap()
            .connected
            .iter()
            .map(|(i, c)| (*i, c.clone()))
            .collect()
    }

    fn connected_count(&self) -> usize {
        self.state.lock().unwrap().connected.len()
    }

    fn broker_count(&self) -> usize {
        self.brokers.len()
    }

    fn broker_name(&self, index: usize) -> String {
        self.brokers
            .get(index)
            .map(|b| b.url.clone())
            .unwrap_or_else(|| format!("broker#{}", index))
    }

    async fn subscribe_client(&self, index: usize, client: &AsyncClient, topic: &str, qos: u8) -> bool {
        let result = client
            .subscribe(topic, if qos >= 1 { QoS::AtLeastOnce } else { QoS::AtMostOnce })
            .await;
        let ok = result.is_ok();
        if ok {
            let mut state = self.state.lock().unwrap();
            state
                .subscribed
                .entry(topic.to_string())
                .or_default()
                .insert(index);
        }
        ok
    }

    /// subscribe on every connected broker; requires ≥1 success.
    async fn subscribe(&self, scope: &Scope, topic: &str, qos: u8) -> Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(P2pError::msg("MQTT signal session closed"));
            }
            state.subscriptions.insert(topic.to_string(), qos);
        }
        let clients = self.connected_clients();
        let mut success = 0usize;
        for (index, client) in &clients {
            if self.subscribe_client(*index, client, topic, qos).await {
                success += 1;
            }
        }
        if scope.expired() {
            return Err(P2pError::msg("operation cancelled"));
        }
        if success == 0 {
            let mut state = self.state.lock().unwrap();
            state.subscriptions.remove(topic);
            state.subscribed.remove(topic);
            return Err(P2pError::msg(format!("failed to subscribe MQTT topic {}", topic)));
        }
        Ok(())
    }

    pub async fn prepare_topic(&self, scope: &Scope, topic_salt: &str, session_uid: &str) -> Result<()> {
        let topic = crypto::topic_from_salt_and_session_uid(topic_salt, session_uid);
        self.subscribe(scope, &topic, 1).await
    }

    fn dispatch_message(&self, topic: &str, index: usize, data: String) {
        let waiters: Vec<Arc<Waiter>> = {
            let mut state = self.state.lock().unwrap();
            match state.waiters.get(topic) {
                Some(map) if !map.is_empty() => map.values().cloned().collect(),
                _ => {
                    crate::p2plog!(
                        "[MQTT-DIAG] dispatch: no waiter on {} (len={}) -> pending",
                        topic,
                        data.len()
                    );
                    state.pending.insert(topic.to_string(), RecvPayload { data, index });
                    return;
                }
            }
        };
        crate::p2plog!("[MQTT-DIAG] dispatch: {} waiter(s) on {}", waiters.len(), topic);
        for waiter in waiters {
            self.deliver_message(&waiter, topic, index, &data);
        }
    }

    fn deliver_message(&self, waiter: &Arc<Waiter>, topic: &str, index: usize, data: &str) {
        if data == waiter.self_payload {
            crate::p2plog!("[MQTT-DIAG] deliver: dropped self echo on {}", topic);
            return;
        }
        if let Some(handler) = &waiter.handler {
            match handler(data) {
                Err(err) => {
                    let _ = waiter.err_tx.try_send(format!(
                        "handling message error from broker {} on topic {}: {}",
                        index, topic, err
                    ));
                    return;
                }
                Ok(false) => return,
                Ok(true) => {}
            }
        }
        let _ = waiter
            .recv_tx
            .try_send(RecvPayload {
                data: data.to_string(),
                index,
            });
    }

    // ============ publish ============

    async fn publish_at_least_n(
        &self,
        clients: &[(usize, AsyncClient)],
        topic: &str,
        payload: &str,
        min_success: usize,
        settle_window: Duration,
    ) -> usize {
        if clients.is_empty() {
            return 0;
        }
        let min_success = if min_success == 0 || min_success > clients.len() {
            clients.len()
        } else {
            min_success
        };

        let (success_tx, mut success_rx) = mpsc::channel::<()>(clients.len());
        for (_, client) in clients {
            let client = client.clone();
            let topic = topic.to_string();
            let payload = payload.to_string();
            let success_tx = success_tx.clone();
            tokio::spawn(async move {
                if client
                    .publish(topic, QoS::AtLeastOnce, false, payload)
                    .await
                    .is_ok()
                {
                    let _ = success_tx.send(()).await;
                }
            });
        }
        drop(success_tx);

        let total = clients.len();
        let mut count = 0usize;
        if settle_window.is_zero() {
            while count < min_success {
                if success_rx.recv().await.is_none() {
                    break;
                }
                count += 1;
            }
        } else {
            let sleep = tokio::time::sleep(settle_window);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    _ = &mut sleep => break,
                    received = success_rx.recv() => {
                        if received.is_none() {
                            break;
                        }
                        count += 1;
                    }
                }
            }
        }
        crate::p2plog!("published {}/{} brokers on topic {}", count, total, topic);
        count
    }

    async fn publish(&self, topic: &str, payload: &str, min_success: usize, settle_window: Duration) -> usize {
        // Only publish on brokers whose subscription for this topic is
        // confirmed. The peer's waitOnly reply uses the broker our message
        // arrived on (Go publish_preferred), and Go republishes for only
        // ~5s after receiving — publishing through a broker we are not
        // subscribed to would steer the reply somewhere we can never hear.
        let subscribed: std::collections::HashSet<usize> = {
            let state = self.state.lock().unwrap();
            state.subscribed.get(topic).cloned().unwrap_or_default()
        };
        let clients: Vec<(usize, AsyncClient)> = if subscribed.is_empty() {
            self.connected_clients()
        } else {
            self.connected_clients()
                .into_iter()
                .filter(|(index, _)| subscribed.contains(index))
                .collect()
        };
        self.publish_at_least_n(&clients, topic, payload, min_success, settle_window).await
    }

    async fn publish_preferred(&self, topic: &str, payload: &str, preferred_broker_index: usize) -> usize {
        let clients: Vec<(usize, AsyncClient)> = self
            .connected_clients()
            .into_iter()
            .filter(|(index, _)| *index == preferred_broker_index)
            .collect();
        let success = self
            .publish_at_least_n(&clients, topic, payload, 1, MQTT_PREFERRED_BROKER_WINDOW)
            .await;
        if success > 0 {
            crate::easyp2p::p2p_logf(&format!(
                "published topic {} via preferred broker {}",
                topic,
                self.broker_name(preferred_broker_index)
            ));
        } else {
            crate::easyp2p::p2p_logf(&format!(
                "preferred broker publish missed for topic {} via {}",
                topic,
                self.broker_name(preferred_broker_index)
            ));
        }
        success
    }

    // ============ exchange ============

    pub async fn exchange(
        self: &Arc<Self>,
        scope: &Scope,
        exmode: i32,
        send_data: &str,
        topic_salt: &str,
        session_uid: &str,
        timeout: Duration,
        message_handler: Option<MessageHandler>,
        preferred_broker_index: i32,
    ) -> Result<ExchangeOutcome> {
        let topic = crypto::topic_from_salt_and_session_uid(topic_salt, session_uid);
        if scope.expired() {
            return Err(P2pError::msg("operation cancelled"));
        }
        let exchange_scope = scope.child(timeout);
        let qos = 1u8;

        if exmode != EXMODE_PUBLISH_ONLY {
            self.subscribe(&exchange_scope, &topic, qos).await?;
        }
        if scope.expired() {
            return Err(P2pError::msg("operation cancelled"));
        }

        let stop_publish = Arc::new(NotifyLike::new());
        let start_background_publisher = || {
            let session = self.clone();
            let topic = topic.clone();
            let payload = send_data.to_string();
            let stop = stop_publish.clone();
            tokio::spawn(async move {
                for delay in MQTT_PUBLISH_BURST_DELAYS {
                    tokio::select! {
                        _ = stop.notified() => return,
                        _ = session.cancel.cancelled() => return,
                        _ = tokio::time::sleep(*delay) => {
                            session.publish(&topic, &payload, 1, Duration::ZERO).await;
                        }
                    }
                }
                let mut ticker = tokio::time::interval(MQTT_PUBLISH_TICKER_INTERVAL);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // first tick fires immediately; skip it
                loop {
                    tokio::select! {
                        _ = stop.notified() => return,
                        _ = session.cancel.cancelled() => return,
                        _ = ticker.tick() => {
                            session.publish(&topic, &payload, 1, Duration::ZERO).await;
                        }
                    }
                }
            });
        };

        let stop_publisher_after = |delay: Duration| {
            let stop = stop_publish.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                stop.notify();
            });
        };

        if exmode == EXMODE_PUBLISH_ONLY {
            let mut success = 0usize;
            if preferred_broker_index >= 0 {
                success = self
                    .publish_preferred(&topic, send_data, preferred_broker_index as usize)
                    .await;
            }
            if success == 0 {
                success = self
                    .publish(&topic, send_data, 1, MQTT_PUBLISH_SETTLE_WINDOW)
                    .await;
            }
            if success == 0 {
                return Err(P2pError::msg("failed to publish MQTT reply"));
            }
            start_background_publisher();
            stop_publisher_after(MQTT_PUBLISH_KEEP_ALIVE);
            return Ok(ExchangeOutcome {
                data: String::new(),
                index: preferred_broker_index,
                keep_alive: true,
            });
        }

        // Go parity: register the waiter before the first mutual publish. This
        // prevents a fast peer reply (or our broker echo followed by the peer
        // reply) from racing through the one-slot pending map before the
        // exchange is ready to receive it.
        let (recv_tx, mut recv_rx) = mpsc::channel(1);
        let (err_tx, mut err_rx) = mpsc::channel(1);
        let waiter = Arc::new(Waiter {
            self_payload: send_data.to_string(),
            handler: message_handler,
            recv_tx,
            err_tx,
        });
        let waiter_id = self.next_waiter_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(P2pError::msg("MQTT signal session closed"));
            }
            state
                .waiters
                .entry(topic.clone())
                .or_default()
                .insert(waiter_id, waiter.clone());
            if let Some(pending) = state.pending.remove(&topic) {
                drop(state);
                self.deliver_message(&waiter, &topic, pending.index, &pending.data);
            }
        }

        if exmode == EXMODE_MUTUAL {
            self.publish(&topic, send_data, 1, Duration::ZERO).await;
            start_background_publisher();
        }

        let outcome = tokio::select! {
            received = recv_rx.recv() => {
                match received {
                    Some(r) => {
                        if exmode != EXMODE_WAIT_ONLY {
                            self.publish(&topic, send_data, 1, Duration::ZERO).await;
                            stop_publisher_after(MQTT_PUBLISH_KEEP_ALIVE);
                            Ok(ExchangeOutcome { data: r.data, index: r.index as i32, keep_alive: true })
                        } else {
                            stop_publish.notify();
                            Ok(ExchangeOutcome { data: r.data, index: r.index as i32, keep_alive: false })
                        }
                    }
                    None => Err(P2pError::msg("MQTT signal session closed")),
                }
            }
            err = err_rx.recv() => {
                stop_publish.notify();
                Err(P2pError::msg(err.unwrap_or_else(|| "MQTT signal session closed".to_string())))
            }
            _ = exchange_scope.sleep_until_deadline(exchange_scope.remaining()) => {
                stop_publish.notify();
                if scope.expired() {
                    return Err(P2pError::msg("operation cancelled"));
                }
                Err(P2pError::msg(format!(
                    "timeout waiting for remote data exchange on topic {} (brokers={}/{} subscribed={})",
                    topic,
                    self.connected_count(),
                    self.broker_count(),
                    self.subscribed_count(&topic),
                )))
            }
            _ = self.cancel.cancelled() => {
                stop_publish.notify();
                if scope.expired() {
                    return Err(P2pError::msg("operation cancelled"));
                }
                Err(P2pError::msg("MQTT signal session closed"))
            }
        };

        // Remove waiter.
        {
            let mut state = self.state.lock().unwrap();
            if let Some(map) = state.waiters.get_mut(&topic) {
                map.remove(&waiter_id);
                if map.is_empty() {
                    state.waiters.remove(&topic);
                }
            }
        }
        outcome
    }

    fn subscribed_count(&self, topic: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .subscribed
            .get(topic)
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

/// Minimal Notify wrapper: notify() wakes current and future waiters.
struct NotifyLike {
    notify: tokio::sync::Notify,
}

impl NotifyLike {
    fn new() -> Self {
        NotifyLike {
            notify: tokio::sync::Notify::new(),
        }
    }
    fn notify(&self) {
        self.notify.notify_waiters();
        // Also permit notified() polled after notify().
        self.notify.notify_one();
    }
    async fn notified(&self) {
        self.notify.notified().await
    }
}

// ============ secure exchange (MQTT_SecureExchangeWithSession) ============

const VER_INCOMPAT: &str = "possible version incompatibility with the peer";
const SECURE_EXCHANGE_SALT: &str = "mqtt-exchange-gonc-v2.2.0";

fn encode_secure_payload<T: serde::Serialize>(key: &[u8; 32], send_data: &T) -> Result<String> {
    let info_bytes = serde_json::to_string(send_data)?;
    let enc_payload = crypto::encrypt_aes(key, info_bytes.as_bytes())?;
    Ok(serde_json::to_string(&enc_payload)?)
}

fn decode_secure_payload<T: serde::de::DeserializeOwned>(key: &[u8; 32], data: &str) -> Result<T> {
    let payload: SecurePayload = serde_json::from_str(data).map_err(|err| {
        P2pError::msg(format!("failed to unmarshal remote secure payload: {} ({})", err, VER_INCOMPAT))
    })?;
    let plain = crypto::decrypt_aes(key, &payload).map_err(|err| {
        P2pError::msg(format!("failed to decrypt remote payload: {} ({})", err, VER_INCOMPAT))
    })?;
    serde_json::from_slice(&plain).map_err(|err| {
        P2pError::msg(format!("failed to unmarshal remote exchange payload: {} ({})", err, VER_INCOMPAT))
    })
}

/// MQTT_SecureExchangeWithSession: AES-GCM encrypted payload exchange.
/// `message_filter` receives the decoded value (Go: `func(T) (bool, error)`).
pub async fn secure_exchange_with_session<T: serde::Serialize + serde::de::DeserializeOwned + 'static>(
    scope: &Scope,
    signal: &Arc<MqttSignalSession>,
    exmode: i32,
    send_data: &T,
    topic_salt: &str,
    session_uid: &str,
    timeout: Duration,
    message_filter: Option<Arc<dyn Fn(&T) -> std::result::Result<bool, String> + Send + Sync>>,
) -> Result<(T, i32)> {
    let key = crypto::derive_key(SECURE_EXCHANGE_SALT, session_uid);
    let payload = encode_secure_payload(&key, send_data)?;

    let handler: MessageHandler = Arc::new(move |data: &str| {
        let decoded: T = decode_secure_payload(&key, data).map_err(|e| e.to_string())?;
        if let Some(filter) = &message_filter {
            if !filter(&decoded)? {
                return Ok(false);
            }
        }
        Ok(true)
    });

    let outcome = signal
        .exchange(scope, exmode, &payload, topic_salt, session_uid, timeout, Some(handler), MQTT_NO_PREFERRED_BROKER)
        .await?;
    let decoded: T = decode_secure_payload(&key, &outcome.data)?;
    Ok((decoded, outcome.index))
}

/// mqttSecurePublishWithSession: publish an encrypted payload, preferring one
/// broker (used by the passive side's reply step).
pub async fn mqtt_secure_publish_with_session<T: serde::Serialize>(
    scope: &Scope,
    signal: &Arc<MqttSignalSession>,
    send_data: &T,
    topic_salt: &str,
    session_uid: &str,
    timeout: Duration,
    preferred_broker_index: i32,
) -> Result<i32> {
    let key = crypto::derive_key(SECURE_EXCHANGE_SALT, session_uid);
    let payload = encode_secure_payload(&key, send_data)?;
    let outcome = signal
        .exchange(scope, EXMODE_PUBLISH_ONLY, &payload, topic_salt, session_uid, timeout, None, preferred_broker_index)
        .await?;
    Ok(outcome.index)
}
