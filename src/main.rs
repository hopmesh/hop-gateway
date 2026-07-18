//! # hop-gateway — the internet-egress node (DESIGN.md §9)
//!
//! An operator runs this to let mesh clients reach the public internet through a policy-gated
//! egress point. It is a **routable Hop leaf** (dials a relay, reachable by its address) whose only
//! job is to fulfill `HttpRequest` bundles addressed to it: a client seals a request to the
//! gateway's well-known key, the gateway performs it (subject to an allowlist, per-source rate
//! limits, dedup, and request/response size caps), and seals the response back to the origin.
//!
//! Unlike `hop-endpoint` (bound to ONE origin), a gateway is a general egress: it fetches any URL
//! its [`EgressPolicy`] allows. Ship it with a TIGHT allowlist.
//!
//! Usage:
//!   hop-gateway --relay wss://relay.hopme.sh/ --identity-file PATH \
//!               --allow-host example.com --allow-host api.example.com \
//!               [--allow-method GET] [--allow-method POST] [--allow-insecure] \
//!               [--max-resp BYTES] [--healthz 0.0.0.0:8080] [--print-address]
//!
//! `--allow-host` is required (there is no default-open policy). With no `--allow-method` the
//! policy permits GET only. `--allow-insecure` drops the https-only requirement (dev only).
//!
//! services-02: this binary + the reqwest [`ReqwestHttpClient`] are the production egress backend
//! the doc comment used to only claim existed. The abuse controls live in the [`Gateway`] (the lib,
//! unit-tested); this driver owns transport (the relay dial) and lets the node do the sealing.

use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hop_core::admission::{
    byte_channel, ByteReceiver, ByteReservation, ByteSender, QueueAdmissionError, QueueLimits,
};
use hop_core::prelude::*;
use hop_gateway::{
    resolve_relay, Allowlist, BudgetedHttpResult, Gateway, HttpCall, NoHttpClient,
    ReqwestHttpClient, ResponseReservation, Screen, HTTP_RESPONSE_METADATA_RESERVATION_BYTES,
};
use tungstenite::Message;

static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

const MAX_FRAME_BYTES: usize = 1 << 20;
const MAX_FETCH_BODY_BYTES: u32 = 16 * 1024 * 1024;
const MAX_EVENT_QUEUE_EVENTS: usize = 256;
const MAX_EVENT_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = MAX_FETCH_BODY_BYTES as usize + 64 * 1024;
const MAX_EVENT_SOURCE_EVENTS: usize = 32;
const MAX_EVENT_SOURCE_BYTES: usize = MAX_EVENT_BYTES;
const MAX_EVENT_BATCH: usize = 32;
const DRIVER_TICK_INTERVAL: Duration = Duration::from_secs(1);
const MAX_OUTBOUND_FRAMES_PER_LINK: usize = 32;
const FETCH_RESERVATION_TIMEOUT: Duration = Duration::from_secs(5);
const FRAME_RESERVATION_TIMEOUT: Duration = Duration::from_millis(250);

/// services-02: cap concurrent backend fetches so a burst of mesh egress requests (which have no
/// TCP-side IP limiter) can't exhaust threads/memory. Over the cap a request is shed with a 503.
const MAX_INFLIGHT_FETCHES: usize = 128;
static INFLIGHT_FETCHES: AtomicUsize = AtomicUsize::new(0);

struct FetchGuard;
impl Drop for FetchGuard {
    fn drop(&mut self) {
        INFLIGHT_FETCHES.fetch_sub(1, Ordering::SeqCst);
    }
}

/// F-17-style liveness: wall-clock ms of the driver loop's last iteration, reported by `/healthz`.
static LAST_TICK_MS: AtomicU64 = AtomicU64::new(0);
const HEALTHZ_STALE_MS: u64 = 30_000;

/// Reconnect backoff bounds (matches hop-endpoint's services-11 fix): a dead relay is probed at
/// most once a minute, not hammered every 5s.
const RECONNECT_BASE: Duration = Duration::from_secs(5);
const RECONNECT_MAX: Duration = Duration::from_secs(60);

/// Backoff after `failures` consecutive failed dials: `BASE * 2^(failures-1)`, capped at MAX.
fn reconnect_backoff(failures: u32) -> Duration {
    if failures == 0 {
        return RECONNECT_BASE;
    }
    let mult = 1u64.checked_shl(failures - 1).unwrap_or(u64::MAX);
    let secs = RECONNECT_BASE
        .as_secs()
        .saturating_mul(mult)
        .min(RECONNECT_MAX.as_secs());
    Duration::from_secs(secs)
}

/// Driver events: bearer lifecycle + a completed backend fetch handed back from a worker.
enum Ev {
    Up(u64, Role, SyncSender<Vec<u8>>),
    Data(u64, Vec<u8>),
    Down(u64),
    /// A finished fetch: (to, for_request_id, status, headers, body).
    Fetched(PubKeyBytes, BundleId, u16, Vec<(String, String)>, Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum EventSource {
    Link(u64),
    Peer(PubKeyBytes),
}

impl Ev {
    fn admission(&self) -> (EventSource, usize) {
        match self {
            Self::Up(link, _, _) | Self::Down(link) => (EventSource::Link(*link), 1),
            Self::Data(link, bytes) => (EventSource::Link(*link), bytes.len()),
            Self::Fetched(to, _, _, headers, body) => {
                let header_bytes = headers.iter().fold(0usize, |total, (name, value)| {
                    total.saturating_add(name.len()).saturating_add(value.len())
                });
                (
                    EventSource::Peer(*to),
                    body.len().saturating_add(header_bytes).saturating_add(80),
                )
            }
        }
    }
}

#[derive(Clone)]
struct EventTx(ByteSender<Ev, EventSource>);

impl EventTx {
    fn send(&self, event: Ev) -> std::result::Result<(), QueueAdmissionError> {
        let (source, bytes) = event.admission();
        self.0.send(source, bytes, event)
    }

    #[cfg(test)]
    fn try_send(&self, event: Ev) -> std::result::Result<(), QueueAdmissionError> {
        let (source, bytes) = event.admission();
        self.0.try_send(source, bytes, event)
    }

    fn try_reserve_fetched(
        &self,
        peer: PubKeyBytes,
        body_cap: u32,
    ) -> std::result::Result<FetchReservation, QueueAdmissionError> {
        self.0
            .try_reserve(
                EventSource::Peer(peer),
                HTTP_RESPONSE_METADATA_RESERVATION_BYTES.saturating_add(body_cap as usize),
            )
            .map(FetchReservation)
    }

    fn send_reserved(
        &self,
        mut reservation: FetchReservation,
        event: Ev,
    ) -> std::result::Result<(), QueueAdmissionError> {
        let (_, bytes) = event.admission();
        if bytes > reservation.0.bytes() {
            reservation.0.grow_to(bytes, FETCH_RESERVATION_TIMEOUT)?;
        } else {
            reservation.0.shrink_to(bytes);
        }
        reservation.0.send(event)
    }

    fn reserve_frame(
        &self,
        link: u64,
    ) -> std::result::Result<ByteReservation<Ev, EventSource>, QueueAdmissionError> {
        self.0.reserve_timeout(
            EventSource::Link(link),
            MAX_FRAME_BYTES,
            FRAME_RESERVATION_TIMEOUT,
        )
    }

    fn send_reserved_frame(
        &self,
        mut reservation: ByteReservation<Ev, EventSource>,
        link: u64,
        bytes: Vec<u8>,
    ) -> std::result::Result<(), QueueAdmissionError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(QueueAdmissionError::EventTooLarge);
        }
        reservation.shrink_to(bytes.len());
        reservation.try_send(Ev::Data(link, bytes))
    }

    #[cfg(test)]
    fn usage(&self) -> (usize, usize) {
        self.0.usage()
    }
}

struct FetchReservation(ByteReservation<Ev, EventSource>);

impl ResponseReservation for FetchReservation {
    fn bytes(&self) -> usize {
        self.0.bytes()
    }

    fn grow_to(&mut self, bytes: usize, timeout: Duration) -> bool {
        self.0.grow_to(bytes, timeout).is_ok()
    }

    fn shrink_to(&mut self, bytes: usize) {
        self.0.shrink_to(bytes);
    }
}

struct EventRx(ByteReceiver<Ev, EventSource>);

impl EventRx {
    fn recv_timeout(&self, timeout: Duration) -> std::result::Result<Ev, RecvTimeoutError> {
        self.0.recv_timeout(timeout)
    }

    fn try_recv(&self) -> std::result::Result<Ev, mpsc::TryRecvError> {
        self.0.try_recv()
    }
}

fn event_channel() -> (EventTx, EventRx) {
    let (tx, rx) = byte_channel(QueueLimits {
        max_events: MAX_EVENT_QUEUE_EVENTS,
        max_bytes: MAX_EVENT_QUEUE_BYTES,
        max_event_bytes: MAX_EVENT_BYTES,
        max_source_events: MAX_EVENT_SOURCE_EVENTS,
        max_source_bytes: MAX_EVENT_SOURCE_BYTES,
    });
    (EventTx(tx), EventRx(rx))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn main() {
    let mut relay: Option<String> = Some("wss://relay.hopme.sh/".to_string());
    let mut relay_cli_set = false;
    let mut identity_file: Option<String> = None;
    let mut allow_hosts: Vec<String> = Vec::new();
    let mut allow_methods: Vec<String> = Vec::new();
    let mut https_only = true;
    let mut max_resp: u32 = 8 * 1024 * 1024;
    let mut healthz: Option<String> = None;
    let mut print_address = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--relay" => {
                relay = args.next();
                relay_cli_set = true;
            }
            "--no-relay" => {
                relay = None;
                relay_cli_set = true;
            }
            "--identity-file" => identity_file = args.next(),
            "--allow-host" => {
                if let Some(h) = args.next() {
                    allow_hosts.push(h);
                }
            }
            "--allow-method" => {
                if let Some(m) = args.next() {
                    allow_methods.push(m);
                }
            }
            "--allow-insecure" => https_only = false,
            "--max-resp" => {
                max_resp = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(max_resp)
                    .min(MAX_FETCH_BODY_BYTES)
            }
            "--healthz" => healthz = args.next(),
            "--print-address" => print_address = true,
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }

    // services-r3-03: env fallbacks (so infra can gate the relay dial without a CLI change) via the
    // ONE shared, tested precedence helper — identical to hop-endpoint, so the two cannot drift.
    relay = resolve_relay(
        relay,
        relay_cli_set,
        std::env::var("HOP_NO_RELAY").ok().as_deref(),
        std::env::var("HOP_RELAY").ok().as_deref(),
    );

    let identity = load_identity(&identity_file);
    if print_address {
        println!("{}", bs58::encode(identity.address()).into_string());
        return;
    }

    if allow_hosts.is_empty() {
        eprintln!(
            "--allow-host <host> is required (at least one). A gateway has NO default-open policy."
        );
        std::process::exit(2);
    }
    if allow_methods.is_empty() {
        allow_methods.push("GET".to_string()); // safe default
    }

    let addr = identity.address();
    println!("hop-gateway: address {}", bs58::encode(addr).into_string());
    println!(
        "hop-gateway: allow methods={allow_methods:?} hosts={allow_hosts:?} https_only={https_only}"
    );

    let method_refs: Vec<&str> = allow_methods.iter().map(|s| s.as_str()).collect();
    let host_refs: Vec<&str> = allow_hosts.iter().map(|s| s.as_str()).collect();
    let policy = Allowlist::new(&method_refs, &host_refs, https_only);
    let client = std::sync::Arc::new(ReqwestHttpClient::default());
    // The gateway and the node share the same identity (Identity isn't Clone; rebuild from the seed).
    // The gateway holds it to open request bundles / seal responses via `screen` + the node.
    let gateway_id = Identity::from_secret_bytes(&identity.to_secret_bytes());
    let mut gateway = Gateway::new(gateway_id, NoHttpClient, policy);

    let mut node = Node::new(identity);
    node.set_kind(NodeKind::Gateway);
    node.set_max_relayed(0); // a leaf: never carries others' traffic

    let (tx, rx) = event_channel();

    // Optional /healthz listener (for a container liveness probe).
    if let Some(hz) = healthz {
        std::thread::spawn(move || {
            let listener = TcpListener::bind(&hz).expect("bind --healthz address");
            for stream in listener.incoming().flatten() {
                serve_healthz(stream);
            }
        });
    }

    if let Some(relay_url) = relay {
        let tx = tx.clone();
        println!("hop-gateway: joining mesh via relay {relay_url} (routable leaf)");
        std::thread::spawn(move || dial_relay(relay_url, tx));
    } else {
        println!("hop-gateway: no relay configured; idle (not mesh-reachable)");
    }

    run(node, &mut gateway, client, max_resp, tx, rx);
}

/// The driver: sole owner of the node + the gateway abuse-control state. Screens each decoded egress
/// services-r6-01: run one core call under catch_unwind so a panic on attacker-controlled bundle bytes
/// (decode/verify/open) becomes a logged skip instead of tearing down this always-on driver loop.
/// Mirrors the endpoint's guard_core (the endpoint has 20 such sites; the gateway had none, so a single
/// core panic here killed the whole gateway process). We do NOT log the offending bytes.
///
/// F-18d (pass-18 audit): this wraps a WHOLE core call, not the individual `self.*` mutations
/// inside one `on_bundle` match arm. That is deliberate: `Node`'s state is plain safe-Rust
/// `HashMap`/`Vec` (memory-safe regardless of where a panic lands). See the longer
/// note on `hop-relayd`'s `guard_core` (`services/hop-relayd/src/main.rs`) for the full
/// audit trail: no reachable mid-arm panic was found beyond one already-fixed case, and the
/// riskiest arm (`Payload::HpsRekey`) was reordered to fail-safe (install-then-remove) and is
/// enforced by `hop_core::node::tests::hps_rekey_install_before_remove_survives_a_mid_arm_panic`.
fn guard_core<T>(what: &str, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            eprintln!("hop-gateway: core panic in {what}; skipped (gateway stays up)");
            None
        }
    }
}

/// request through the [`Gateway`], performs allowed fetches on worker threads (so a slow upstream
/// never stalls the mesh loop), and seals responses.
fn run(
    mut node: Node,
    gateway: &mut Gateway<NoHttpClient, Allowlist>,
    client: std::sync::Arc<ReqwestHttpClient>,
    max_resp: u32,
    tx: EventTx,
    rx: EventRx,
) {
    let mut writers: HashMap<u64, SyncSender<Vec<u8>>> = HashMap::new();
    let mut next_tick = Instant::now() + DRIVER_TICK_INTERVAL;
    loop {
        if !process_driver_events(&mut node, &mut writers, &rx, &mut next_tick) {
            break;
        }

        for r in guard_core("take-http-requests", || node.take_http_requests()).unwrap_or_default()
        {
            let now = now_ms();
            let url = match gateway.screen(r.id, r.from, &r.method, &r.url, r.body.len(), now) {
                Screen::Allow(url) => url,
                decision => {
                    let (status, msg) = deny_response(decision);
                    let ct = vec![("content-type".to_string(), "text/plain".to_string())];
                    apply_driver_event(
                        &mut node,
                        &mut writers,
                        Ev::Fetched(r.from, r.id, status, ct, msg.into_bytes()),
                    );
                    continue;
                }
            };
            if INFLIGHT_FETCHES.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT_FETCHES {
                INFLIGHT_FETCHES.fetch_sub(1, Ordering::SeqCst);
                // services-r6-02: screen() Allowed this and recorded it for dedup, but we are shedding
                // it here with a TRANSIENT, explicitly-retryable 503. Release the dedup record so the
                // client's retry of the same id is screened afresh instead of bouncing as Duplicate.
                gateway.forget(r.id);
                let ct = vec![("content-type".to_string(), "text/plain".to_string())];
                apply_driver_event(
                    &mut node,
                    &mut writers,
                    Ev::Fetched(r.from, r.id, 503, ct, b"hop-gateway: busy".to_vec()),
                );
                continue;
            }
            let resp_cap = r.max_resp.min(max_resp);
            let reservation = match tx.try_reserve_fetched(r.from, resp_cap) {
                Ok(reservation) => reservation,
                Err(_) => {
                    INFLIGHT_FETCHES.fetch_sub(1, Ordering::SeqCst);
                    gateway.forget(r.id);
                    let headers = vec![("content-type".to_string(), "text/plain".to_string())];
                    apply_driver_event(
                        &mut node,
                        &mut writers,
                        Ev::Fetched(
                            r.from,
                            r.id,
                            503,
                            headers,
                            b"hop-gateway: response budget saturated".to_vec(),
                        ),
                    );
                    continue;
                }
            };
            let call = HttpCall {
                method: r.method,
                url,
                headers: r.headers,
                body: r.body,
                max_resp_bytes: resp_cap,
            };
            let (client, tx) = (client.clone(), tx.clone());
            let (from, id) = (r.from, r.id);
            std::thread::spawn(move || {
                let _guard = FetchGuard; // releases the in-flight slot on drop (incl. panic unwind)
                match client.perform_reserved(call, reservation, FETCH_RESERVATION_TIMEOUT) {
                    BudgetedHttpResult::Complete {
                        result,
                        reservation,
                    } => {
                        let _ = tx.send_reserved(
                            reservation,
                            Ev::Fetched(from, id, result.status, result.headers, result.body),
                        );
                    }
                    BudgetedHttpResult::BudgetRejected(reservation) => {
                        let headers = vec![("content-type".to_string(), "text/plain".to_string())];
                        let _ = tx.send_reserved(
                            reservation,
                            Ev::Fetched(
                                from,
                                id,
                                503,
                                headers,
                                b"hop-gateway: response budget saturated".to_vec(),
                            ),
                        );
                    }
                }
            });
        }

        let mut blocked = Vec::new();
        for (link, bytes) in
            guard_core("drain-outgoing", || node.drain_outgoing()).unwrap_or_default()
        {
            if let Some(out) = writers.get(&link) {
                if matches!(
                    out.try_send(bytes),
                    Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_))
                ) {
                    blocked.push(link);
                }
            }
        }
        for link in blocked {
            writers.remove(&link);
            guard_core("bearer-disconnected", || {
                node.handle(BearerEvent::Disconnected(link))
            });
        }
    }
}

fn process_driver_events(
    node: &mut Node,
    writers: &mut HashMap<u64, SyncSender<Vec<u8>>>,
    rx: &EventRx,
    next_tick: &mut Instant,
) -> bool {
    tick_if_due(node, next_tick);
    let wait = next_tick.saturating_duration_since(Instant::now());
    let first = match rx.recv_timeout(wait) {
        Ok(event) => Some(event),
        Err(RecvTimeoutError::Timeout) => {
            tick_if_due(node, next_tick);
            None
        }
        Err(RecvTimeoutError::Disconnected) => return false,
    };
    if let Some(first) = first {
        apply_driver_event(node, writers, first);
        for _ in 1..MAX_EVENT_BATCH {
            if Instant::now() >= *next_tick {
                break;
            }
            match rx.try_recv() {
                Ok(event) => apply_driver_event(node, writers, event),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return false,
            }
        }
    }
    tick_if_due(node, next_tick);
    true
}

fn apply_driver_event(node: &mut Node, writers: &mut HashMap<u64, SyncSender<Vec<u8>>>, event: Ev) {
    match event {
        Ev::Up(link, role, out) => {
            writers.insert(link, out);
            guard_core("bearer-connected", || {
                node.handle(BearerEvent::Connected(link, role))
            });
        }
        Ev::Data(link, bytes) => {
            guard_core("bearer-data", || {
                node.handle(BearerEvent::Data(link, bytes))
            });
        }
        Ev::Down(link) => {
            writers.remove(&link);
            guard_core("bearer-disconnected", || {
                node.handle(BearerEvent::Disconnected(link))
            });
        }
        Ev::Fetched(to, for_id, status, headers, body) => {
            guard_core("http-response", || {
                let _ = node.send_http_response(to, for_id, status, headers, body);
            });
        }
    }
}

fn tick_if_due(node: &mut Node, next_tick: &mut Instant) {
    let monotonic_now = Instant::now();
    if monotonic_now < *next_tick {
        return;
    }
    let wall_now = now_ms();
    LAST_TICK_MS.store(wall_now, Ordering::Relaxed);
    guard_core("tick", || node.tick(wall_now));
    while *next_tick <= monotonic_now {
        *next_tick += DRIVER_TICK_INTERVAL;
    }
}

/// Map a non-Allow screen decision to an HTTP-ish status + a short body for the origin.
fn deny_response(decision: Screen) -> (u16, String) {
    match decision {
        Screen::Allow(_) => (200, String::new()),
        Screen::Duplicate => (208, "hop-gateway: duplicate request".to_string()),
        Screen::RateLimited => (429, "hop-gateway: rate limited".to_string()),
        Screen::PolicyDenied => (403, "hop-gateway: policy denied".to_string()),
        Screen::RequestTooLarge => (413, "hop-gateway: request too large".to_string()),
    }
}

/// A `/healthz` probe: 200 if the driver ticked recently, else 503.
fn serve_healthz(mut stream: TcpStream) {
    let last = LAST_TICK_MS.load(Ordering::Relaxed);
    let healthy = last != 0 && now_ms().saturating_sub(last) < HEALTHZ_STALE_MS;
    let (status, body) = if healthy {
        ("200 OK", "ok")
    } else {
        ("503 Service Unavailable", "stale")
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn bearer_ws_config() -> tungstenite::protocol::WebSocketConfig {
    tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES))
}

/// Dial a relay over `wss://` and bridge it as a Hop bearer link (Initiator). Reconnects with
/// exponential backoff (services-11) so a dead relay isn't hammered.
fn dial_relay(url: String, ev_tx: EventTx) {
    use tungstenite::stream::MaybeTlsStream;
    let mut failures: u32 = 0;
    loop {
        match tungstenite::client::connect_with_config(&url, Some(bearer_ws_config()), 3) {
            Ok((mut ws, _resp)) => {
                failures = 0;
                eprintln!("hop-gateway: connected to relay {url}");
                match ws.get_ref() {
                    MaybeTlsStream::Plain(s) => {
                        let _ = s.set_nonblocking(true);
                    }
                    MaybeTlsStream::Rustls(t) => {
                        let _ = t.get_ref().set_nonblocking(true);
                    }
                    _ => {}
                }
                let link = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
                let (out_tx, out_rx) = mpsc::sync_channel::<Vec<u8>>(MAX_OUTBOUND_FRAMES_PER_LINK);
                if ev_tx.send(Ev::Up(link, Role::Initiator, out_tx)).is_err() {
                    return;
                }
                'conn: loop {
                    loop {
                        match out_rx.try_recv() {
                            Ok(bytes) => match ws.write(Message::Binary(bytes.into())) {
                                Ok(()) => {}
                                Err(tungstenite::Error::Io(e))
                                    if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                Err(_) => break 'conn,
                            },
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => break 'conn,
                        }
                    }
                    match ws.flush() {
                        Ok(()) => {}
                        Err(tungstenite::Error::Io(e))
                            if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => break,
                    }
                    let reservation = match ev_tx.reserve_frame(link) {
                        Ok(reservation) => reservation,
                        Err(QueueAdmissionError::TimedOut)
                        | Err(QueueAdmissionError::QueueFull) => continue,
                        Err(_) => break,
                    };
                    match ws.read() {
                        Ok(Message::Binary(b)) => {
                            if ev_tx
                                .send_reserved_frame(reservation, link, b.to_vec())
                                .is_err()
                            {
                                return;
                            }
                        }
                        Ok(Message::Close(_)) => break,
                        Ok(_) => drop(reservation),
                        Err(tungstenite::Error::Io(e))
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
                let _ = ev_tx.send(Ev::Down(link));
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let wait = reconnect_backoff(failures);
                eprintln!(
                    "hop-gateway: relay {url} unreachable ({e}); retry #{failures} in {}s",
                    wait.as_secs()
                );
                std::thread::sleep(wait);
                continue;
            }
        }
        std::thread::sleep(RECONNECT_BASE);
    }
}

/// Load a stable identity from a 32-byte file (so the gateway's well-known address survives
/// restarts), generating and persisting one 0600 on first run.
fn load_identity(path: &Option<String>) -> Identity {
    if let Some(path) = path {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Identity::from_secret_bytes(&seed);
            }
        }
        let id = Identity::generate();
        if let Err(e) = write_secret_600(path, &id.to_secret_bytes()) {
            eprintln!("warning: could not persist identity to {path}: {e}; address will change");
        }
        return id;
    }
    eprintln!("warning: no --identity-file; address will change on restart");
    Identity::generate()
}

/// Write `bytes` to `path` owner-only (0600), like hop-endpoint (services-13).
fn write_secret_600(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturated_driver_queue_still_ticks_prunes_and_limits_each_batch() {
        let identity = Identity::generate();
        let destination = Identity::generate();
        let expiring = Bundle::create(
            &identity,
            Destination::Device(destination.address()),
            &destination.address(),
            &Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"expire".to_vec(),
            },
            BundleOpts {
                lifetime_ms: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let expiring_id = expiring.id();
        let mut node = Node::new(identity);
        assert!(node.store.put(expiring, 0));

        let (tx, rx) = event_channel();
        for link in 0..MAX_EVENT_QUEUE_EVENTS / MAX_EVENT_SOURCE_EVENTS {
            for _ in 0..MAX_EVENT_SOURCE_EVENTS {
                tx.try_send(Ev::Data(link as u64, vec![link as u8]))
                    .unwrap();
            }
        }
        assert_eq!(
            tx.try_send(Ev::Data(100, vec![0])),
            Err(QueueAdmissionError::QueueFull)
        );
        assert_eq!(tx.usage(), (MAX_EVENT_QUEUE_EVENTS, MAX_EVENT_QUEUE_EVENTS));

        let mut writers = HashMap::new();
        let mut next_tick = Instant::now();
        assert!(process_driver_events(
            &mut node,
            &mut writers,
            &rx,
            &mut next_tick,
        ));
        assert!(!node.store.contains(&expiring_id));
        assert_eq!(
            tx.usage().0,
            MAX_EVENT_QUEUE_EVENTS - MAX_EVENT_BATCH,
            "one loop iteration consumes only a bounded batch"
        );
    }

    #[test]
    fn one_hundred_twenty_eight_fetch_producers_are_bounded_by_queue_plus_reservations() {
        let (tx, rx) = event_channel();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(129));
        let mut workers = Vec::new();
        for index in 0..128u8 {
            let tx = tx.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                tx.try_reserve_fetched([index; 32], MAX_FETCH_BODY_BYTES)
                    .ok()
            }));
        }
        barrier.wait();
        let reservations: Vec<_> = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            reservations.len(),
            MAX_EVENT_QUEUE_BYTES / MAX_EVENT_BYTES,
            "worker concurrency is coupled to the complete response byte ceiling"
        );
        assert!(tx.usage().1 <= MAX_EVENT_QUEUE_BYTES);
        drop(reservations);
        assert_eq!(tx.usage(), (0, 0));
        assert!(tx
            .try_reserve_fetched([255u8; 32], MAX_FETCH_BODY_BYTES)
            .is_ok());
        drop(rx);
    }

    #[test]
    fn reconnect_backoff_grows_then_caps() {
        assert_eq!(reconnect_backoff(0), RECONNECT_BASE);
        assert_eq!(reconnect_backoff(1), Duration::from_secs(5));
        assert_eq!(reconnect_backoff(2), Duration::from_secs(10));
        assert_eq!(reconnect_backoff(5), RECONNECT_MAX);
        assert_eq!(
            reconnect_backoff(100),
            RECONNECT_MAX,
            "no overflow, stays capped"
        );
    }

    #[test]
    fn deny_response_maps_each_rejection() {
        assert_eq!(deny_response(Screen::PolicyDenied).0, 403);
        assert_eq!(deny_response(Screen::RateLimited).0, 429);
        assert_eq!(deny_response(Screen::RequestTooLarge).0, 413);
        assert_eq!(deny_response(Screen::Duplicate).0, 208);
    }
}
