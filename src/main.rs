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
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hop_core::prelude::*;
use hop_gateway::{
    resolve_relay, Allowlist, Gateway, HttpCall, HttpClient, NoHttpClient, ReqwestHttpClient,
    Screen,
};
use tungstenite::Message;

static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

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
    Up(u64, Role, Sender<Vec<u8>>),
    Data(u64, Vec<u8>),
    Down(u64),
    /// A finished fetch: (to, for_request_id, status, headers, body).
    Fetched(PubKeyBytes, BundleId, u16, Vec<(String, String)>, Vec<u8>),
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
            "--max-resp" => max_resp = args.next().and_then(|s| s.parse().ok()).unwrap_or(max_resp),
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

    let (tx, rx) = mpsc::channel::<Ev>();

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
/// request through the [`Gateway`], performs allowed fetches on worker threads (so a slow upstream
/// never stalls the mesh loop), and seals responses.
fn run(
    mut node: Node,
    gateway: &mut Gateway<NoHttpClient, Allowlist>,
    client: std::sync::Arc<ReqwestHttpClient>,
    max_resp: u32,
    tx: Sender<Ev>,
    rx: mpsc::Receiver<Ev>,
) {
    let mut writers: HashMap<u64, Sender<Vec<u8>>> = HashMap::new();
    loop {
        LAST_TICK_MS.store(now_ms(), Ordering::Relaxed);
        match rx.recv_timeout(Duration::from_millis(1000)) {
            Ok(Ev::Up(link, role, out)) => {
                writers.insert(link, out);
                node.handle(BearerEvent::Connected(link, role));
            }
            Ok(Ev::Data(link, bytes)) => node.handle(BearerEvent::Data(link, bytes)),
            Ok(Ev::Down(link)) => {
                writers.remove(&link);
                node.handle(BearerEvent::Disconnected(link));
            }
            Ok(Ev::Fetched(to, for_id, status, headers, body)) => {
                let _ = node.send_http_response(to, for_id, status, headers, body);
            }
            Err(RecvTimeoutError::Timeout) => node.tick(now_ms()),
            Err(RecvTimeoutError::Disconnected) => break,
        }

        for r in node.take_http_requests() {
            let now = now_ms();
            let decision = gateway.screen(r.id, r.from, &r.method, &r.url, r.body.len(), now);
            if decision != Screen::Allow {
                let (status, msg) = deny_response(decision);
                let ct = vec![("content-type".to_string(), "text/plain".to_string())];
                let _ = tx.send(Ev::Fetched(r.from, r.id, status, ct, msg.into_bytes()));
                continue;
            }
            if INFLIGHT_FETCHES.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT_FETCHES {
                INFLIGHT_FETCHES.fetch_sub(1, Ordering::SeqCst);
                let ct = vec![("content-type".to_string(), "text/plain".to_string())];
                let _ = tx.send(Ev::Fetched(
                    r.from,
                    r.id,
                    503,
                    ct,
                    b"hop-gateway: busy".to_vec(),
                ));
                continue;
            }
            let resp_cap = r.max_resp.min(max_resp);
            let call = HttpCall {
                method: r.method,
                url: r.url,
                headers: r.headers,
                body: r.body,
                max_resp_bytes: resp_cap,
            };
            let (client, tx) = (client.clone(), tx.clone());
            let (from, id) = (r.from, r.id);
            std::thread::spawn(move || {
                let _guard = FetchGuard; // releases the in-flight slot on drop (incl. panic unwind)
                let result = client.perform(call);
                let _ = tx.send(Ev::Fetched(
                    from,
                    id,
                    result.status,
                    result.headers,
                    result.body,
                ));
            });
        }

        for (link, bytes) in node.drain_outgoing() {
            if let Some(out) = writers.get(&link) {
                if out.send(bytes).is_err() {
                    writers.remove(&link);
                }
            }
        }
    }
}

/// Map a non-Allow screen decision to an HTTP-ish status + a short body for the origin.
fn deny_response(decision: Screen) -> (u16, String) {
    match decision {
        Screen::Allow => (200, String::new()),
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

/// Dial a relay over `wss://` and bridge it as a Hop bearer link (Initiator). Reconnects with
/// exponential backoff (services-11) so a dead relay isn't hammered.
fn dial_relay(url: String, ev_tx: Sender<Ev>) {
    use tungstenite::stream::MaybeTlsStream;
    let mut failures: u32 = 0;
    loop {
        match tungstenite::connect(&url) {
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
                let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
                if ev_tx.send(Ev::Up(link, Role::Initiator, out_tx)).is_err() {
                    return;
                }
                'conn: loop {
                    loop {
                        match out_rx.try_recv() {
                            Ok(bytes) => match ws.write(Message::Binary(bytes)) {
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
                    match ws.read() {
                        Ok(Message::Binary(b)) => {
                            if ev_tx.send(Ev::Data(link, b.to_vec())).is_err() {
                                return;
                            }
                        }
                        Ok(Message::Close(_)) => break,
                        Ok(_) => {}
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
