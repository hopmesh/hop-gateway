//! # hop-gateway
//!
//! The internet-egress role (DESIGN.md §9). A gateway unseals an `HttpRequest`
//! bundle, performs the request (subject to policy + abuse controls), and seals an
//! `HttpResponse` back to the origin device key (approach (c): request sealed to a
//! well-known gateway key, response sealed to the origin's `src_x`).
//!
//! The HTTP client is injected via [`HttpClient`] so fulfillment logic is testable
//! without a network; a blocking `reqwest` impl ([`ReqwestHttpClient`]) is the production
//! backend, enforcing connect/read timeouts and a streaming response-size cap.
//!
//! Abuse controls (DESIGN.md §9): TTL-bounded request dedup, per-source rate
//! limiting, an allowlist [`EgressPolicy`], and request/response size caps.
//!
//! Two entry points share the same abuse controls:
//!
//!  * [`Gateway::fulfill`] operates on a raw sealed [`Bundle`] (unseals, performs, reseals the
//!    response back to the origin). Used directly + in tests.
//!  * [`Gateway::screen`] operates on an already-decoded request (the shape a Hop [`Node`] surfaces
//!    via `take_http_requests`), returning an allow/deny decision so the `hop-gateway` binary can
//!    let the node do the sealing/routing while the gateway keeps ownership of the abuse controls.

use std::collections::HashMap;

use hop_core::prelude::*;

/// services-r3-03: the ONE shared, tested graceful-degrade precedence for resolving the relay
/// endpoint from (CLI, `HOP_NO_RELAY`, `HOP_RELAY`). Both the `hop-gateway` and `hop-endpoint`
/// binaries call this so the two cannot drift, and a regression fails `resolve_relay_precedence`
/// below rather than shipping. Pure (no process spawn, no env mutation) so it is unit-testable.
///
/// Precedence:
///  * A CLI `--relay`/`--no-relay` (`cli_set = true`) ALWAYS wins; env is ignored entirely.
///  * Otherwise `HOP_NO_RELAY` in {`1`,`true`,`yes`} forces no relay (degrade).
///  * Otherwise a non-empty `HOP_RELAY` overrides the default relay URL.
///  * Otherwise the passed-in default (`cli_relay`) stands.
pub fn resolve_relay(
    cli_relay: Option<String>,
    cli_set: bool,
    no_relay_env: Option<&str>,
    relay_env: Option<&str>,
) -> Option<String> {
    if cli_set {
        return cli_relay; // an explicit --relay/--no-relay is authoritative
    }
    match no_relay_env {
        Some("1") | Some("true") | Some("yes") => None,
        _ => match relay_env {
            Some(url) if !url.is_empty() => Some(url.to_string()),
            _ => cli_relay,
        },
    }
}

/// An outbound HTTP request the gateway should perform.
pub struct HttpCall {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub max_resp_bytes: u32,
}

/// The result of performing an [`HttpCall`].
pub struct HttpResult {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Pluggable HTTP backend. The real impl (reqwest) is injected in production;
/// tests use a fake.
pub trait HttpClient {
    fn perform(&self, call: HttpCall) -> HttpResult;
}

/// Policy gate for which requests a gateway is willing to make (DESIGN.md §9).
pub trait EgressPolicy {
    fn allows(&self, method: &str, url: &str) -> bool;
}

/// A placeholder [`HttpClient`] that never performs a request (returns 500). Used when a caller
/// drives fulfillment via [`Gateway::screen`] and owns the fetch itself (the `hop-gateway` binary),
/// so the gateway's `C` parameter is present but unused. Calling `perform` is a programming error.
pub struct NoHttpClient;
impl HttpClient for NoHttpClient {
    fn perform(&self, _call: HttpCall) -> HttpResult {
        HttpResult {
            status: 500,
            headers: vec![],
            body: b"hop-gateway: NoHttpClient::perform called (use screen() + your own client)"
                .to_vec(),
        }
    }
}

/// Permit everything — for tests/dev only. Production ships an [`Allowlist`].
pub struct AllowAll;
impl EgressPolicy for AllowAll {
    fn allows(&self, _method: &str, _url: &str) -> bool {
        true
    }
}

/// An allowlist policy: only the listed methods, only `https` (optionally), and
/// only hosts matching one of the suffixes (exact or `*.suffix`).
pub struct Allowlist {
    pub methods: Vec<String>,
    pub host_suffixes: Vec<String>,
    pub https_only: bool,
}

impl Allowlist {
    pub fn new(methods: &[&str], host_suffixes: &[&str], https_only: bool) -> Self {
        Self {
            methods: methods.iter().map(|m| m.to_string()).collect(),
            host_suffixes: host_suffixes.iter().map(|h| h.to_string()).collect(),
            https_only,
        }
    }
}

/// Extract the host (no scheme, no userinfo, no port, no path) from a URL.
///
/// services-01: this MUST strip userinfo before parsing the host. The naive
/// `split(['/', '?', ':']).next()` returns the userinfo for `https://good.com:x@evil.com/` (it
/// splits at the first `:`), so the allowlist would approve `good.com` while the fetch actually hits
/// `evil.com`, an SSRF/allowlist-bypass primitive. We take the authority (up to the first path /
/// query / fragment delimiter), drop anything up to and including the last `@` (userinfo), then trim
/// a trailing `:port`. IPv6 literals (`[::1]`) keep their bracketed colons.
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split("://").nth(1)?;
    // Authority ends at the first '/', '?', or '#'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Drop userinfo: everything up to and including the LAST '@' in the authority.
    let hostport = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    // Strip a trailing ":port". For an IPv6 literal keep everything inside the brackets.
    let host = if let Some(end) = hostport.strip_prefix('[').and_then(|_| hostport.find(']')) {
        &hostport[..=end] // includes the closing bracket; ignore any ":port" after it
    } else {
        hostport.split(':').next().unwrap_or(hostport)
    };
    Some(host).filter(|h| !h.is_empty())
}

impl EgressPolicy for Allowlist {
    fn allows(&self, method: &str, url: &str) -> bool {
        if !self.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return false;
        }
        if self.https_only && !url.starts_with("https://") {
            return false;
        }
        match host_of(url) {
            Some(host) => self
                .host_suffixes
                .iter()
                .any(|s| host == s || host.ends_with(&format!(".{s}"))),
            None => false,
        }
    }
}

/// Gateway abuse-control configuration.
#[derive(Clone, Copy, Debug)]
pub struct GatewayConfig {
    /// How long a fulfilled request id is remembered for dedup.
    pub dedup_ttl_ms: u64,
    /// Max fulfillments per source within `rate_window_ms`.
    pub max_requests_per_window: u32,
    pub rate_window_ms: u64,
    /// Reject requests whose body exceeds this many bytes.
    pub max_request_bytes: usize,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            dedup_ttl_ms: 600_000, // 10 min
            max_requests_per_window: 60,
            rate_window_ms: 60_000, // 1 min
            max_request_bytes: 64 * 1024,
        }
    }
}

/// Why a request was not fulfilled (or the response, if it was).
pub enum FulfillOutcome {
    /// A response bundle sealed back to the origin.
    Response(Box<Bundle>),
    /// Not an internet-egress request for us.
    NotForUs,
    /// Already fulfilled within the dedup window.
    Duplicate,
    /// The source exceeded its rate limit.
    RateLimited,
    /// The policy rejected the method/URL.
    PolicyDenied,
    /// The request body exceeded the size cap.
    RequestTooLarge,
}

/// A gateway fulfillment worker.
pub struct Gateway<C, P> {
    identity: Identity,
    client: C,
    policy: P,
    config: GatewayConfig,
    /// Request id → time fulfilled, pruned past the dedup TTL.
    fulfilled: HashMap<BundleId, u64>,
    /// Source address → recent fulfillment timestamps, pruned past the window.
    rate: HashMap<PubKeyBytes, Vec<u64>>,
}

impl<C: HttpClient, P: EgressPolicy> Gateway<C, P> {
    pub fn new(identity: Identity, client: C, policy: P) -> Self {
        Self::with_config(identity, client, policy, GatewayConfig::default())
    }

    pub fn with_config(identity: Identity, client: C, policy: P, config: GatewayConfig) -> Self {
        Self {
            identity,
            client,
            policy,
            config,
            fulfilled: HashMap::new(),
            rate: HashMap::new(),
        }
    }

    /// The gateway's address — clients seal egress requests to this (approach (c)).
    pub fn address(&self) -> PubKeyBytes {
        self.identity.address()
    }

    /// Fulfill an egress bundle, subject to dedup, rate limits, policy, and size
    /// caps. The response is sealed back to the request's `src` address.
    pub fn fulfill(&mut self, request: &Bundle, now_ms: u64) -> Result<FulfillOutcome> {
        // Egress requests are now device-addressed to the gateway (like a hop-endpoint),
        // not a mesh-visible `InternetEgress` destination — the mesh can't tell an egress
        // request from any other peer message (§30, privacy by default).
        let to_us = match &request.inner.dst {
            Destination::Device(d) => *d == self.address(),
            _ => false,
        };
        if !to_us {
            return Ok(FulfillOutcome::NotForUs);
        }
        request.verify()?;

        // Dedup within the TTL window (DESIGN.md §7) — pruned to bound memory.
        let ttl = self.config.dedup_ttl_ms;
        self.fulfilled
            .retain(|_, &mut t| now_ms.saturating_sub(t) < ttl);
        // services-12: bound the per-source rate map too. Without this it grows one entry per
        // distinct source address forever (each source's vec is only pruned when THAT source is
        // seen again). Drop any source whose most recent hit has aged out of the rate window.
        let window = self.config.rate_window_ms;
        self.rate.retain(|_, hits| {
            hits.retain(|&t| now_ms.saturating_sub(t) < window);
            !hits.is_empty()
        });
        if self.fulfilled.contains_key(&request.id()) {
            return Ok(FulfillOutcome::Duplicate);
        }

        let Payload::HttpRequest {
            method,
            url,
            headers,
            body,
            max_resp_bytes,
            ..
        } = request.open(&self.identity)?
        else {
            return Ok(FulfillOutcome::NotForUs);
        };

        if body.len() > self.config.max_request_bytes {
            return Ok(FulfillOutcome::RequestTooLarge);
        }
        if !self.policy.allows(&method, &url) {
            return Ok(FulfillOutcome::PolicyDenied);
        }
        if self.is_rate_limited(request.inner.src, now_ms) {
            return Ok(FulfillOutcome::RateLimited);
        }

        let result = self.client.perform(HttpCall {
            method,
            url,
            headers,
            body,
            max_resp_bytes,
        });

        let mut resp_body = result.body;
        resp_body.truncate(max_resp_bytes as usize);

        let payload = Payload::HttpResponse {
            status: result.status,
            headers: result.headers,
            body: resp_body,
            for_bundle_id: request.id(),
        };

        let response = Bundle::create(
            &self.identity,
            Destination::Device(request.inner.src),
            &request.inner.src,
            &payload,
            BundleOpts {
                created_at: now_ms,
                lifetime_ms: request.inner.lifetime_ms,
                hop_limit: request.env.hop_limit.max(1),
                ..Default::default()
            },
        )?;

        // Record success for dedup and rate accounting.
        self.fulfilled.insert(request.id(), now_ms);
        self.rate.entry(request.inner.src).or_default().push(now_ms);

        Ok(FulfillOutcome::Response(Box::new(response)))
    }

    fn is_rate_limited(&mut self, src: PubKeyBytes, now_ms: u64) -> bool {
        let window = self.config.rate_window_ms;
        let hits = self.rate.entry(src).or_default();
        hits.retain(|&t| now_ms.saturating_sub(t) < window);
        hits.len() as u32 >= self.config.max_requests_per_window
    }

    /// Apply the abuse controls (dedup, rate limit, policy, size cap) to an already-decoded egress
    /// request, WITHOUT unsealing a bundle or performing the fetch. This is the seam the
    /// `hop-gateway` binary uses: a Hop [`Node`] surfaces decoded requests + seals the response, so
    /// the gateway keeps ownership of the abuse controls while the node owns transport/crypto.
    ///
    /// `id`/`src` identify the request for dedup + per-source rate accounting; on [`Screen::Allow`]
    /// the id and source are recorded (so a later duplicate is rejected and the source's rate ticks).
    /// The caller then performs the fetch and routes the response by `id`.
    pub fn screen(
        &mut self,
        id: BundleId,
        src: PubKeyBytes,
        method: &str,
        url: &str,
        body_len: usize,
        now_ms: u64,
    ) -> Screen {
        // Prune both maps to bound memory (same as fulfill()).
        let ttl = self.config.dedup_ttl_ms;
        self.fulfilled
            .retain(|_, &mut t| now_ms.saturating_sub(t) < ttl);
        let window = self.config.rate_window_ms;
        self.rate.retain(|_, hits| {
            hits.retain(|&t| now_ms.saturating_sub(t) < window);
            !hits.is_empty()
        });

        if self.fulfilled.contains_key(&id) {
            return Screen::Duplicate;
        }
        if body_len > self.config.max_request_bytes {
            return Screen::RequestTooLarge;
        }
        if !self.policy.allows(method, url) {
            return Screen::PolicyDenied;
        }
        if self.is_rate_limited(src, now_ms) {
            return Screen::RateLimited;
        }
        // Accepted: record for dedup + rate accounting, then let the caller perform the fetch.
        self.fulfilled.insert(id, now_ms);
        self.rate.entry(src).or_default().push(now_ms);
        Screen::Allow
    }

    /// services-r6-02: release the dedup record for a request that `screen()` Allowed but the caller
    /// then could NOT perform (e.g. it was shed with a transient 503 at the in-flight fetch cap).
    /// Without this, the Allow's dedup insert would make the client's retry of the SAME id a
    /// `Duplicate`, so an explicitly-retryable 503 could never actually be retried. Only the dedup
    /// entry is released; the rate-limit accounting stays, since the attempt was real.
    pub fn forget(&mut self, id: BundleId) {
        self.fulfilled.remove(&id);
    }
}

/// The decision [`Gateway::screen`] returns for a decoded egress request. `Allow` means the caller
/// should perform the fetch and route the response; every other variant is a rejection the caller
/// turns into an error response (or drops).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Allow,
    Duplicate,
    RateLimited,
    PolicyDenied,
    RequestTooLarge,
}

/// The production HTTP backend (services-02): a blocking `reqwest` client that enforces connect and
/// read timeouts, disables redirects (so a backend can't bounce an egress fetch off-allowlist), and
/// streams the response body with a hard cap at `max_resp_bytes` so a huge/endless response can't
/// exhaust gateway memory. Gated behind the `reqwest` feature so the trait-only lib stays lean.
#[cfg(feature = "reqwest")]
pub struct ReqwestHttpClient {
    http: reqwest::blocking::Client,
}

#[cfg(feature = "reqwest")]
impl ReqwestHttpClient {
    /// Build a client with a total request `timeout` and a separate `connect_timeout`. Redirects are
    /// disabled (an egress fetch must hit exactly the allowlisted URL, never a redirect target).
    pub fn new(timeout: std::time::Duration, connect_timeout: std::time::Duration) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .connect_timeout(connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build reqwest client");
        Self { http }
    }
}

#[cfg(feature = "reqwest")]
impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(10),
        )
    }
}

#[cfg(feature = "reqwest")]
fn sanitized_request_headers(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    let connection_named: std::collections::HashSet<String> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    headers
        .iter()
        .filter(|(name, _)| {
            let name = name.to_ascii_lowercase();
            !connection_named.contains(&name)
                && !matches!(
                    name.as_str(),
                    "host"
                        | "connection"
                        | "keep-alive"
                        | "proxy-authenticate"
                        | "proxy-authorization"
                        | "proxy-connection"
                        | "te"
                        | "trailer"
                        | "transfer-encoding"
                        | "upgrade"
                        | "forwarded"
                )
                && !name.starts_with("x-forwarded-")
        })
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

#[cfg(feature = "reqwest")]
impl HttpClient for ReqwestHttpClient {
    fn perform(&self, call: HttpCall) -> HttpResult {
        use std::io::Read;
        let method = match reqwest::Method::from_bytes(call.method.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                return HttpResult {
                    status: 400,
                    headers: vec![],
                    body: b"hop-gateway: bad method".to_vec(),
                }
            }
        };
        let mut req = self.http.request(method, &call.url);
        for (k, v) in sanitized_request_headers(&call.headers) {
            req = req.header(k, v);
        }
        if !call.body.is_empty() {
            req = req.body(call.body);
        }
        let mut resp = match req.send() {
            Ok(r) => r,
            Err(_) => {
                return HttpResult {
                    status: 502,
                    headers: vec![],
                    body: b"hop-gateway: upstream unreachable".to_vec(),
                }
            }
        };
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();
        // Stream the body with a hard cap: read at most max_resp_bytes+1 and truncate, so an
        // endless/oversized response can't exhaust memory (the +1 lets the gateway note truncation
        // if it ever wants to; here we simply cap).
        let cap = call.max_resp_bytes as usize;
        let mut body = Vec::new();
        let mut limited = (&mut resp).take(cap as u64 + 1);
        let _ = limited.read_to_end(&mut body);
        body.truncate(cap);
        HttpResult {
            status,
            headers,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "reqwest")]
    #[test]
    fn production_client_derives_host_and_strips_hop_by_hop_headers() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let url = format!("http://{authority}/headers");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = Vec::new();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
                }
            }
            tx.send(headers).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });

        let result = ReqwestHttpClient::default().perform(HttpCall {
            method: "GET".into(),
            url,
            headers: vec![
                ("Host".into(), "internal.invalid".into()),
                ("Connection".into(), "x-secret".into()),
                ("X-Secret".into(), "remove-me".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
                ("X-Forwarded-Host".into(), "internal.invalid".into()),
                ("X-End-To-End".into(), "keep-me".into()),
            ],
            body: vec![],
            max_resp_bytes: 1024,
        });
        assert_eq!(result.status, 204);
        let headers = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(
            headers.iter().find(|(name, _)| name == "host").unwrap().1,
            authority
        );
        for forbidden in [
            "connection",
            "x-secret",
            "transfer-encoding",
            "x-forwarded-host",
        ] {
            assert!(!headers.iter().any(|(name, _)| name == forbidden));
        }
        assert!(headers
            .iter()
            .any(|(name, value)| name == "x-end-to-end" && value == "keep-me"));
    }

    #[test]
    fn resolve_relay_precedence_is_shared_and_correct() {
        // services-r3-03: the ONE tested precedence both binaries now call, so the gateway can no
        // longer drift from the endpoint. Mirrors the endpoint's precedence test.
        let default = || Some("wss://relay.hopme.sh/".to_string());

        // 1. No CLI, no env: the default stands.
        assert_eq!(resolve_relay(default(), false, None, None), default());
        // 2. HOP_NO_RELAY truthy => degrade to no relay.
        for v in ["1", "true", "yes"] {
            assert_eq!(
                resolve_relay(default(), false, Some(v), None),
                None,
                "HOP_NO_RELAY={v} degrades"
            );
        }
        // 3. HOP_RELAY overrides the default; an empty value is ignored.
        assert_eq!(
            resolve_relay(default(), false, None, Some("wss://eu.relay/")),
            Some("wss://eu.relay/".to_string())
        );
        assert_eq!(resolve_relay(default(), false, None, Some("")), default());
        // HOP_NO_RELAY wins over HOP_RELAY.
        assert_eq!(
            resolve_relay(default(), false, Some("1"), Some("wss://eu.relay/")),
            None,
            "degrade wins over an explicit HOP_RELAY"
        );
        // 4. A CLI --relay/--no-relay ALWAYS wins; env is ignored entirely.
        assert_eq!(
            resolve_relay(
                Some("wss://cli/".into()),
                true,
                Some("1"),
                Some("wss://env/")
            ),
            Some("wss://cli/".to_string()),
            "explicit --relay overrides even HOP_NO_RELAY"
        );
        assert_eq!(
            resolve_relay(None, true, None, Some("wss://env/")),
            None,
            "explicit --no-relay overrides HOP_RELAY"
        );
    }

    struct FakeHttp;
    impl HttpClient for FakeHttp {
        fn perform(&self, _call: HttpCall) -> HttpResult {
            HttpResult {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"hello from the internet".to_vec(),
            }
        }
    }

    fn request(
        client: &Identity,
        gw_x: &PubKeyBytes,
        method: &str,
        url: &str,
        body: Vec<u8>,
    ) -> Bundle {
        Bundle::create(
            client,
            Destination::Device(*gw_x),
            gw_x,
            &Payload::HttpRequest {
                host: String::new(),
                method: method.into(),
                url: url.into(),
                headers: vec![],
                body,
                max_resp_bytes: 64_000,
            },
            BundleOpts::default(),
        )
        .unwrap()
    }

    #[test]
    fn fulfills_and_dedups_within_ttl() {
        let client = Identity::generate();
        let mut gw = Gateway::new(Identity::generate(), FakeHttp, AllowAll);
        let req = request(&client, &gw.address(), "GET", "https://example.com", vec![]);

        match gw.fulfill(&req, 1).unwrap() {
            FulfillOutcome::Response(resp) => {
                assert_eq!(resp.inner.dst, Destination::Device(client.address()));
                match resp.open(&client).unwrap() {
                    Payload::HttpResponse { status, body, .. } => {
                        assert_eq!(status, 200);
                        assert_eq!(body, b"hello from the internet");
                    }
                    _ => panic!("wrong payload"),
                }
            }
            _ => panic!("expected a response"),
        }

        // Duplicate within TTL is rejected...
        assert!(matches!(
            gw.fulfill(&req, 2).unwrap(),
            FulfillOutcome::Duplicate
        ));
        // ...but after the TTL elapses, the id is forgotten and it's served again.
        assert!(matches!(
            gw.fulfill(&req, 2 + GatewayConfig::default().dedup_ttl_ms)
                .unwrap(),
            FulfillOutcome::Response(_)
        ));
    }

    #[test]
    fn rate_limits_per_source() {
        let client = Identity::generate();
        let cfg = GatewayConfig {
            max_requests_per_window: 2,
            ..Default::default()
        };
        let mut gw = Gateway::with_config(Identity::generate(), FakeHttp, AllowAll, cfg);

        // Three distinct requests (different bodies → different ids) from one source.
        let r1 = request(&client, &gw.address(), "GET", "https://a.com", vec![1]);
        let r2 = request(&client, &gw.address(), "GET", "https://a.com", vec![2]);
        let r3 = request(&client, &gw.address(), "GET", "https://a.com", vec![3]);

        assert!(matches!(
            gw.fulfill(&r1, 0).unwrap(),
            FulfillOutcome::Response(_)
        ));
        assert!(matches!(
            gw.fulfill(&r2, 1).unwrap(),
            FulfillOutcome::Response(_)
        ));
        assert!(matches!(
            gw.fulfill(&r3, 2).unwrap(),
            FulfillOutcome::RateLimited
        ));
    }

    #[test]
    fn allowlist_policy_blocks_disallowed_requests() {
        let client = Identity::generate();
        let policy = Allowlist::new(&["GET"], &["example.com"], true);
        let mut gw = Gateway::new(Identity::generate(), FakeHttp, policy);
        let gx = gw.address();

        // Allowed: GET https to an allowed host (and a subdomain).
        assert!(matches!(
            gw.fulfill(
                &request(&client, &gx, "GET", "https://api.example.com/x", vec![]),
                0
            )
            .unwrap(),
            FulfillOutcome::Response(_)
        ));
        // Wrong method.
        assert!(matches!(
            gw.fulfill(
                &request(&client, &gx, "POST", "https://example.com", vec![]),
                1
            )
            .unwrap(),
            FulfillOutcome::PolicyDenied
        ));
        // Not https.
        assert!(matches!(
            gw.fulfill(
                &request(&client, &gx, "GET", "http://example.com", vec![]),
                2
            )
            .unwrap(),
            FulfillOutcome::PolicyDenied
        ));
        // Disallowed host.
        assert!(matches!(
            gw.fulfill(&request(&client, &gx, "GET", "https://evil.com", vec![]), 3)
                .unwrap(),
            FulfillOutcome::PolicyDenied
        ));
    }

    #[test]
    fn host_of_strips_userinfo_and_port() {
        // services-01: userinfo must not be mistaken for the host, or the allowlist is bypassable.
        assert_eq!(
            host_of("https://good.com:x@evil.com/path"),
            Some("evil.com")
        );
        assert_eq!(host_of("https://user:pass@evil.com"), Some("evil.com"));
        assert_eq!(host_of("https://example.com:443/x"), Some("example.com"));
        assert_eq!(host_of("https://example.com/a:b"), Some("example.com"));
        assert_eq!(host_of("https://[::1]:8443/x"), Some("[::1]"));
        assert_eq!(
            host_of("https://api.example.com?q=1"),
            Some("api.example.com")
        );
    }

    #[test]
    fn allowlist_is_not_bypassable_via_userinfo() {
        // services-01: a crafted userinfo URL whose real host is off-allowlist must be denied.
        let client = Identity::generate();
        let policy = Allowlist::new(&["GET"], &["example.com"], true);
        let mut gw = Gateway::new(Identity::generate(), FakeHttp, policy);
        let gx = gw.address();
        assert!(
            matches!(
                gw.fulfill(
                    &request(
                        &client,
                        &gx,
                        "GET",
                        "https://example.com:x@evil.com/",
                        vec![]
                    ),
                    0
                )
                .unwrap(),
                FulfillOutcome::PolicyDenied
            ),
            "userinfo trick must not smuggle an off-allowlist host past the policy"
        );
    }

    #[test]
    fn rejects_oversized_request_body() {
        let client = Identity::generate();
        let cfg = GatewayConfig {
            max_request_bytes: 16,
            ..Default::default()
        };
        let mut gw = Gateway::with_config(Identity::generate(), FakeHttp, AllowAll, cfg);
        let req = request(
            &client,
            &gw.address(),
            "GET",
            "https://example.com",
            vec![0u8; 17],
        );
        assert!(matches!(
            gw.fulfill(&req, 0).unwrap(),
            FulfillOutcome::RequestTooLarge
        ));
    }

    #[test]
    fn rate_map_does_not_grow_unbounded_across_sources() {
        // services-12: distinct sources whose activity has aged out must be dropped, not retained
        // forever. After the window elapses, an unrelated request prunes the stale source entry.
        let cfg = GatewayConfig {
            rate_window_ms: 100,
            ..Default::default()
        };
        let mut gw = Gateway::with_config(Identity::generate(), FakeHttp, AllowAll, cfg);
        let gx = gw.address();
        let s1 = Identity::generate();
        gw.fulfill(&request(&s1, &gx, "GET", "https://a.com", vec![1]), 0)
            .unwrap();
        assert_eq!(gw.rate.len(), 1);
        // A later request from a different source, past s1's window, prunes s1.
        let s2 = Identity::generate();
        gw.fulfill(&request(&s2, &gx, "GET", "https://a.com", vec![2]), 1_000)
            .unwrap();
        assert_eq!(gw.rate.len(), 1, "aged-out source dropped, not accumulated");
    }

    #[test]
    fn ignores_non_egress_bundles() {
        let client = Identity::generate();
        let gw_id = Identity::generate();
        let mut gw = Gateway::new(Identity::generate(), FakeHttp, AllowAll);
        // A device-to-device bundle, not an egress request.
        let b = Bundle::create(
            &client,
            Destination::Device(gw_id.address()),
            &gw_id.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: vec![],
            },
            BundleOpts::default(),
        )
        .unwrap();
        assert!(matches!(
            gw.fulfill(&b, 0).unwrap(),
            FulfillOutcome::NotForUs
        ));
    }

    // --- services-02: the `screen` seam the binary uses (node decodes + seals; gateway screens). ---

    #[test]
    fn screen_applies_all_abuse_controls() {
        let src = Identity::generate();
        let policy = Allowlist::new(&["GET"], &["example.com"], true);
        let cfg = GatewayConfig {
            max_requests_per_window: 2,
            max_request_bytes: 16,
            ..Default::default()
        };
        let mut gw = Gateway::with_config(Identity::generate(), FakeHttp, policy, cfg);
        let s = src.address();
        let id = |n: u8| {
            let mut b = [0u8; 32];
            b[0] = n;
            b
        };

        // Policy: wrong method / non-https / off-allowlist host are denied.
        assert_eq!(
            gw.screen(id(1), s, "POST", "https://example.com/", 0, 0),
            Screen::PolicyDenied
        );
        assert_eq!(
            gw.screen(id(2), s, "GET", "http://example.com/", 0, 0),
            Screen::PolicyDenied
        );
        assert_eq!(
            gw.screen(id(3), s, "GET", "https://evil.com/", 0, 0),
            Screen::PolicyDenied
        );
        // Size cap.
        assert_eq!(
            gw.screen(id(4), s, "GET", "https://example.com/", 17, 0),
            Screen::RequestTooLarge
        );
        // Allowed, and recorded: a duplicate id is then rejected.
        assert_eq!(
            gw.screen(id(5), s, "GET", "https://example.com/", 0, 0),
            Screen::Allow
        );
        assert_eq!(
            gw.screen(id(5), s, "GET", "https://example.com/", 0, 1),
            Screen::Duplicate
        );
        // Rate limit: budget is 2/window; id(5) counted as 1, this is 2 (ok), the next is shed.
        assert_eq!(
            gw.screen(id(6), s, "GET", "https://example.com/", 0, 2),
            Screen::Allow
        );
        assert_eq!(
            gw.screen(id(7), s, "GET", "https://example.com/", 0, 3),
            Screen::RateLimited
        );
    }

    #[test]
    fn forget_releases_dedup_so_a_503_shed_request_can_retry() {
        // services-r6-02: screen() records the id for dedup on Allow, but the binary may then shed the
        // request with a transient 503 at the in-flight fetch cap without performing it. forget() must
        // release the dedup entry so the client's retry of the SAME id is screened afresh (Allow), not
        // bounced as Duplicate. Without the fix, the second screen() below would return Duplicate.
        let src = Identity::generate();
        let policy = Allowlist::new(&["GET"], &["example.com"], true);
        let mut gw = Gateway::new(Identity::generate(), FakeHttp, policy);
        let s = src.address();
        let mut id = [0u8; 32];
        id[0] = 9;

        // First screen: Allowed and recorded for dedup.
        assert_eq!(
            gw.screen(id, s, "GET", "https://example.com/", 0, 0),
            Screen::Allow
        );
        // Simulate the binary shedding it with a 503 before the fetch: undo the dedup record.
        gw.forget(id);
        // The client's retry of the same id is now screened afresh, not a Duplicate.
        assert_eq!(
            gw.screen(id, s, "GET", "https://example.com/", 0, 1),
            Screen::Allow,
            "after forget(), a 503-shed request's retry is retryable, not Duplicate"
        );
        // And a genuine duplicate (no forget) is still deduped.
        assert_eq!(
            gw.screen(id, s, "GET", "https://example.com/", 0, 2),
            Screen::Duplicate
        );
    }

    #[test]
    fn screen_userinfo_host_is_not_bypassable() {
        // services-01 + services-02: the same host-parsing guard applies through the screen() seam.
        let src = Identity::generate();
        let policy = Allowlist::new(&["GET"], &["example.com"], true);
        let mut gw = Gateway::new(Identity::generate(), FakeHttp, policy);
        assert_eq!(
            gw.screen(
                [9u8; 32],
                src.address(),
                "GET",
                "https://example.com:x@evil.com/",
                0,
                0
            ),
            Screen::PolicyDenied,
            "userinfo trick must not smuggle an off-allowlist host past screen()"
        );
    }
}
