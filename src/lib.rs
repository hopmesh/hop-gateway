//! # hop-gateway
//!
//! The internet-egress role (DESIGN.md §9). A gateway unseals an `HttpRequest`
//! bundle, performs the request (subject to policy + abuse controls), and seals an
//! `HttpResponse` back to the origin device key (approach (c): request sealed to a
//! well-known gateway key, response sealed to the origin's `src_x`).
//!
//! The HTTP client is injected via [`HttpClient`] so fulfillment logic is testable
//! without a network; a `tokio` + `reqwest` impl is the production backend.
//!
//! Abuse controls (DESIGN.md §9): TTL-bounded request dedup, per-source rate
//! limiting, an allowlist [`EgressPolicy`], and request/response size caps.

use std::collections::HashMap;

use hop_core::prelude::*;

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

/// Extract the host (no scheme, no port, no path) from a URL.
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split("://").nth(1)?;
    rest.split(['/', '?', ':']).next().filter(|h| !h.is_empty())
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
            dedup_ttl_ms: 600_000,         // 10 min
            max_requests_per_window: 60,
            rate_window_ms: 60_000,        // 1 min
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
        if !matches!(request.inner.dst, Destination::InternetEgress) {
            return Ok(FulfillOutcome::NotForUs);
        }
        request.verify()?;

        // Dedup within the TTL window (DESIGN.md §7) — pruned to bound memory.
        let ttl = self.config.dedup_ttl_ms;
        self.fulfilled.retain(|_, &mut t| now_ms.saturating_sub(t) < ttl);
        if self.fulfilled.contains_key(&request.id()) {
            return Ok(FulfillOutcome::Duplicate);
        }

        let Payload::HttpRequest { method, url, headers, body, max_resp_bytes, .. } =
            request.open(&self.identity)?
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

        let result = self.client.perform(HttpCall { method, url, headers, body, max_resp_bytes });

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
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn request(client: &Identity, gw_x: &PubKeyBytes, method: &str, url: &str, body: Vec<u8>) -> Bundle {
        Bundle::create(
            client,
            Destination::InternetEgress,
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
        assert!(matches!(gw.fulfill(&req, 2).unwrap(), FulfillOutcome::Duplicate));
        // ...but after the TTL elapses, the id is forgotten and it's served again.
        assert!(matches!(
            gw.fulfill(&req, 2 + GatewayConfig::default().dedup_ttl_ms).unwrap(),
            FulfillOutcome::Response(_)
        ));
    }

    #[test]
    fn rate_limits_per_source() {
        let client = Identity::generate();
        let cfg = GatewayConfig { max_requests_per_window: 2, ..Default::default() };
        let mut gw = Gateway::with_config(Identity::generate(), FakeHttp, AllowAll, cfg);

        // Three distinct requests (different bodies → different ids) from one source.
        let r1 = request(&client, &gw.address(), "GET", "https://a.com", vec![1]);
        let r2 = request(&client, &gw.address(), "GET", "https://a.com", vec![2]);
        let r3 = request(&client, &gw.address(), "GET", "https://a.com", vec![3]);

        assert!(matches!(gw.fulfill(&r1, 0).unwrap(), FulfillOutcome::Response(_)));
        assert!(matches!(gw.fulfill(&r2, 1).unwrap(), FulfillOutcome::Response(_)));
        assert!(matches!(gw.fulfill(&r3, 2).unwrap(), FulfillOutcome::RateLimited));
    }

    #[test]
    fn allowlist_policy_blocks_disallowed_requests() {
        let client = Identity::generate();
        let policy = Allowlist::new(&["GET"], &["example.com"], true);
        let mut gw = Gateway::new(Identity::generate(), FakeHttp, policy);
        let gx = gw.address();

        // Allowed: GET https to an allowed host (and a subdomain).
        assert!(matches!(
            gw.fulfill(&request(&client, &gx, "GET", "https://api.example.com/x", vec![]), 0).unwrap(),
            FulfillOutcome::Response(_)
        ));
        // Wrong method.
        assert!(matches!(
            gw.fulfill(&request(&client, &gx, "POST", "https://example.com", vec![]), 1).unwrap(),
            FulfillOutcome::PolicyDenied
        ));
        // Not https.
        assert!(matches!(
            gw.fulfill(&request(&client, &gx, "GET", "http://example.com", vec![]), 2).unwrap(),
            FulfillOutcome::PolicyDenied
        ));
        // Disallowed host.
        assert!(matches!(
            gw.fulfill(&request(&client, &gx, "GET", "https://evil.com", vec![]), 3).unwrap(),
            FulfillOutcome::PolicyDenied
        ));
    }

    #[test]
    fn rejects_oversized_request_body() {
        let client = Identity::generate();
        let cfg = GatewayConfig { max_request_bytes: 16, ..Default::default() };
        let mut gw = Gateway::with_config(Identity::generate(), FakeHttp, AllowAll, cfg);
        let req = request(&client, &gw.address(), "GET", "https://example.com", vec![0u8; 17]);
        assert!(matches!(gw.fulfill(&req, 0).unwrap(), FulfillOutcome::RequestTooLarge));
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
            &Payload::PeerMessage { content_type: "t".into(), body: vec![] },
            BundleOpts::default(),
        )
        .unwrap();
        assert!(matches!(gw.fulfill(&b, 0).unwrap(), FulfillOutcome::NotForUs));
    }
}
