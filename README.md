<p align="center">
  <img alt="Hop" src="https://hopme.sh/hop-mark.svg" width="200">
</p>

<h1 align="center">hop-gateway</h1>

<p align="center">
  <b>A policy-gated internet-egress node: let mesh clients reach the public web through an allowlist you control.</b><br>
  One routable Hop leaf whose only job is to fulfill HTTP requests, safely.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-stable-CE422B" alt="Rust">
  <img src="https://img.shields.io/badge/deploy-Cloud%20Run%20%C2%B7%20Docker-1f6feb" alt="Cloud Run · Docker">
  <img src="https://img.shields.io/badge/license-Apache--2.0-3ddc84" alt="license Apache-2.0">
</p>

---

Hop is a **delay-tolerant, end-to-end-encrypted mesh**: messages hop device to device over BLE, Wi-Fi,
and the internet until they reach the person or service you meant. Held, never dropped.

**hop-gateway is the internet-egress role.** It's a routable Hop leaf (it dials a relay and is reachable
by its address) whose only job is to fulfill `HttpRequest` bundles addressed to it: a client seals a
request to the gateway's key, the gateway performs it (subject to an allowlist, per-source rate limits,
dedup, and size caps), and seals the response back to the origin device. Unlike an endpoint (bound to
one origin), a gateway is general egress, so ship it with a tight allowlist: `--allow-host` is required
and there is no default-open policy.

## Run it

```sh
hop-gateway \
  --relay wss://relay.hopme.sh/ \
  --identity-file /etc/hop/identity \
  --allow-host example.com --allow-host api.example.com \
  --allow-method GET --allow-method POST \
  --healthz 0.0.0.0:8080 \
  --print-address
```

Full flags:

```
hop-gateway --relay wss://relay.hopme.sh/ --identity-file PATH \
            --allow-host example.com [--allow-host …] \
            [--allow-method GET] [--allow-insecure] \
            [--max-resp BYTES] [--healthz 0.0.0.0:8080] [--print-address]
```

`--allow-host` is required. With no `--allow-method` the policy permits `GET` only. `--allow-insecure`
drops the https-only requirement (dev only).

## Sealed both ways

A request is sealed to the gateway's well-known key; the response is sealed back to the origin's key.
The gateway sees plaintext only for the hosts you allow, and only for the moment it performs the fetch;
it is never a conduit for anything else on the mesh.

## Abuse controls

General egress is a standing target, so the gateway gates every request:

- **Allowlist.** Host and method are checked against your `--allow-host` / `--allow-method` policy;
  there is no default-open path.
- **Rate limiting and dedup.** Per-source rate limits plus TTL-bounded request dedup.
- **Size and concurrency caps.** Request and streamed-response bodies are capped (`--max-resp`), and
  concurrent backend fetches are bounded so a burst can't exhaust threads or memory (excess sheds 503).
- **No off-policy fetches.** https-only unless `--allow-insecure`, and redirects are disabled so a
  backend can't bounce the fetch to a host outside the allowlist.

The abuse controls live in the library and are unit-tested without a network; the binary owns transport
(the relay dial) and lets the node do the sealing and routing.

## Configure

| Env / flag          | Purpose                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `PORT`              | Cloud Run's serving port; the `/healthz` probe binds here        |
| `HOP_IDENTITY_FILE` | path to the 32-byte identity seed, for a stable address          |
| `HOP_RELAY`         | relay URL to dial (overrides the default when no CLI flag is set) |
| `HOP_NO_RELAY`      | set to `1`/`true`/`yes` to run without a relay (graceful degrade) |
| `--max-resp BYTES`  | cap on the backend response size sealed back to the client       |

## Status

Prototype. The egress role (unseal, screen against the policy, perform with the production HTTP client,
reseal to the origin) and every abuse control above are built and unit-tested. Run it on Cloud Run or
any container host as a routable leaf that dials the relay fleet.

## The Hop family

Hop is one protocol with many faces. The endpoint SDKs, same surface in your language:
[node](https://github.com/hopmesh/hop-sdk-node) ·
[python](https://github.com/hopmesh/hop-sdk-python) ·
[go](https://github.com/hopmesh/hop-sdk-go) ·
[ruby](https://github.com/hopmesh/hop-sdk-ruby) ·
[crystal](https://github.com/hopmesh/hop-sdk-crystal) ·
[elixir](https://github.com/hopmesh/hop-sdk-elixir) ·
[apple](https://github.com/hopmesh/hop-sdk-apple) ·
[android](https://github.com/hopmesh/hop-sdk-android).
The protocol core is [hop-core](https://github.com/hopmesh/hop-core) / [libhop](https://github.com/hopmesh/libhop).

## License

[Apache-2.0](./LICENSE.md), use it freely. Only the protocol core (`hop-core`) is FSL-1.1-ALv2,
source-available and converting to Apache-2.0 after two years.
