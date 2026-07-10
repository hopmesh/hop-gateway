# Container image for a Hop internet-egress gateway (DESIGN.md §9, services-02). Built with the
# `reqwest` feature so it ships the production HTTP client + the relay-dial WebSocket bearer. Runs a
# /healthz probe on Cloud Run's $PORT and dials the mesh as a routable leaf.
#
# Build context is the repo root:
#   docker build -f services/hop-gateway/Dockerfile -t hop-gateway .
#
# Ship it with a TIGHT allowlist: --allow-host is REQUIRED (no default-open policy). Pass the
# allowlist + relay via HOP_ALLOW_HOSTS / HOP_RELAY (or bake explicit --allow-host flags into CMD).

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY services ./services
COPY examples ./examples
RUN cargo build --release -p hop-gateway --features reqwest

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/hop-gateway /usr/local/bin/hop-gateway

# Cloud Run sets $PORT; the gateway serves its /healthz probe there. HOP_RELAY / HOP_NO_RELAY gate
# the relay dial (graceful-degrade when the fleet is off, services-11). Override CMD to supply the
# REQUIRED --allow-host allowlist for your deployment. Shell form so $PORT expands.
ENV PORT=8080
CMD hop-gateway \
      --healthz 0.0.0.0:${PORT} \
      --identity-file ${HOP_IDENTITY_FILE}
