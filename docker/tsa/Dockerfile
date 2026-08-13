# Multi-stage build: compiles the `tsa` workspace member from source (a
# Cargo workspace needs every member's Cargo.toml present to resolve, so
# the whole `crates/` tree is copied in, not just `crates/tsa`), then
# ships only the resulting binary in a minimal runtime image.
#
# Builder image is NOT the workspace's declared MSRV (1.80, see
# Cargo.toml) — resolving the workspace graph (required even to build
# just this one member) needs rustc 1.85+, because `wallet`'s git
# dependency `open-auth2-rs` declares `edition = "2024"` in its own
# Cargo.toml. That's a pre-existing MSRV/reality mismatch in the
# workspace, unrelated to `tsa`; masked outside Docker because dev
# machines typically have a much newer rustc than the declared MSRV.
# Flagged in ROADMAP.md rather than silently "fixed" here — CLAUDE.md
# marks MSRV as a decision not to change without consulting.
FROM rust:1.90-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p tsa

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/tsa /usr/local/bin/tsa
ENTRYPOINT ["tsa"]
# --host 0.0.0.0: see the doc comment on crates/tsa/src/serve.rs::run —
# a TSA is meant to be reachable by other processes, unlike wallet/portal
# serve, which never leave 127.0.0.1. --ca-dir /certs matches the
# `./data/ca:/certs:ro` volume docker-compose.yml already mounts.
CMD ["serve", "--host", "0.0.0.0", "--ca-dir", "/certs"]
