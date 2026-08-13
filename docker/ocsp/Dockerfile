# Multi-stage build: compiles the `ocsp` workspace member from source (a
# Cargo workspace needs every member's Cargo.toml present to resolve, so
# the whole `crates/` tree is copied in, not just `crates/ocsp`), then
# ships only the resulting binary in a minimal runtime image.
FROM rust:1.80-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p ocsp

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/ocsp /usr/local/bin/ocsp
ENTRYPOINT ["ocsp"]
# --host 0.0.0.0: see the doc comment on crates/ocsp/src/serve.rs::run —
# an OCSP responder is meant to be reachable by other processes, unlike
# wallet/portal serve, which never leave 127.0.0.1. --ca-dir /certs
# matches the `./data/ca:/certs:ro` volume docker-compose.yml already
# mounts.
CMD ["serve", "--host", "0.0.0.0", "--ca-dir", "/certs"]
