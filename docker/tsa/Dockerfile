# Multi-stage build: compiles the `tsa` workspace member from source (a
# Cargo workspace needs every member's Cargo.toml present to resolve, so
# the whole `crates/` tree is copied in, not just `crates/tsa`), then
# ships only the resulting binary in a minimal runtime image.
FROM rust:1.80-bookworm AS builder
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
