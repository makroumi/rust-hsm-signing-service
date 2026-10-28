# syntax=docker/dockerfile:1.7
############################
# Stage 1 — build
############################
FROM rust:1.82-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev clang && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Prime the dep cache
COPY Cargo.toml Cargo.lock* ./
COPY crates/hsm-core/Cargo.toml crates/hsm-core/Cargo.toml
COPY crates/hsm-mock/Cargo.toml crates/hsm-mock/Cargo.toml
COPY crates/hsm-pkcs11/Cargo.toml crates/hsm-pkcs11/Cargo.toml
COPY crates/signing-service/Cargo.toml crates/signing-service/Cargo.toml
COPY crates/load-test/Cargo.toml crates/load-test/Cargo.toml
RUN mkdir -p crates/hsm-core/src crates/hsm-mock/src crates/hsm-pkcs11/src \
    crates/signing-service/src crates/load-test/src && \
    echo "fn main(){}" > crates/signing-service/src/main.rs && \
    echo "fn main(){}" > crates/load-test/src/main.rs && \
    touch crates/hsm-core/src/lib.rs crates/hsm-mock/src/lib.rs \
          crates/hsm-pkcs11/src/lib.rs crates/signing-service/src/lib.rs && \
    cargo build --release --bin signing-service || true

# Real sources
COPY crates ./crates
RUN cargo build --release --bin signing-service

############################
# Stage 2 — runtime
############################
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 opensc ca-certificates tini && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r app && useradd -r -g app -s /usr/sbin/nologin app

COPY --from=builder /src/target/release/signing-service /usr/local/bin/signing-service
COPY scripts/init-softhsm.sh /usr/local/bin/init-softhsm.sh
COPY scripts/provision-keys.sh /usr/local/bin/provision-keys.sh
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/*.sh && \
    mkdir -p /var/lib/softhsm/tokens && chown -R app:app /var/lib/softhsm

USER app
ENV TOKEN_DIR=/var/lib/softhsm/tokens \
    USER_PIN=1234 \
    SO_PIN=12345678 \
    LABEL=arkion-dev \
    RUST_LOG=info,signing_service=debug

EXPOSE 8080 9100
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/entrypoint.sh"]
