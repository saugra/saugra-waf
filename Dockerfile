# Multi-stage Dockerfile for Saugra WAF
FROM rust:1-slim-bookworm AS builder

WORKDIR /usr/src/saugra-waf

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY configs ./configs

# Build release binary
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary and configuration files
COPY --from=builder /usr/src/saugra-waf/target/release/saugra-waf /usr/local/bin/saugra-waf
COPY --from=builder /usr/src/saugra-waf/configs /app/configs

EXPOSE 8787

ENV SAUGRA_WAF_CONFIG=/app/configs/saugra-waf.example.yml

CMD ["saugra-waf", "run"]
