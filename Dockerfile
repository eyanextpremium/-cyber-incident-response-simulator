# ==============================================================================
# Multi-Stage Dockerfile for Cyber Incident Response Simulator
# ==============================================================================

# --- Stage 1: Build & Compile ---
FROM rust:1.80-slim-bullseye AS builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy cargo manifest
COPY Cargo.toml Cargo.lock ./

# Copy source code and asset definitions
COPY src ./src
COPY tests ./tests

# Build release binary
RUN cargo build --release --bin cyber-incident-simulator

# --- Stage 2: Runtime Environment ---
FROM debian:bullseye-slim

WORKDIR /app

# Install minimal runtime certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root unprivileged service account
RUN groupadd -g 10001 simuser && \
    useradd -u 10000 -g simuser -s /bin/sh -m simuser

# Copy compiled binary from builder
COPY --from=builder /usr/src/app/target/release/cyber-incident-simulator /usr/local/bin/cyber-incident-simulator

# Copy static assets, configuration and scenarios
COPY fronted ./fronted
COPY scenarios ./scenarios
COPY config ./config
COPY data ./data

# Ensure data directory permissions
RUN mkdir -p /app/data /app/logs && chown -R simuser:simuser /app

# Switch to non-root user
USER simuser

# Environment defaults
ENV RUST_LOG=info
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080
ENV STATIC_DIR=fronted

# Expose HTTP dashboard and UDP Syslog listener
EXPOSE 8080/tcp
EXPOSE 5140/udp

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/api/health || exit 1

# Launch application
CMD ["cyber-incident-simulator"]
