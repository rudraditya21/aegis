# Builder
FROM rust:1.82-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p aegis

# Runtime
FROM debian:bookworm-slim
RUN useradd --system --create-home --uid 1000 aegis
WORKDIR /home/aegis

# Create config and log locations; keep config read-only by default.
RUN mkdir -p /config /var/log/aegis && chown -R aegis:aegis /var/log/aegis

COPY --from=builder /app/target/release/aegis /usr/local/bin/aegis

USER aegis
ENV AEGIS_CONFIG_ROOT=/config \
    AEGIS_CONFIG_READONLY=1 \
    FIREWALL_CONFIG_ROOT=/config \
    FIREWALL_CONFIG_READONLY=1

ENTRYPOINT ["aegis"]
