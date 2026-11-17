# syntax=docker/dockerfile:1

# ─── Build ──────────────────────────────────────────────────────────────────
FROM rust:1.98-alpine AS builder

RUN apk add --no-cache build-base pkgconf

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY README.md ARCHITECTURE.md ./

RUN cargo build --release --locked

# ─── Runtime ────────────────────────────────────────────────────────────────
FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S meshvault \
    && adduser -S -G meshvault -h /var/lib/meshvault meshvault \
    && mkdir -p /etc/meshvault /var/lib/meshvault/import \
    && chown -R meshvault:meshvault /etc/meshvault /var/lib/meshvault

COPY --from=builder /build/target/release/meshvault /usr/local/bin/meshvault

# ProjectDirs resolves to /etc/meshvault/config.toml and
# /var/lib/meshvault for the repository/control socket.
ENV XDG_CONFIG_HOME=/etc \
    XDG_DATA_HOME=/var/lib \
    RUST_LOG=meshvault=info,reticulum_sdk=warn

USER meshvault
WORKDIR /var/lib/meshvault

# Repository: identity, blobs, manifests, partial downloads, control.sock.
VOLUME ["/var/lib/meshvault"]

# Reticulum TCP listener (when configured in /etc/meshvault/config.toml).
EXPOSE 4243

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD test -S /var/lib/meshvault/control.sock || exit 1

ENTRYPOINT ["meshvault"]
CMD ["daemon"]
