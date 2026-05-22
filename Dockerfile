# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.88
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS build

WORKDIR /usr/src/ferrite

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/usr/src/ferrite/target,sharing=locked \
    cargo build --release --all-features --locked && \
    cp target/release/ferrite /tmp/ferrite

FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="ferrite" \
      org.opencontainers.image.description="A Rust DNS sinkhole and filtering API server" \
      org.opencontainers.image.source="https://github.com/syntlyx/ferrite-server" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates gosu libcap2-bin tini && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 ferrite && \
    useradd --system --uid 10001 --gid ferrite \
      --home-dir /var/lib/ferrite --create-home \
      --shell /usr/sbin/nologin ferrite && \
    mkdir -p /etc/ferrite /var/lib/ferrite/.local/share/ferrite && \
    chown -R ferrite:ferrite /etc/ferrite /var/lib/ferrite

COPY --from=build /tmp/ferrite /usr/local/bin/ferrite
COPY docker/config.toml /etc/ferrite/config.toml
COPY docker/entrypoint.sh /usr/local/bin/ferrite-entrypoint

RUN chmod 0755 /usr/local/bin/ferrite && \
    chmod 0755 /usr/local/bin/ferrite-entrypoint && \
    setcap cap_net_bind_service=+ep /usr/local/bin/ferrite && \
    chown ferrite:ferrite /etc/ferrite/config.toml

ENV HOME=/var/lib/ferrite \
    RUST_LOG=ferrite=info

VOLUME ["/var/lib/ferrite"]
EXPOSE 53/tcp 53/udp 80/tcp

ENTRYPOINT ["/usr/local/bin/ferrite-entrypoint"]
