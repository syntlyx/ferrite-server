# syntax=docker/dockerfile:1.7

ARG ALPINE_VERSION=3

FROM alpine:${ALPINE_VERSION}

LABEL org.opencontainers.image.title="ferrite" \
      org.opencontainers.image.description="A Rust DNS sinkhole and filtering API server" \
      org.opencontainers.image.source="https://github.com/syntlyx/ferrite-server" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates curl libcap su-exec tar tini && \
    addgroup -S -g 10001 ferrite && \
    adduser -S -D -u 10001 -G ferrite -h /var/lib/ferrite -s /sbin/nologin ferrite && \
    mkdir -p /etc/ferrite /var/lib/ferrite/bin /var/lib/ferrite/.local/share/ferrite && \
    ln -s /var/lib/ferrite/bin/ferrite /usr/local/bin/ferrite && \
    chown -R ferrite:ferrite /etc/ferrite /var/lib/ferrite

COPY docker/config.toml /etc/ferrite/config.toml
COPY docker/entrypoint.sh /usr/local/bin/ferrite-entrypoint

RUN chmod 0755 /usr/local/bin/ferrite-entrypoint && \
    chown ferrite:ferrite /etc/ferrite/config.toml

ENV HOME=/var/lib/ferrite \
    RUST_LOG=ferrite=info

VOLUME ["/var/lib/ferrite"]
# Docker exposes protocols separately; Ferrite still binds one DNS address.
EXPOSE 53/tcp 53/udp 80/tcp

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/ferrite-entrypoint"]
