FROM node:24 AS builder-web

COPY cluster/wrdpgw/wrdpgw/web/package /build
ENV NODE_OPTIONS="--max-old-space-size=4096"
RUN cd /build && npm ci && npm run build


FROM rust:1-bookworm AS builder-rust

WORKDIR /build
COPY cluster/wrdpgw/wrdpgw/credssp-rs/Cargo.toml /build/Cargo.toml
COPY cluster/wrdpgw/wrdpgw/credssp-rs/src /build/src
RUN cargo build --release


FROM golang:1.26.4-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential pkg-config ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /build
ADD . /build/
WORKDIR /build

COPY --from=builder-web /build/dist /build/cluster/wrdpgw/wrdpgw/web

RUN mkdir -p /build/cluster/wrdpgw/wrdpgw/.libs
COPY --from=builder-rust /build/target/release/libwrdpgw_credssp.a /build/cluster/wrdpgw/wrdpgw/.libs/libwrdpgw_credssp.a
RUN ls -la /build/cluster/wrdpgw/wrdpgw/.libs && \
    test -f /build/cluster/wrdpgw/wrdpgw/.libs/libwrdpgw_credssp.a

RUN make build-wrdpgw


FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 3454 --home-dir /app --shell /usr/sbin/nologin octelium && \
    mkdir -p /app && \
    chown -R octelium:octelium /app

USER octelium
EXPOSE 8080

COPY --from=builder /build/bin/octelium-wrdpgw /app/

ENTRYPOINT ["/app/octelium-wrdpgw"]