FROM node:24 AS builder-web

COPY cluster/vigil/vigil/modes/webrdp/web/package /build
ENV NODE_OPTIONS="--max-old-space-size=4096"
RUN cd /build && npm ci && npm run build


FROM rust:1-bookworm AS builder-rust

WORKDIR /build
COPY cluster/vigil/vigil/modes/webrdp/credssp-rs/Cargo.toml /build/Cargo.toml
COPY cluster/vigil/vigil/modes/webrdp/credssp-rs/src /build/src
RUN cargo build --release


FROM golang:1.26.6-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential pkg-config ca-certificates libvectorscan-dev && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /build
ADD . /build/
WORKDIR /build

COPY --from=builder-web /build/dist /build/cluster/vigil/vigil/modes/webrdp/web

RUN mkdir -p /build/cluster/vigil/vigil/modes/webrdp/.libs
COPY --from=builder-rust /build/target/release/libwebrdp_credssp.a /build/cluster/vigil/vigil/modes/webrdp/.libs/libwebrdp_credssp.a
RUN test -f /build/cluster/vigil/vigil/modes/webrdp/.libs/libwebrdp_credssp.a

RUN make build-vigil

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libvectorscan5 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 3454 --home-dir /app --shell /usr/sbin/nologin octelium && \
    mkdir -p /app && \
    chown -R octelium:octelium /app

USER octelium

COPY --from=builder /build/bin/octelium-vigil /app/

ENTRYPOINT ["/app/octelium-vigil"]
