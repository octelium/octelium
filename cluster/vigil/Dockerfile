FROM golang:1.26.6-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential pkg-config libvectorscan-dev && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /build
ADD . /build/
WORKDIR /build
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
