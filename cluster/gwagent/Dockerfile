
FROM golang:1.24.7 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make build-gwagent

FROM alpine:3.22
RUN apk --no-cache add ca-certificates ipset iptables ip6tables
RUN adduser -S -D -H -u 3454 -h /app octelium
RUN wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.38/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe
USER octelium
COPY --from=builder /build/bin/octelium-gwagent /app/
ENTRYPOINT ["/app/octelium-gwagent"]

