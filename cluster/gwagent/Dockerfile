
FROM golang:1.23.8 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make build-gwagent

FROM alpine
RUN apk --no-cache add ca-certificates ipset iptables ip6tables
RUN adduser -S -D -H -u 3454 -h /app octelium
USER octelium
COPY --from=builder /build/bin/octelium-gwagent /app/
ENTRYPOINT ["/app/octelium-gwagent"]

