FROM golang:1.24.7 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make build-nodeinit
FROM alpine:3.22
RUN apk --no-cache add ca-certificates kmod
COPY --from=builder /build/bin/octelium-nodeinit /app/
ENTRYPOINT ["/app/octelium-nodeinit"]
