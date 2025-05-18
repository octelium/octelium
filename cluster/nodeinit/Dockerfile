FROM golang:1.23.8 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make build-nodeinit
FROM alpine
RUN apk --no-cache add ca-certificates kmod
COPY --from=builder /build/bin/octelium-nodeinit /app/
ENTRYPOINT ["/app/octelium-nodeinit"]
