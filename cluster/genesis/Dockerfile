FROM golang:1.24.7 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make build-genesis
FROM alpine:3.22
RUN apk --no-cache add ca-certificates bash curl openssl
# RUN apk del bash curl openssl
RUN adduser -S -D -h /app octelium
# RUN chown octelium /app
USER octelium
COPY --from=builder /build/bin/octelium-genesis /app/
ENTRYPOINT ["/app/octelium-genesis"]
