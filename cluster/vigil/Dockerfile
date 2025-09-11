
FROM golang:1.24.7 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make build-vigil
FROM alpine:3.22
RUN apk --no-cache add ca-certificates curl go
RUN adduser -S -D -H -u 3454 -h /app octelium
USER octelium
COPY --from=builder /build/bin/octelium-vigil /app/
ENTRYPOINT ["/app/octelium-vigil"]
