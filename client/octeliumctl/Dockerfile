
FROM golang:1.25.5 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make build-cli-octeliumctl

FROM alpine:3.23
RUN apk --no-cache add ca-certificates
ENV OCTELIUM_CONTAINER_MODE=true
COPY --from=builder /build/bin/octeliumctl /usr/bin/
ENTRYPOINT ["/usr/bin/octeliumctl"]