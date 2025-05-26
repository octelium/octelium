
FROM golang:1.23.8 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make build-cli-octops

FROM alpine
RUN apk --no-cache add ca-certificates
ENV OCTELIUM_CONTAINER_MODE=true
COPY --from=builder /build/bin/octops /usr/bin/
ENTRYPOINT ["/usr/bin/octops"]