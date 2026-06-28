FROM node:24 AS builder-web

COPY cluster/wrdpgw/wrdpgw/web/package /build
ENV NODE_OPTIONS="--max-old-space-size=4096"
RUN cd /build && npm ci && npm run build

FROM golang:1.26.4 AS builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
COPY --from=builder-web /build/dist /build/cluster/wrdpgw/wrdpgw/web
RUN ls -la /build
RUN ls -la /build/cluster/wrdpgw/wrdpgw/web
RUN make build-wrdpgw
FROM alpine:3.23
RUN apk --no-cache add ca-certificates
RUN adduser -S -D -H -u 3454 -h /app octelium
USER octelium
EXPOSE 8080
COPY --from=builder /build/bin/octelium-wrdpgw /app/
ENTRYPOINT ["/app/octelium-wrdpgw"]

