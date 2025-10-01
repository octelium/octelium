FROM node:22 as builder-web

COPY cluster/authserver/authserver/web/package /build
RUN cd /build && npm install && npm run build

FROM golang:1.24.7 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
COPY --from=builder-web /build/dist /build/cluster/authserver/authserver/web
RUN ls -la /build
RUN ls -la /build/cluster/authserver/authserver/web
RUN make build-authserver
FROM alpine:3.22
RUN apk --no-cache add ca-certificates
RUN adduser -S -D -H -u 3454 -h /app octelium
USER octelium
EXPOSE 8080
COPY --from=builder /build/bin/octelium-authserver /app/
ENTRYPOINT ["/app/octelium-authserver"]

