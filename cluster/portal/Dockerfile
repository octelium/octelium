FROM node:22 as builder-web

COPY cluster/portal/portal/web/package /build
RUN cd /build && npm install && npm run build

FROM golang:1.24.7 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
COPY --from=builder-web /build/dist /build/cluster/portal/portal/web
RUN ls -la /build
RUN ls -la /build/cluster/portal/portal/web
RUN make build-portal
FROM alpine:3.22
RUN apk --no-cache add ca-certificates
RUN adduser -S -D -H -u 3454 -h /app octelium
USER octelium
EXPOSE 8080
COPY --from=builder /build/bin/octelium-portal /app/
ENTRYPOINT ["/app/octelium-portal"]

