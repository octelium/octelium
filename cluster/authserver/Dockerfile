FROM node:20 as builder-web
# RUN --mount=type=secret,id=private-repo-gen-sh \
#     cp /run/secrets/private-repo-gen-sh /tmp/private-repo-gen-sh && \
#     chmod 755 /tmp/private-repo-gen-sh && /tmp/private-repo-gen-sh || true

COPY cluster/authserver/authserver/web/package /build
RUN cd /build && npm install && npm run build

FROM golang:1.23.8 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
COPY --from=builder-web /build/dist /build/cluster/authserver/authserver/web
RUN ls -la /build
RUN ls -la /build/cluster/authserver/authserver/web
RUN make build-authserver
FROM alpine
RUN apk --no-cache add ca-certificates
RUN adduser -S -D -H -u 3454 -h /app octelium
USER octelium
EXPOSE 8080
COPY --from=builder /build/bin/octelium-authserver /app/
ENTRYPOINT ["/app/octelium-authserver"]

