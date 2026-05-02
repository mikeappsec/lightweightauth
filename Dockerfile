# syntax=docker/dockerfile:1.7
#
# Stock build using public images. Hardened-image support
# (dhi.io/golang, dhi.io/alpine) is deferred to a later milestone — see
# docs/DESIGN.md §7 (roadmap).

# ---- build stage -------------------------------------------------------------
FROM golang:1.26.2-alpine AS build

RUN apk add --no-cache ca-certificates git

WORKDIR /src

# Cache modules
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ENV CGO_ENABLED=0 GOOS=linux

RUN go build -trimpath \
        -ldflags "-s -w \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Version=${VERSION} \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Commit=${COMMIT} \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -o /out/lwauth     ./cmd/lwauth \
 && go build -trimpath \
        -ldflags "-s -w \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Version=${VERSION} \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Commit=${COMMIT} \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -o /out/lwauthctl  ./cmd/lwauthctl

# ---- runtime stage -----------------------------------------------------------
FROM alpine:3.22.4

RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S lwauth \
 && adduser -S -G lwauth -u 10001 lwauth \
 && mkdir -p /etc/lwauth \
 && chown -R lwauth:lwauth /etc/lwauth

COPY --from=build /out/lwauth     /usr/local/bin/lwauth
COPY --from=build /out/lwauthctl  /usr/local/bin/lwauthctl
COPY examples/config.yaml         /etc/lwauth/config.yaml

USER lwauth
EXPOSE 8080 9001

ENTRYPOINT ["/usr/local/bin/lwauth"]
CMD ["--config=/etc/lwauth/config.yaml", "--http-addr=:8080"]
