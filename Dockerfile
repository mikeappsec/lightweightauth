# syntax=docker/dockerfile:1.7
#
# Stock build using public images. Hardened-image support
# (dhi.io/golang, dhi.io/alpine) is deferred to a later milestone — see
# docs/DESIGN.md §7 (roadmap).

# ---- build stage -------------------------------------------------------------
# --platform=$BUILDPLATFORM pins this stage to the runner's own arch (amd64)
# regardless of which target platform is being assembled, so on a
# multi-platform build (linux/amd64,linux/arm64) this stage's expensive
# steps -- apk add, go mod download, go build -- run natively exactly once
# and are reused for both targets, instead of BuildKit running the whole
# stage a second time under QEMU emulation for arm64. Go cross-compiles the
# arm64 binary itself (GOARCH=$TARGETARCH below) with no emulation needed;
# only the tiny final runtime stage actually varies per target platform.
FROM --platform=$BUILDPLATFORM golang:1.26.2-alpine AS build

RUN apk add --no-cache ca-certificates git

WORKDIR /src

# Cache modules
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Build
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build,id=gobuild-${TARGETARCH} \
    go build -trimpath \
        -ldflags "-s -w \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Version=${VERSION} \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Commit=${COMMIT} \
          -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -o /out/lwauth     ./cmd/lwauth && \
    go build -trimpath \
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
