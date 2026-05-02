.PHONY: build test vet tidy run lint clean docker proto proto-tools envtest envtest-bin fuzz soak chaos vuln fips fips-test fips-verify docker-fips docs docs-serve docs-deps release-snapshot

GO     ?= go
BIN    ?= bin
PKG    := ./...
IMAGE  ?= lightweightauth
TAG    ?= dev

# K-CRYPTO-2 (Tier A5): the FIPS targets below build with the Go
# 1.24+ in-tree FIPS 140-3 module selected via GOFIPS140. The
# variable defaults to v1.0.0 (the first cert profile shipped with
# the toolchain); operators on a different cert revision override
# `make fips GOFIPS140_VER=vX.Y.Z`. Setting GOFIPS140 alone is
# sufficient — no GOEXPERIMENT or build tag is required on Go ≥ 1.24.
# CGO is not required (the FIPS module is in-tree pure Go).
GOFIPS140_VER ?= v1.0.0
LDFLAGS_VERSION ?= -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Version=$(TAG) \
                   -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) \
                   -X github.com/mikeappsec/lightweightauth/pkg/buildinfo.Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# envtest binaries live under .envtest-bin/ (gitignored). The path
# printed by setup-envtest is exported as KUBEBUILDER_ASSETS for the
# envtest-tagged tests in tests/envtest/.
ENVTEST_BIN_DIR ?= .envtest-bin

build:
	$(GO) build -trimpath -ldflags "-s -w $(LDFLAGS_VERSION)" -o $(BIN)/lwauth ./cmd/lwauth
	$(GO) build -trimpath -ldflags "-s -w $(LDFLAGS_VERSION)" -o $(BIN)/lwauthctl ./cmd/lwauthctl

test:
	$(GO) test $(PKG)

vet:
	$(GO) vet $(PKG)

tidy:
	$(GO) mod tidy

run: build
	$(BIN)/lwauth --config examples/config.yaml

lint: vet

# Install the proto code generation toolchain. All three are pure Go.
proto-tools:
	$(GO) install github.com/bufbuild/buf/cmd/buf@latest
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Regenerate Go bindings from api/proto/**/*.proto. Generated files are
# committed (DESIGN.md §1, Door B) so consumers don't need a toolchain.
proto:
	buf generate

docker:
	docker build -t $(IMAGE):$(TAG) .

# Download kube-apiserver + etcd binaries for envtest into ENVTEST_BIN_DIR.
# Idempotent; safe to re-run.
envtest-bin:
	$(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
	setup-envtest use --bin-dir $(ENVTEST_BIN_DIR) -p path

# Run the envtest-tagged e2e suite against a real apiserver.
envtest: envtest-bin
	$(GO) test -tags envtest ./tests/envtest/... -count=1 -timeout 120s

# Cycle each Fuzz* target for $(FUZZTIME) (default 30s). Go runs one
# fuzz target per invocation, so we drive them sequentially.
FUZZTIME ?= 30s
fuzz:
	$(GO) test ./pkg/identity/hmac/...  -fuzz=FuzzParseAuth  -fuzztime=$(FUZZTIME)
	$(GO) test ./pkg/identity/mtls/...  -fuzz=FuzzParseXFCC  -fuzztime=$(FUZZTIME)
	$(GO) test ./pkg/identity/dpop/...  -fuzz=FuzzMatchHTU   -fuzztime=$(FUZZTIME)

# Soak/load harness: drives synthetic traffic through Door A (HTTP) and Door B (gRPC)
# against an apikey + rbac + decision-cache config. Build-tag-gated so default
# `go test ./...` stays fast. Tunables: SOAK_RPS, SOAK_DURATION, SOAK_P99_MS, SOAK_WORKERS.
# CI default is 1k RPS for 10s; nightly should override SOAK_DURATION=30m SOAK_RPS=10000.
soak:
	$(GO) test -tags soak ./tests/soak/... -count=1 -timeout 120s

# Chaos: validates pkg/upstream resilience invariants under simulated
# upstream faults (500-storm, slow IdP, concurrent fan-out). Build-tag
# gated so default `go test ./...` stays fast.
chaos:
	$(GO) test -tags chaos ./tests/chaos/... -count=1 -timeout 60s

# Vulnerability scan via Go's official govulncheck. Pinned to the
# repo's Go toolchain so vendored stdlib paths resolve correctly.
vuln:
	GOTOOLCHAIN=go1.26.2 $(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# ---- K-CRYPTO-2 (Tier A5): FIPS 140-3 build mode ---------------------
#
# `make fips` produces lwauth + lwauthctl binaries that link against
# Go's in-tree FIPS 140-3 module. Operators verify the artifact via
# `make fips-verify` (asserts buildinfo.FIPSEnabled() at runtime) or
# by scraping `lwauth_fips_enabled` from the Prometheus surface.
#
# Outputs land under bin/fips/ to keep them isolated from the stock
# bin/ artifacts; mixing the two in a single image is a footgun (a
# release pipeline that pushes both must use distinct tags — see
# `make docker-fips` and Dockerfile.fips).
fips:
	mkdir -p $(BIN)/fips
	GOFIPS140=$(GOFIPS140_VER) $(GO) build -trimpath \
		-ldflags "-s -w $(LDFLAGS_VERSION)" \
		-o $(BIN)/fips/lwauth ./cmd/lwauth
	GOFIPS140=$(GOFIPS140_VER) $(GO) build -trimpath \
		-ldflags "-s -w $(LDFLAGS_VERSION)" \
		-o $(BIN)/fips/lwauthctl ./cmd/lwauthctl
	@echo "FIPS binaries written to $(BIN)/fips/. Verify with: make fips-verify"

# Run the full test suite under the FIPS module so a primitive that
# only differs in FIPS mode (e.g. an RSA key < 2048 bits, an MD5
# fallback) surfaces as a test failure, not a production incident.
fips-test:
	GOFIPS140=$(GOFIPS140_VER) $(GO) test -race -count=1 $(PKG)

# Probe a built FIPS binary at runtime. Asserts that
# buildinfo.FIPSEnabled() is true; exits non-zero otherwise. Wired
# into CI so a misconfigured matrix entry (GOFIPS140 unset, wrong
# toolchain, etc.) is caught at build time rather than at promotion.
fips-verify:
	@if [ ! -x $(BIN)/fips/lwauth ]; then \
		echo "missing $(BIN)/fips/lwauth; run 'make fips' first" >&2; exit 1; \
	fi
	$(BIN)/fips/lwauth --print-build-info | tee /dev/stderr | grep -q 'fips_enabled=true'

# Build a separately tagged FIPS image. Default tag is
# `lightweightauth:$(TAG)-fips`, chosen so a stock-image deploy that
# accidentally lands in a FIPS-only namespace fails the image-policy
# admission webhook (a registry-prefix or label match) rather than
# silently serving from the wrong crypto module.
docker-fips:
	docker build -f Dockerfile.fips \
		--build-arg VERSION=$(TAG) \
		--build-arg COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) \
		--build-arg GOFIPS140_VER=$(GOFIPS140_VER) \
		-t $(IMAGE):$(TAG)-fips .

# DOC-COOKBOOK-1 (Tier C1, v1.1): the cookbook + per-module reference
# under docs/ is rendered into a static site by mkdocs-material. The
# release pipeline runs `make docs`; contributors preview locally with
# `make docs-serve`. Both go through `make docs-deps` so the same
# pinned `docs/requirements.txt` is the single source of truth for
# tool versions — a floating mkdocs-material that breaks the nav at
# release time would be exactly the kind of "works on my machine"
# regression the strict build is meant to catch.
PYTHON ?= python

docs-deps:
	$(PYTHON) -m pip install --quiet --upgrade -r docs/requirements.txt

# Build matches what CI runs. `--strict` promotes every mkdocs warning
# to a build failure: an orphan page, a broken in-docs link, an unknown
# nav entry, an anchor typo. Source-tree references are absolute
# https://github.com/... URLs (rewritten in C1.6) so they resolve
# identically on the rendered site and on GitHub without the strict
# build flagging them.
docs: docs-deps
	$(PYTHON) -m mkdocs build --strict

# Live-reload preview. Binds to localhost only so a developer running
# this on a laptop on a hostile network does not accidentally publish
# the in-progress site to the LAN.
docs-serve: docs-deps
	$(PYTHON) -m mkdocs serve --dev-addr 127.0.0.1:8000

# F1 (RELEASE-1): local release dry-run. Builds all cross-platform
# archives without publishing. Useful to verify .goreleaser.yaml
# changes before pushing a tag.
release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf $(BIN) dist
