.PHONY: build test vet tidy run lint clean docker proto proto-tools envtest envtest-bin fuzz

GO     ?= go
BIN    ?= bin
PKG    := ./...
IMAGE  ?= lightweightauth
TAG    ?= dev

# envtest binaries live under .envtest-bin/ (gitignored). The path
# printed by setup-envtest is exported as KUBEBUILDER_ASSETS for the
# envtest-tagged tests in tests/envtest/.
ENVTEST_BIN_DIR ?= .envtest-bin

build:
	$(GO) build -o $(BIN)/lwauth ./cmd/lwauth
	$(GO) build -o $(BIN)/lwauthctl ./cmd/lwauthctl

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

clean:
	rm -rf $(BIN)
