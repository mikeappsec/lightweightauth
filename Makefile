.PHONY: build test vet tidy run lint clean docker proto proto-tools

GO     ?= go
BIN    ?= bin
PKG    := ./...
IMAGE  ?= lightweightauth
TAG    ?= dev

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

clean:
	rm -rf $(BIN)
