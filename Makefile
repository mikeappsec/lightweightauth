.PHONY: build test vet tidy run lint clean docker

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

docker:
	docker build -t $(IMAGE):$(TAG) .

clean:
	rm -rf $(BIN)
