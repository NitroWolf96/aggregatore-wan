GO      ?= go
BIN     := bin
LDFLAGS := -s -w

.PHONY: all build build-arm64 test test-race test-integration fuzz bench lint docker clean

all: build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/treccia-client ./cmd/treccia-client
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/treccia-server ./cmd/treccia-server

build-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/treccia-client-arm64 ./cmd/treccia-client
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/treccia-server-arm64 ./cmd/treccia-server

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Integration tests need root for network namespaces: run with sudo.
test-integration: build
	$(GO) test -tags integration -count=1 -v ./test/...

fuzz:
	$(GO) test ./internal/wire -fuzz FuzzParseDataHeader -fuzztime 30s
	$(GO) test ./internal/wire -fuzz FuzzParseHeader -fuzztime 15s
	$(GO) test ./internal/wire -fuzz FuzzMACVerify -fuzztime 15s

bench:
	$(GO) test -bench . -benchmem -run '^$$' ./...

lint:
	$(GO) vet ./...
	gofmt -l . | tee /dev/stderr | wc -l | grep -q '^0$$'

docker:
	docker buildx build --platform linux/amd64,linux/arm64 -f deploy/docker/Dockerfile -t treccia:dev .

clean:
	rm -rf $(BIN) dist
