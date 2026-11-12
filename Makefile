VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo v1.0.0)
LDFLAGS := -s -w -X github.com/drau6/keydra/internal/buildinfo.Version=$(VERSION)

.PHONY: build test vet fmt install release docs clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/keydra ./cmd/keydra

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/keydra

# Regenerate the detector tables in README.md from the code
docs:
	./scripts/sync-readme.sh

# Cross-compile static binaries into dist/
release:
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/keydra-linux-amd64   ./cmd/keydra
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/keydra-linux-arm64   ./cmd/keydra
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/keydra-darwin-arm64  ./cmd/keydra
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/keydra-darwin-amd64  ./cmd/keydra
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/keydra-windows-amd64.exe ./cmd/keydra

clean:
	rm -rf bin dist
