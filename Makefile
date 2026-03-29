BINARY := verify-cmp
MODULE  := patagia.dev/Patagia/argocd-verify-cmp

.PHONY: build test lint clean integration-test

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) ./cmd/verify-cmp/

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

integration-test: build
	bats test/integration/integration.bats
