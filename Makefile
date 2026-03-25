BINARY := verify-cmp
MODULE  := patagia.dev/Patagia/argocd-verify-cmp
IMAGE   ?= registry.internal.example.com/verify-cmp:dev

.PHONY: build test lint docker clean integration-test

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) ./cmd/verify-cmp/

test:
	go test ./...

lint:
	golangci-lint run ./...

docker:
	docker build -f deploy/Dockerfile -t $(IMAGE) .

clean:
	rm -rf bin/

integration-test: build
	test/integration/setup.sh
	bats test/integration/integration.bats; \
	  STATUS=$$?; \
	  test/integration/teardown.sh; \
	  exit $$STATUS
