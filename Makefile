VERSION ?= dev
MODULE := github.com/sv222/k8s-remediate-nis2
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)

.PHONY: build test vet fmt e2e policy-test

build:
	go build -ldflags "$(LDFLAGS)" -o bin/k8s-remediate-nis2 ./cmd/k8s-remediate-nis2

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

e2e:
	bash scripts/e2e.sh

policy-test:
	bash scripts/kyverno/check.sh
