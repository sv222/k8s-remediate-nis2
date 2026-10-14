VERSION ?= dev
MODULE := github.com/sv222/k8s-remediate-nis2
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)
FUZZTIME ?= 20s

.PHONY: build test vet fmt e2e policy-test tf-check fuzz

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/k8s-remediate-nis2 ./cmd/k8s-remediate-nis2

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

e2e:
	bash scripts/e2e.sh

policy-test:
	bash scripts/kyverno/check.sh

tf-check:
	bash scripts/tfcheck.sh

fuzz:
	go test ./internal/prowler -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME) -parallel 2
	go test ./internal/kubebench -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME) -parallel 2
	go test ./internal/render -run '^$$' -fuzz '^FuzzRender$$' -fuzztime $(FUZZTIME) -parallel 2
	go test ./internal/render -run '^$$' -fuzz '^FuzzSanitizeResourceID$$' -fuzztime $(FUZZTIME) -parallel 2
	go test ./internal/out -run '^$$' -fuzz '^FuzzCell$$' -fuzztime $(FUZZTIME) -parallel 2
	go test ./internal/out -run '^$$' -fuzz '^FuzzCode$$' -fuzztime $(FUZZTIME) -parallel 2
	go test ./internal/out -run '^$$' -fuzz '^FuzzMappingTableKeepsItsShape$$' -fuzztime $(FUZZTIME) -parallel 2
