BINARY_NAME ?= sre-agent
IMAGE_NAME ?= ghcr.io/kubebee-com/sre
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 'dev')
REVISION ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf 'unknown')
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE_TAG ?= $(VERSION)

.PHONY: all build test run version check check-docs check-manifests check-image-metadata check-helm kind-shell-test unified-runner-test ci-syntax-test kind-test docker-build docker-push clean

all: test build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -p 1 -trimpath -o bin/sre-orchestrator ./cmd/sre-orchestrator
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/kubebee-com/sre/pkg/buildinfo.Version=$(VERSION) -X github.com/kubebee-com/sre/pkg/buildinfo.Revision=$(REVISION) -X github.com/kubebee-com/sre/pkg/buildinfo.BuildDate=$(BUILD_DATE)" -o bin/$(BINARY_NAME) ./cmd/sre-agent

test:
	go test -v -race ./...

run: build
	./bin/sre-orchestrator

version: build
	./bin/$(BINARY_NAME) --version

check: check-docs check-manifests check-image-metadata check-helm unified-chart-test kind-shell-test unified-runner-test ci-syntax-test

check-docs:
	./scripts/ci/check-docs.sh

legacy-check: check-manifests check-image-metadata enterprise-chart-test

check-manifests:
	./scripts/ci/check-manifests.sh

check-image-metadata:
	./scripts/ci/check-image-metadata.sh

check-helm:
	./scripts/ci/check-helm.sh

kind-shell-test:
	bash -n scripts/ci/kind-fixtures.sh scripts/ci/kind-assertions.sh scripts/ci/kind-fixtures_test.sh scripts/ci/kind-integration.sh
	bash scripts/ci/kind-fixtures_test.sh

unified-runner-test:
	python3 scripts/ci/unified_kind_test.py
	bash scripts/ci/enterprise-postgres_test.sh

ci-syntax-test:
	@files="$$(git ls-files --cached --others --exclude-standard '*.go')"; test -z "$$(gofmt -l $$files)" || { printf 'gofmt required for:\n%s\n' "$$(gofmt -l $$files)"; exit 1; }
	@python3 -c 'import ast; from pathlib import Path; [ast.parse(path.read_text(), filename=str(path)) for path in sorted(Path("scripts/ci").glob("*.py"))]'
	@for file in scripts/ci/*.cjs; do node --check "$$file"; done
	@git diff --check
	@if git rev-parse --verify HEAD^ >/dev/null 2>&1; then git diff --check HEAD^; fi

kind-test:
	./scripts/ci/unified-kind.sh

docker-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) --build-arg BUILD_DATE=$(BUILD_DATE) -t $(IMAGE_NAME):$(IMAGE_TAG) -f deploy/Dockerfile .

docker-push:
	@test "$(IMAGE_TAG)" != "latest" || (echo "refusing to push floating latest tag" >&2; exit 1)
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

clean:
	rm -rf bin/

.PHONY: enterprise-build enterprise-test
enterprise-build:
	@mkdir -p bin/enterprise
	CGO_ENABLED=0 go build -trimpath -o bin/enterprise/ ./cmd/sre-orchestrator ./cmd/sre-agent ./cmd/sre-enterprise ./cmd/sre-evaluate

enterprise-test:
	./scripts/ci/enterprise-postgres.sh

.PHONY: enterprise-chart-test enterprise-kind-test
enterprise-chart-test:
	./scripts/ci/enterprise-chart.sh

enterprise-kind-test:
	./scripts/ci/unified-kind.sh

.PHONY: enterprise-evaluate enterprise-capacity-test
enterprise-evaluate:
	go run ./cmd/sre-evaluate --max-calls 26

enterprise-capacity-test:
	./scripts/ci/enterprise-capacity.sh

.PHONY: unified-chart-test
unified-chart-test:
	python3 scripts/ci/unified-chart_test.py

.PHONY: unified-kind-test
unified-kind-test: kind-test
