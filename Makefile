BINARY_NAME ?= sre-agent
IMAGE_NAME ?= ghcr.io/kubebee-com/sre
IMAGE_TAG ?= latest

.PHONY: all build test run docker-build docker-push clean

all: test build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/$(BINARY_NAME) ./cmd/sre-agent

test:
	go test -v -race ./...

run: build
	./bin/$(BINARY_NAME) -llm-provider rule-based -port 8080

docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) -f deploy/Dockerfile .

docker-push:
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

clean:
	rm -rf bin/
