# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83
ARG RUNTIME_IMAGE=cgr.dev/chainguard/static@sha256:f51c2493951313c3ad4069080b2814ffb6ed6fe3909dabeb84a9482f42d5600b

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder

ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown

WORKDIR /app

RUN apk add --no-cache ca-certificates git tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-$(go env GOARCH)} go build \
    -trimpath \
    -ldflags="-s -w -X github.com/kubebee-com/sre/pkg/buildinfo.Version=${VERSION} -X github.com/kubebee-com/sre/pkg/buildinfo.Revision=${REVISION} -X github.com/kubebee-com/sre/pkg/buildinfo.BuildDate=${BUILD_DATE}" \
    -o /app/bin/sre-agent ./cmd/sre-agent

FROM ${RUNTIME_IMAGE} AS runtime

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="KubeBee SRE Agent" \
      org.opencontainers.image.description="Authenticated Kubernetes SRE diagnostics and approval-gated remediation" \
      org.opencontainers.image.source="https://github.com/kubebee-com/sre" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /home/nonroot
USER 65532:65532

COPY --from=builder /app/bin/sre-agent /usr/local/bin/sre-agent

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/sre-agent"]
