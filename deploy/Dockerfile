# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/bin/sre-agent ./cmd/sre-agent

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl tzdata && \
    adduser -D -u 10001 -g sre sre

USER 10001:10001
WORKDIR /home/sre

COPY --from=builder /app/bin/sre-agent /usr/local/bin/sre-agent

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/sre-agent"]
