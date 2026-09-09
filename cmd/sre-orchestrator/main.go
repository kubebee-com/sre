// The orchestrator coordinates agents; it never constructs a Kubernetes client.
package main

import (
	"context"
	orchestratorruntime "github.com/kubebee-com/sre/pkg/orchestrator/runtime"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func run(ctx context.Context) error { return orchestratorruntime.Run(ctx) }
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil {
		log.Print("SRE orchestrator stopped: configuration or service unavailable")
		os.Exit(1)
	}
}
