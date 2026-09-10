package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubebee-com/sre/internal/legacyagent"
	"github.com/kubebee-com/sre/pkg/agent"
	"github.com/kubebee-com/sre/pkg/agent/bootstrap"
	"github.com/kubebee-com/sre/pkg/buildinfo"
)

func managedArgs(args []string) []string {
	if len(args) > 0 && args[0] == "--managed" {
		return args[1:]
	}
	return args
}

func main() {
	isManaged := len(os.Args) > 1 && os.Args[1] == "--managed"
	args := managedArgs(os.Args[1:])
	// The release image supplies this marker in its ENTRYPOINT. Keeping it
	// accepted by the executable also makes the managed mode explicit in local
	// invocations and prevents an image from accidentally selecting a legacy
	// command surface when orchestrator flags are passed.
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version") {
		fmt.Println(buildinfo.String())
		return
	}
	if len(args) > 0 && (args[0] == "--help" || args[0] == "help" || args[0] == "-h") {
		if isManaged || len(args) > 1 {
			fmt.Println("sre-agent [--managed] [run] --orchestrator HTTPS_URL --organization-id ID --cluster-id ID --application-id ID --cluster-uid UID --namespaces LIST --state-dir PATH --identity-key-file PATH (--in-cluster | --kubeconfig PATH) [--profiles IDS] [--execution-enabled] [--interactive --human-token-file PATH]\nsre-agent init --source-key PATH --source-bootstrap PATH --destination PATH\nKUBECONFIG (KUBE_CONFIG alias) selects external cluster access. Approval and UI are owned by sre-orchestrator.")
			return
		}
	}
	if len(args) > 0 && args[0] == "init" {
		if err := bootstrap.Run(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// Managed agent mode requires either explicit args with an orchestrator flag
	// or SRE_ORCHESTRATOR_URL set in the environment.
	hasOrchestrator := os.Getenv("SRE_ORCHESTRATOR_URL") != ""
	for _, a := range args {
		if a == "--orchestrator" || a == "-orchestrator" || (len(a) > 15 && a[:15] == "--orchestrator=") {
			hasOrchestrator = true
			break
		}
	}

	if isManaged && hasOrchestrator {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		if err := agent.Run(ctx, args, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// Standalone in-cluster SRE agent service (HTTP/gRPC, healthz/readyz, scanner loop, dashboard)
	legacyagent.LegacyMain()
}
