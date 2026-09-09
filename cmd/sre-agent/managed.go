package main

import (
	"context"
	"fmt"
	"github.com/kubebee-com/sre/pkg/agent"
	"github.com/kubebee-com/sre/pkg/agent/bootstrap"
	"github.com/kubebee-com/sre/pkg/buildinfo"
	"os"
	"os/signal"
	"syscall"
)

func managedArgs(args []string) []string {
	if len(args) > 0 && args[0] == "--managed" {
		return args[1:]
	}
	return args
}

func main() {
	args := managedArgs(os.Args[1:])
	// The release image supplies this marker in its ENTRYPOINT. Keeping it
	// accepted by the executable also makes the managed mode explicit in local
	// invocations and prevents an image from accidentally selecting a legacy
	// command surface.
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version") {
		fmt.Println(buildinfo.String())
		return
	}
	if len(args) > 0 && (args[0] == "--help" || args[0] == "help" || args[0] == "-h") {
		fmt.Println("sre-agent [--managed] [run] --orchestrator HTTPS_URL --organization-id ID --cluster-id ID --application-id ID --cluster-uid UID --namespaces LIST --state-dir PATH --identity-key-file PATH (--in-cluster | --kubeconfig PATH) [--profiles IDS] [--execution-enabled] [--interactive --human-token-file PATH]\nsre-agent init --source-key PATH --source-bootstrap PATH --destination PATH\nKUBECONFIG (KUBE_CONFIG alias) selects external cluster access. Approval and UI are owned by sre-orchestrator.")
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	var err error
	if len(args) > 0 && args[0] == "init" {
		err = bootstrap.Run(args[1:])
	} else {
		err = agent.Run(ctx, args, os.Stdin, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
