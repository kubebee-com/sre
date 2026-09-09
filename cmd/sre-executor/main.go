// sre-executor executes approved pod replacement in explicitly allowed namespaces.
package main

import (
	"context"
	"errors"
	"flag"
	"github.com/kubebee-com/sre/pkg/agent/executor"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run(args []string) error {
	cfg := executor.RuntimeConfig{}
	flags := flag.NewFlagSet("sre-executor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.ControlPlane, "control-plane", "", "HTTPS control-plane origin")
	flags.StringVar(&cfg.Scope.OrganizationID, "organization-id", "", "organization ID")
	flags.StringVar(&cfg.Scope.ClusterID, "cluster-id", "", "cluster ID")
	flags.StringVar(&cfg.Scope.ApplicationID, "application-id", "", "application ID")
	flags.StringVar(&cfg.ExpectedClusterUID, "cluster-uid", "", "expected kube-system namespace UID")
	var namespaces, protected, keyFile string
	flags.StringVar(&protected, "protected-namespaces", "", "additional comma-separated namespaces to deny")
	flags.StringVar(&namespaces, "namespaces", "", "explicit comma-separated namespace allowlist")
	flags.StringVar(&keyFile, "identity-key-file", "", "private file containing exactly 32 raw key bytes")
	flags.StringVar(&cfg.RegistryDir, "registry-dir", "", "read-only local encrypted registry directory")
	flags.StringVar(&cfg.CredentialFile, "credential-file", "", "credential file in separate private directory")
	flags.StringVar(&cfg.BootstrapFile, "bootstrap-file", "", "private bootstrap token file for initial enrollment")
	flags.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "explicit kubeconfig path")
	flags.BoolVar(&cfg.InCluster, "in-cluster", false, "use in-cluster Kubernetes credentials")
	if flags.Parse(args) != nil || flags.NArg() != 0 || namespaces == "" || keyFile == "" {
		return executor.ErrRuntime
	}
	cfg.Namespaces = strings.Split(namespaces, ",")
	if protected != "" {
		cfg.ProtectedNamespaces = strings.Split(protected, ",")
	}
	st, err := os.Lstat(keyFile)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() != 32 {
		return executor.ErrRuntime
	}
	f, err := os.Open(keyFile)
	if err != nil {
		return executor.ErrRuntime
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(st, actual) {
		return executor.ErrRuntime
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return executor.ErrRuntime
	}
	defer clear(key)
	cfg.IdentityKey = key
	runtime, err := executor.NewRuntime(cfg)
	if err != nil {
		return err
	}
	defer runtime.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err = runtime.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
