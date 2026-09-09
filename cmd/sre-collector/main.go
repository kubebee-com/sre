// sre-collector reads only explicitly configured namespaces and sends typed,
// privacy-projected observations to an HTTPS control plane.
package main

import (
	"context"
	"errors"
	"flag"
	"github.com/kubebee-com/sre/pkg/agent/collection"
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
	cfg := collection.RuntimeConfig{}
	flags := flag.NewFlagSet("sre-collector", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.ControlPlane, "control-plane", "", "HTTPS control-plane origin")
	flags.StringVar(&cfg.Scope.OrganizationID, "organization-id", "", "organization ID")
	flags.StringVar(&cfg.Scope.ClusterID, "cluster-id", "", "cluster ID")
	flags.StringVar(&cfg.Scope.ApplicationID, "application-id", "", "application ID")
	flags.StringVar(&cfg.ExpectedClusterUID, "cluster-uid", "", "expected kube-system namespace UID")
	var namespaces, keyFile string
	flags.StringVar(&namespaces, "namespaces", "", "explicit comma-separated namespace allowlist")
	flags.StringVar(&keyFile, "identity-key-file", "", "private file containing exactly 32 raw key bytes")
	flags.StringVar(&cfg.RegistryDir, "registry-dir", "", "local encrypted registry directory")
	flags.StringVar(&cfg.CredentialFile, "credential-file", "", "credential file in separate private directory")
	flags.StringVar(&cfg.BootstrapFile, "bootstrap-file", "", "private bootstrap token file for initial enrollment")
	flags.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "explicit kubeconfig path")
	flags.BoolVar(&cfg.InCluster, "in-cluster", false, "use in-cluster Kubernetes credentials")
	if flags.Parse(args) != nil || flags.NArg() != 0 || namespaces == "" || keyFile == "" {
		return collection.ErrRuntime
	}
	cfg.Namespaces = strings.Split(namespaces, ",")
	st, err := os.Lstat(keyFile)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() != 32 {
		return collection.ErrRuntime
	}
	f, err := os.Open(keyFile)
	if err != nil {
		return collection.ErrRuntime
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(st, actual) {
		return collection.ErrRuntime
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return collection.ErrRuntime
	}
	defer clear(key)
	cfg.IdentityKey = key
	runtime, err := collection.NewRuntime(cfg)
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
