package agent

import (
	"context"
	"errors"
	"fmt"
	"github.com/kubebee-com/sre/pkg/agent/collection"
	"github.com/kubebee-com/sre/pkg/agent/executor"
	"github.com/kubebee-com/sre/pkg/interaction"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Run never exposes a second HTTP server or approval authority.
func Run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	c, err := Parse(args)
	if err != nil {
		return err
	}
	key, err := readPrivate(c.KeyFile, 32)
	if err != nil || len(key) != 32 {
		return errors.New("private 32-byte identity key required")
	}
	defer clear(key)
	for _, dir := range []string{c.StateDir, filepath.Join(c.StateDir, "collector"), filepath.Join(c.StateDir, "executor")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return errors.New("private agent state unavailable")
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("agent state directories must be private (0700)")
		}
	}
	reg := filepath.Join(c.StateDir, "identities")
	reader, err := collection.NewRuntime(collection.RuntimeConfig{ControlPlane: c.Orchestrator, Scope: c.Scope, ExpectedClusterUID: c.ClusterUID, Namespaces: c.Namespaces, IdentityKey: key, RegistryDir: reg, CredentialFile: filepath.Join(c.StateDir, "collector", "credential"), BootstrapFile: c.CollectorBootstrap, Kubeconfig: c.Kubeconfig, InCluster: c.InCluster})
	if err != nil {
		return err
	}
	defer reader.Close()
	// Establish source identity before either diagnostics or execution uses it.
	if err := reader.Scan(ctx); err != nil {
		return err
	}
	workers := []loop{reader}
	if len(c.Profiles) > 0 {
		workers = append(workers, loopFunc(func(ctx context.Context) error { return reader.RunDiagnostics(ctx, c.Profiles, nil) }))
	}
	if c.Execution {
		writer, err := executor.NewRuntime(executor.RuntimeConfig{ControlPlane: c.Orchestrator, Scope: c.Scope, ExpectedClusterUID: c.ClusterUID, Namespaces: c.Namespaces, ProtectedNamespaces: c.ProtectedNamespaces, IdentityKey: key, RegistryDir: reg, CredentialFile: filepath.Join(c.StateDir, "executor", "credential"), BootstrapFile: c.ExecutorBootstrap, Kubeconfig: c.Kubeconfig, InCluster: c.InCluster})
		if err != nil {
			return err
		}
		defer writer.Close()
		workers = append(workers, writer)
	}
	if c.Interactive {
		human, err := readPrivate(c.HumanTokenFile, 16384)
		if err != nil {
			return errors.New("private human token file unavailable")
		}
		defer clear(human)
		workers = append(workers, loopFunc(func(ctx context.Context) error {
			return interaction.Run(ctx, interaction.ClientConfig{BaseURL: c.Orchestrator, Scope: c.Scope, HumanToken: strings.TrimSpace(string(human)), IncidentID: c.IncidentID, Input: input, Output: output})
		}))
	} else {
		fmt.Fprintln(output, "Agent connected; human requests are available through configured notifications and the orchestrator UI.")
	}
	return runLoops(ctx, workers)
}

func readPrivate(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, errors.New("private file required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("private file unavailable")
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("private file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("private file invalid")
	}
	return raw, nil
}
