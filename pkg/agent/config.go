// Package agent runs collection, diagnosis and optional approved execution in one
// process. Kubernetes credential location does not change its authority model.
package agent

import (
	"errors"
	"flag"
	"github.com/kubebee-com/sre/pkg/identity"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var ErrConfig = errors.New("agent requires HTTPS orchestrator, explicit scope/cluster, namespaces, private state and exactly one Kubernetes credential source")

type Config struct {
	Profiles                              []string
	Orchestrator                          string
	Scope                                 identity.Scope
	ClusterUID                            string
	Namespaces, ProtectedNamespaces       []string
	StateDir, KeyFile, Kubeconfig         string
	CollectorBootstrap, ExecutorBootstrap string
	InCluster, Execution, Interactive     bool
	HumanTokenFile, IncidentID            string
}

func Parse(args []string) (Config, error) {
	c := Config{}
	f := flag.NewFlagSet("sre-agent", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	namespaces, protected, profiles := "", "kube-system,kube-public,kube-node-lease", ""
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBE_CONFIG")
	}
	f.StringVar(&c.Orchestrator, "orchestrator", os.Getenv("SRE_ORCHESTRATOR_URL"), "HTTPS orchestrator origin")
	f.StringVar(&c.Scope.OrganizationID, "organization-id", "", "organization ID")
	f.StringVar(&c.Scope.ClusterID, "cluster-id", "", "cluster ID")
	f.StringVar(&c.Scope.ApplicationID, "application-id", "", "application ID")
	f.StringVar(&c.ClusterUID, "cluster-uid", "", "verified kube-system namespace UID")
	f.StringVar(&profiles, "profiles", "", "approved provider profile IDs enabled on this agent")
	f.StringVar(&namespaces, "namespaces", "", "explicit namespace allowlist")
	f.StringVar(&protected, "protected-namespaces", protected, "namespaces protected from execution")
	f.StringVar(&c.StateDir, "state-dir", "", "persistent private agent directory")
	f.StringVar(&c.KeyFile, "identity-key-file", "", "private 32-byte identity key file")
	f.StringVar(&c.CollectorBootstrap, "collector-bootstrap-file", "", "initial collector enrollment token file")
	f.StringVar(&c.ExecutorBootstrap, "executor-bootstrap-file", "", "initial executor enrollment token file")
	f.StringVar(&c.Kubeconfig, "kubeconfig", kubeconfig, "external kubeconfig path")
	f.BoolVar(&c.InCluster, "in-cluster", false, "use ServiceAccount credentials")
	f.BoolVar(&c.Execution, "execution-enabled", false, "enable approved execution capability")
	f.BoolVar(&c.Interactive, "interactive", false, "interact through the terminal")
	f.StringVar(&c.HumanTokenFile, "human-token-file", "", "private human OIDC token file")
	f.StringVar(&c.IncidentID, "incident-id", "", "optional interactive incident filter")
	if len(args) > 0 && (args[0] == "serve" || args[0] == "run") {
		args = args[1:]
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return c, ErrConfig
	}
	u, err := url.Parse(c.Orchestrator)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || c.Scope.Validate() != nil || !identity.ValidID(c.ClusterUID) || namespaces == "" || c.StateDir == "" || c.KeyFile == "" || c.InCluster == (c.Kubeconfig != "") {
		return c, ErrConfig
	}
	c.Namespaces = strings.Split(namespaces, ",")
	if profiles != "" {
		c.Profiles = strings.Split(profiles, ",")
	}
	c.ProtectedNamespaces = strings.Split(protected, ",")
	if c.Interactive {
		if c.HumanTokenFile == "" {
			return c, errors.New("interactive mode requires --human-token-file with human OIDC identity")
		}
		human, _ := filepath.Abs(c.HumanTokenFile)
		for _, other := range []string{filepath.Join(c.StateDir, "collector", "credential"), filepath.Join(c.StateDir, "executor", "credential"), c.KeyFile, c.CollectorBootstrap, c.ExecutorBootstrap} {
			if other == "" {
				continue
			}
			path, _ := filepath.Abs(other)
			if path == human {
				return c, errors.New("human identity must be separate from agent credentials")
			}
		}
	}
	return c, nil
}
