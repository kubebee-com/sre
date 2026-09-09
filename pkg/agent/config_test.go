package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func configArgs() []string {
	return []string{"--orchestrator=https://sre.example.com", "--organization-id=o", "--cluster-id=c", "--application-id=a", "--cluster-uid=uid", "--namespaces=work", "--state-dir=/tmp/agent", "--identity-key-file=/tmp/key"}
}
func TestCredentialSourcesAndCapabilityDefaults(t *testing.T) {
	t.Setenv("KUBECONFIG", "/tmp/context")
	c, err := Parse(configArgs())
	if err != nil || c.Kubeconfig != "/tmp/context" || c.Execution || c.Interactive {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	c, err = Parse(append(configArgs(), "--kubeconfig=/tmp/explicit"))
	if err != nil || c.Kubeconfig != "/tmp/explicit" {
		t.Fatal("flag precedence", err)
	}
	if _, err = Parse(append(configArgs(), "--in-cluster")); err == nil {
		t.Fatal("ambiguous credentials accepted")
	}
	t.Setenv("KUBECONFIG", "")
	t.Setenv("KUBE_CONFIG", "/tmp/alias")
	c, err = Parse(configArgs())
	if err != nil || c.Kubeconfig != "/tmp/alias" {
		t.Fatal("alias", err)
	}
	t.Setenv("KUBE_CONFIG", "")
	c, err = Parse(append(configArgs(), "--in-cluster"))
	if err != nil || !c.InCluster {
		t.Fatal("in-cluster", err)
	}
	if _, err = Parse(configArgs()); err == nil {
		t.Fatal("missing credential source accepted")
	}
}
func TestInteractiveRequiresDistinctHumanIdentity(t *testing.T) {
	t.Setenv("KUBECONFIG", "/tmp/context")
	if _, err := Parse(append(configArgs(), "--interactive")); err == nil {
		t.Fatal("interactive without human identity")
	}
	if _, err := Parse(append(configArgs(), "--interactive", "--human-token-file=/tmp/agent/collector/credential")); err == nil {
		t.Fatal("agent identity used for approval")
	}
}

type testLoop struct{ run func(context.Context) error }

func (l testLoop) Run(c context.Context) error { return l.run(c) }
func TestWorkerFailureCancelsOtherWorkers(t *testing.T) {
	stopped := make(chan struct{})
	err := runLoops(context.Background(), []loop{testLoop{func(ctx context.Context) error { <-ctx.Done(); close(stopped); return nil }}, testLoop{func(context.Context) error { return errors.New("failed") }}})
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("returned with live worker")
	}
}
