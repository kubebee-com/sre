package plugin

import (
	"context"
	"errors"
	"testing"

	apiv1 "github.com/kubebee-com/sre/api/v1"
	"github.com/kubebee-com/sre/pkg/scanner"
)

type registryRecorder struct {
	registered    []scanner.Analyzer
	unregistered  []string
	unregisterErr error
}

func (r *registryRecorder) RegisterAnalyzer(analyzer scanner.Analyzer) error {
	r.registered = append(r.registered, analyzer)
	return nil
}

func (r *registryRecorder) UnregisterAnalyzer(name string) error {
	r.unregistered = append(r.unregistered, name)
	if r.unregisterErr != nil {
		return r.unregisterErr
	}
	return nil
}

func TestRegistryRequiresExplicitActivationAndClosesOnUnregister(t *testing.T) {
	client, cleanup := newBufconnClient(t, &testPluginServer{response: &apiv1.AnalyzeResponse{SchemaVersion: SchemaVersion}}, Options{})
	defer cleanup()
	registry := NewRegistry()
	if err := registry.Register(client, nil); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	status, ok := registry.Get("external-check")
	if !ok || status.State != StateInactive {
		t.Fatalf("Get() = %#v, %v; want inactive", status, ok)
	}
	recorder := &registryRecorder{}
	if err := registry.Activate(context.Background(), "external-check", recorder); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if len(recorder.registered) != 1 {
		t.Fatalf("registered %d analyzers, want 1", len(recorder.registered))
	}
	if err := registry.Unregister("external-check"); !errors.Is(err, ErrPluginActive) {
		t.Fatalf("Unregister(active) error = %v, want ErrPluginActive", err)
	}
	if err := registry.Deactivate("external-check", recorder); err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if err := registry.Unregister("external-check"); err != nil {
		t.Fatalf("Unregister() error = %v", err)
	}
}

func TestRegistryDiscoversMetadataAndUnregistersOwnedAnalyzerOnClose(t *testing.T) {
	client, cleanup := newBufconnClient(t, &testPluginServer{
		response: &apiv1.AnalyzeResponse{SchemaVersion: SchemaVersion},
	}, Options{})
	defer cleanup()
	registry := NewRegistry()
	if err := registry.RegisterDiscovered(context.Background(), client, nil); err != nil {
		t.Fatalf("RegisterDiscovered() error = %v", err)
	}
	recorder := &registryRecorder{}
	if err := registry.Activate(context.Background(), "external-check", recorder); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(recorder.unregistered) != 1 || recorder.unregistered[0] != "external-check" {
		t.Fatalf("owned unregister calls = %#v, want external-check", recorder.unregistered)
	}
	if len(registry.List()) != 0 {
		t.Fatalf("registry entries after Close() = %#v, want empty", registry.List())
	}
}

func TestRegistryCloseRetainsOwnershipWhenUnregisterFails(t *testing.T) {
	client, cleanup := newBufconnClient(t, &testPluginServer{
		response: &apiv1.AnalyzeResponse{SchemaVersion: SchemaVersion},
	}, Options{})
	defer cleanup()
	registry := NewRegistry()
	if err := registry.Register(client, nil); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	recorder := &registryRecorder{}
	if err := registry.Activate(context.Background(), "external-check", recorder); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	recorder.unregisterErr = errors.New("registrar unavailable")
	if err := registry.Close(); err == nil {
		t.Fatal("Close() succeeded despite failed owned unregister")
	}
	status, ok := registry.Get("external-check")
	if !ok || status.State != StateActive {
		t.Fatalf("registry ownership after failed Close() = %#v, %v; want active retained entry", status, ok)
	}
	recorder.unregisterErr = nil
	if err := registry.Close(); err != nil {
		t.Fatalf("retry Close() error = %v", err)
	}
	if _, ok := registry.Get("external-check"); ok {
		t.Fatal("retry Close() retained plugin after successful unregister")
	}
}
