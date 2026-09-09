package plugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type blockingScannerRegistrar struct {
	registerStarted  chan struct{}
	releaseRegister  chan struct{}
	unregisterCalled chan struct{}
}

func newBlockingScannerRegistrar() *blockingScannerRegistrar {
	return &blockingScannerRegistrar{
		registerStarted:  make(chan struct{}),
		releaseRegister:  make(chan struct{}),
		unregisterCalled: make(chan struct{}),
	}
}

func (r *blockingScannerRegistrar) RegisterAnalyzer(scanner.Analyzer) error {
	close(r.registerStarted)
	<-r.releaseRegister
	return nil
}

func (r *blockingScannerRegistrar) UnregisterAnalyzer(string) error {
	close(r.unregisterCalled)
	return nil
}

func TestClassifyErrorUsesGRPCCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "resource exhausted", err: status.Error(codes.ResourceExhausted, "too large"), want: ErrPluginResponseLimit},
		{name: "deadline exceeded", err: status.Error(codes.DeadlineExceeded, "deadline"), want: context.DeadlineExceeded},
		{name: "canceled", err: status.Error(codes.Canceled, "canceled"), want: context.Canceled},
		{name: "permission denied", err: status.Error(codes.PermissionDenied, "denied"), want: ErrPluginUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyError(test.err, context.Background()); !errors.Is(got, test.want) {
				t.Fatalf("classifyError() = %v, want errors.Is(..., %v)", got, test.want)
			}
		})
	}
}

func TestRegistrySerializesDeactivateBehindActivate(t *testing.T) {
	client, cleanup := newBufconnClient(t, &testPluginServer{response: nil}, Options{})
	defer cleanup()
	registry := NewRegistry()
	if err := registry.Register(client, nil); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registrar := newBlockingScannerRegistrar()
	activateDone := make(chan error, 1)
	go func() { activateDone <- registry.Activate(context.Background(), "external-check", registrar) }()
	<-registrar.registerStarted

	deactivateDone := make(chan error, 1)
	go func() { deactivateDone <- registry.Deactivate("external-check", registrar) }()
	assertChannelBlocked(t, deactivateDone, "Deactivate")
	close(registrar.releaseRegister)
	if err := <-activateDone; err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := <-deactivateDone; err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	status, ok := registry.Get("external-check")
	if !ok || status.State != StateInactive {
		t.Fatalf("Get() = %#v, %v; want inactive", status, ok)
	}
}

func TestRegistrySerializesUnregisterAndCloseBehindActivate(t *testing.T) {
	for _, operation := range []string{"unregister", "close"} {
		t.Run(operation, func(t *testing.T) {
			client, cleanup := newBufconnClient(t, &testPluginServer{response: nil}, Options{})
			defer cleanup()
			registry := NewRegistry()
			if err := registry.Register(client, nil); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			registrar := newBlockingScannerRegistrar()
			activateDone := make(chan error, 1)
			go func() { activateDone <- registry.Activate(context.Background(), "external-check", registrar) }()
			<-registrar.registerStarted

			operationDone := make(chan error, 1)
			go func() {
				if operation == "unregister" {
					operationDone <- registry.Unregister("external-check")
					return
				}
				operationDone <- registry.Close()
			}()
			assertChannelBlocked(t, operationDone, operation)
			close(registrar.releaseRegister)
			if err := <-activateDone; err != nil {
				t.Fatalf("Activate() error = %v", err)
			}
			err := <-operationDone
			if operation == "unregister" {
				if !errors.Is(err, ErrPluginActive) {
					t.Fatalf("Unregister() error = %v, want ErrPluginActive", err)
				}
				if _, ok := registry.Get("external-check"); !ok {
					t.Fatal("Unregister() removed active plugin after serialized activation")
				}
				if closeErr := registry.Close(); closeErr != nil {
					t.Fatalf("cleanup Close() error = %v", closeErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if _, ok := registry.Get("external-check"); ok {
				t.Fatal("Close() retained plugin")
			}
		})
	}
}

func assertChannelBlocked(t *testing.T, done <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s completed before Activate released: %v", operation, err)
	case <-time.After(50 * time.Millisecond):
	}
}
