package plugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	apiv1 "github.com/kubebee-com/sre/api/v1"
	"google.golang.org/grpc"
)

const pluginSupervisorHelperEnv = "SRE_PLUGIN_SUPERVISOR_HELPER"

func TestPluginSupervisorHelperProcess(t *testing.T) {
	if os.Getenv(pluginSupervisorHelperEnv) != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || len(os.Args) <= separator+1 {
		os.Exit(2)
	}
	address := os.Args[separator+1]
	listener, err := net.Listen("tcp", address)
	if err != nil {
		os.Exit(3)
	}
	server := grpc.NewServer()
	apiv1.RegisterExternalAnalyzerServer(server, &supervisorHelperServer{ready: true})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		server.GracefulStop()
		_ = listener.Close()
	}()
	if err := server.Serve(listener); err != nil {
		return
	}
}

type supervisorHelperServer struct {
	apiv1.UnimplementedExternalAnalyzerServer
	ready bool
}

func (s *supervisorHelperServer) Metadata(context.Context, *apiv1.PluginMetadataRequest) (*apiv1.PluginMetadata, error) {
	return &apiv1.PluginMetadata{
		SchemaVersion: SchemaVersion,
		Name:          "supervised-check",
		Resource:      "Pod",
		Description:   "supervised pod checks",
		ReadOnly:      true,
	}, nil
}

func (s *supervisorHelperServer) Analyze(context.Context, *apiv1.AnalyzeRequest) (*apiv1.AnalyzeResponse, error) {
	return &apiv1.AnalyzeResponse{SchemaVersion: SchemaVersion}, nil
}

func (s *supervisorHelperServer) Health(context.Context, *apiv1.PluginEmpty) (*apiv1.HealthResponse, error) {
	return &apiv1.HealthResponse{SchemaVersion: SchemaVersion, Ready: s.ready}, nil
}

func TestProcessSupervisorStartsAndStopsWithoutShellInterpolation(t *testing.T) {
	address := unusedTCPAddress(t)
	sentinel := filepath.Join(t.TempDir(), "shell-expanded")
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		ClientOptions: Options{
			Metadata:              Metadata{Name: "supervised-check", Resource: "Pod", Description: "supervised pod checks", ReadOnly: true},
			Endpoint:              "http://" + address,
			AllowInsecureLoopback: true,
		},
		Command:        []string{os.Args[0], "-test.run=TestPluginSupervisorHelperProcess", "--", address, "$(touch " + sentinel + ")"},
		Environment:    []string{pluginSupervisorHelperEnv + "=1"},
		StartupTimeout: 2 * time.Second,
		HealthTimeout:  750 * time.Millisecond,
		StopTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewProcessSupervisor() error = %v", err)
	}
	client, err := supervisor.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if client == nil || supervisor.Client() != client {
		t.Fatal("Start() did not return the owned client")
	}
	registry := NewRegistry()
	if _, ok := registry.Get(client.Info().Name); ok {
		t.Fatal("Start() implicitly registered the plugin")
	}
	if err := registry.Register(client, nil); err != nil {
		t.Fatalf("Registry.Register() error = %v", err)
	}
	status, ok := registry.Get(client.Info().Name)
	if !ok || status.State != StateInactive {
		t.Fatalf("Registry.Get() = %#v, %v; want inactive", status, ok)
	}
	if _, _, err := client.Health(context.Background()); err != nil {
		t.Fatalf("client health after Start() error = %v", err)
	}
	if err := registry.Unregister(client.Info().Name); err != nil {
		t.Fatalf("Registry.Unregister() error = %v", err)
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shell expression was interpreted, stat error = %v", err)
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if supervisor.Client() != nil {
		t.Fatal("Client() returned a client after Stop()")
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestProcessSupervisorStartCancellationStopsChild(t *testing.T) {
	address := unusedTCPAddress(t)
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		ClientOptions: Options{
			Metadata:              Metadata{Name: "supervised-check", Resource: "Pod", Description: "supervised pod checks", ReadOnly: true},
			Endpoint:              "http://" + address,
			AllowInsecureLoopback: true,
		},
		Command:        []string{os.Args[0], "-test.run=TestPluginSupervisorHelperProcess", "--", address},
		Environment:    []string{pluginSupervisorHelperEnv + "=1"},
		StartupTimeout: time.Second,
		HealthTimeout:  time.Second,
		StopTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewProcessSupervisor() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if _, err := supervisor.Start(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start() error = %v, want context deadline", err)
	}
	if supervisor.Client() != nil {
		t.Fatal("Client() returned a client after canceled Start()")
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() after canceled Start() error = %v", err)
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() after canceled Start() error = %v", err)
	}
}

func TestProcessSupervisorStopCancelsInFlightStart(t *testing.T) {
	address := unusedTCPAddress(t)
	commandCreated := make(chan struct{})
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		ClientOptions: Options{
			Metadata:              Metadata{Name: "supervised-check", Resource: "Pod", Description: "supervised pod checks", ReadOnly: true},
			Endpoint:              "http://" + address,
			AllowInsecureLoopback: true,
		},
		CommandFactory: func(ctx context.Context) (*exec.Cmd, error) {
			close(commandCreated)
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestPluginSupervisorHelperProcess", "--", address)
			command.Env = append(os.Environ(), pluginSupervisorHelperEnv+"=1")
			return command, nil
		},
		StartupTimeout: 2 * time.Second,
		HealthTimeout:  2 * time.Second,
		StopTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewProcessSupervisor() error = %v", err)
	}
	startResult := make(chan error, 1)
	go func() {
		_, startErr := supervisor.Start(context.Background())
		startResult <- startErr
	}()
	select {
	case <-commandCreated:
	case <-time.After(time.Second):
		t.Fatal("command factory was not called")
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case err := <-startResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after Stop() canceled it")
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProcessSupervisorBoundsHealthAndUsesSafeErrors(t *testing.T) {
	address := unusedTCPAddress(t)
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		ClientOptions: Options{
			Metadata:              Metadata{Name: "supervised-check", Resource: "Pod", Description: "supervised pod checks", ReadOnly: true},
			Endpoint:              "http://" + address,
			AllowInsecureLoopback: true,
		},
		Command:        []string{os.Args[0], "-test.run=TestPluginSupervisorHelperProcess", "--", address},
		Environment:    []string{pluginSupervisorHelperEnv + "=1"},
		StartupTimeout: 50 * time.Millisecond,
		HealthTimeout:  50 * time.Millisecond,
		StopTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewProcessSupervisor() error = %v", err)
	}
	start := time.Now()
	_, err = supervisor.Start(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start() error = %v, want context deadline", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Start() took %s, want bounded startup", elapsed)
	}
	if strings.Contains(err.Error(), address) || strings.Contains(err.Error(), "-test.run") {
		t.Fatalf("Start() error leaked process details: %v", err)
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProcessSupervisorValidatesLifecycleAndClientTransport(t *testing.T) {
	baseClientOptions := Options{
		Metadata: Metadata{Name: "supervised-check", Resource: "Pod", Description: "supervised pod checks", ReadOnly: true},
		Endpoint: "https://plugin.example.test:43123",
	}
	tests := []struct {
		name    string
		options ProcessSupervisorOptions
		want    error
	}{
		{
			name: "missing command",
			options: ProcessSupervisorOptions{
				ClientOptions: baseClientOptions,
			},
			want: ErrProcessSupervisorCommand,
		},
		{
			name: "multiple command sources",
			options: ProcessSupervisorOptions{
				ClientOptions:  baseClientOptions,
				Command:        []string{"plugin"},
				CommandFactory: func(context.Context) (*exec.Cmd, error) { return exec.Command("plugin"), nil },
			},
			want: ErrProcessSupervisorCommand,
		},
		{
			name: "startup timeout too large",
			options: ProcessSupervisorOptions{
				ClientOptions:  baseClientOptions,
				Command:        []string{"plugin"},
				StartupTimeout: MaxProcessStartupTimeout + time.Nanosecond,
			},
			want: ErrProcessSupervisorTimeout,
		},
		{
			name: "TLS required",
			options: ProcessSupervisorOptions{
				ClientOptions: func() Options {
					clientOptions := baseClientOptions
					clientOptions.Endpoint = "http://plugin.example.test:43123"
					return clientOptions
				}(),
				Command: []string{"plugin"},
			},
			want: ErrTLSRequired,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewProcessSupervisor(test.options)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewProcessSupervisor() error = %v, want errors.Is(..., %v)", err, test.want)
			}
		})
	}
}

func TestProcessSupervisorClosePreventsStart(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		ClientOptions: Options{
			Metadata:              Metadata{Name: "supervised-check", Resource: "Pod", Description: "supervised pod checks", ReadOnly: true},
			Endpoint:              "http://127.0.0.1:43123",
			AllowInsecureLoopback: true,
		},
		Command: []string{"plugin"},
	})
	if err != nil {
		t.Fatalf("NewProcessSupervisor() error = %v", err)
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := supervisor.Start(context.Background()); !errors.Is(err, ErrProcessSupervisorClosed) {
		t.Fatalf("Start() after Close error = %v, want ErrProcessSupervisorClosed", err)
	}
}

func unusedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}
	return address
}

func TestProcessSupervisorCommandFactoryReceivesContext(t *testing.T) {
	address := unusedTCPAddress(t)
	var received context.Context
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		ClientOptions: Options{
			Metadata:              Metadata{Name: "supervised-check", Resource: "Pod", Description: "supervised pod checks", ReadOnly: true},
			Endpoint:              "http://" + address,
			AllowInsecureLoopback: true,
		},
		CommandFactory: func(ctx context.Context) (*exec.Cmd, error) {
			received = ctx
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestPluginSupervisorHelperProcess", "--", address)
			command.Env = append(os.Environ(), pluginSupervisorHelperEnv+"=1")
			return command, nil
		},
		StartupTimeout: 2 * time.Second,
		HealthTimeout:  time.Second,
		StopTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewProcessSupervisor() error = %v", err)
	}
	client, err := supervisor.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if client == nil || received == nil {
		t.Fatal("Start() did not create the command with a context")
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProcessSupervisorErrorDoesNotExposeFactoryError(t *testing.T) {
	secret := "plugin-secret"
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		ClientOptions: Options{
			Metadata: Metadata{Name: "supervised-check", Resource: "Pod", Description: "supervised pod checks", ReadOnly: true},
			Endpoint: "https://plugin.example.test:43123",
		},
		CommandFactory: func(context.Context) (*exec.Cmd, error) {
			return nil, fmt.Errorf("internal detail %s", secret)
		},
	})
	if err != nil {
		t.Fatalf("NewProcessSupervisor() error = %v", err)
	}
	_, err = supervisor.Start(context.Background())
	if !errors.Is(err, ErrProcessSupervisorCommand) {
		t.Fatalf("Start() error = %v, want ErrProcessSupervisorCommand", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Start() error leaked factory detail: %v", err)
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
