package plugin

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apiv1 "github.com/kubebee-com/sre/api/v1"
	"github.com/kubebee-com/sre/pkg/scanner"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type testPluginServer struct {
	apiv1.UnimplementedExternalAnalyzerServer
	response    *apiv1.AnalyzeResponse
	block       atomic.Bool
	started     chan struct{}
	startedOnce sync.Once
	token       string
}

func (s *testPluginServer) authorize(ctx context.Context) error {
	if s.token == "" {
		return nil
	}
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(values.Get("authorization")) != 1 || values.Get("authorization")[0] != "Bearer "+s.token {
		return status.Error(codes.Unauthenticated, "authentication required")
	}
	return nil
}

func (s *testPluginServer) Analyze(ctx context.Context, _ *apiv1.AnalyzeRequest) (*apiv1.AnalyzeResponse, error) {
	if err := s.authorize(ctx); err != nil {
		return nil, err
	}
	if s.block.Load() {
		s.startedOnce.Do(func() { close(s.started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.response, nil
}

func (s *testPluginServer) Metadata(ctx context.Context, _ *apiv1.PluginMetadataRequest) (*apiv1.PluginMetadata, error) {
	if err := s.authorize(ctx); err != nil {
		return nil, err
	}
	return &apiv1.PluginMetadata{SchemaVersion: SchemaVersion, Name: "external-check", Resource: "Pod", Description: "external pod checks", DocsUrl: "https://example.test/plugin", ReadOnly: true}, nil
}

func (s *testPluginServer) Health(ctx context.Context, _ *apiv1.PluginEmpty) (*apiv1.HealthResponse, error) {
	if err := s.authorize(ctx); err != nil {
		return nil, err
	}
	return &apiv1.HealthResponse{SchemaVersion: SchemaVersion, Ready: true, Message: "ready"}, nil
}

func newBufconnClient(t *testing.T, service *testPluginServer, options Options) (*Client, func()) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	apiv1.RegisterExternalAnalyzerServer(grpcServer, service)
	go func() { _ = grpcServer.Serve(listener) }()
	options.Endpoint = "http://127.0.0.1:43123"
	options.AllowInsecureLoopback = true
	options.DialContext = func(context.Context, string) (net.Conn, error) { return listener.Dial() }
	if options.Metadata.Name == "" {
		options.Metadata = Metadata{Name: "external-check", Resource: "Pod", Description: "external pod checks", ReadOnly: true}
	}
	client, err := NewClient(options)
	if err != nil {
		grpcServer.Stop()
		_ = listener.Close()
		t.Fatalf("NewClient() error = %v", err)
	}
	return client, func() {
		_ = client.Close()
		grpcServer.Stop()
		_ = listener.Close()
	}
}

func TestClientProjectsAndRedactsExternalFindings(t *testing.T) {
	secret := "plugin-secret"
	service := &testPluginServer{response: &apiv1.AnalyzeResponse{
		SchemaVersion: SchemaVersion,
		Findings: []*apiv1.PluginFinding{{
			Id: "finding-1", Kind: "Pod", Name: "payments", Severity: "HIGH", Category: "ExternalFailure",
			Summary: "secret=" + secret, Details: "inspect " + secret, Evidence: []string{"token=" + secret},
			DocsUrl: "https://example.test/docs",
		}},
	}}
	client, cleanup := newBufconnClient(t, service, Options{SecretValues: []string{secret}})
	defer cleanup()
	issues, err := client.Analyze(context.Background(), "payments")
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(issues) != 1 || issues[0].Kind != "Pod" || issues[0].Severity != scanner.SeverityHigh {
		t.Fatalf("Analyze() = %#v, want one high Pod finding", issues)
	}
	if strings.Contains(issues[0].Summary+issues[0].Details+strings.Join(issues[0].Events, " "), secret) {
		t.Fatalf("external finding leaked secret: %#v", issues[0])
	}
}

func TestClientRejectsMalformedResponsesAndHonorsClose(t *testing.T) {
	service := &testPluginServer{response: &apiv1.AnalyzeResponse{SchemaVersion: "plugin/v0"}}
	client, cleanup := newBufconnClient(t, service, Options{})
	defer cleanup()
	if _, err := client.Analyze(context.Background(), "default"); !errors.Is(err, ErrPluginResponse) {
		t.Fatalf("Analyze() error = %v, want ErrPluginResponse", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := client.Analyze(context.Background(), "default"); !errors.Is(err, ErrPluginClosed) {
		t.Fatalf("Analyze() after Close error = %v, want ErrPluginClosed", err)
	}
}

func TestClientCancellationAndQuota(t *testing.T) {
	service := &testPluginServer{started: make(chan struct{})}
	service.block.Store(true)
	client, cleanup := newBufconnClient(t, service, Options{MaxConcurrent: 1})
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := client.Analyze(ctx, "default")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Analyze() error = %v, want context deadline", err)
	}
	select {
	case <-service.started:
	case <-time.After(time.Second):
		t.Fatal("plugin did not receive canceled request")
	}
}

func TestClientRequiresTLSForNonLoopbackEndpoint(t *testing.T) {
	_, err := NewClient(Options{Metadata: Metadata{Name: "external-check", Resource: "Pod", Description: "checks", ReadOnly: true}, Endpoint: "http://plugin.example.test:43123"})
	if !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("NewClient() error = %v, want ErrTLSRequired", err)
	}
}

func TestClientPropagatesTokenAndDiscoversMetadata(t *testing.T) {
	service := &testPluginServer{response: &apiv1.AnalyzeResponse{SchemaVersion: SchemaVersion}, token: "plugin-token"}
	client, cleanup := newBufconnClient(t, service, Options{Token: "plugin-token"})
	defer cleanup()

	metadata, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if metadata.Name != "external-check" || !metadata.ReadOnly {
		t.Fatalf("Discover() = %#v, want read-only external-check metadata", metadata)
	}
	if _, _, err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health() with configured token error = %v", err)
	}
	if _, err := client.Analyze(context.Background(), "default"); err != nil {
		t.Fatalf("Analyze() with configured token error = %v", err)
	}
}

func TestClientRejectsNonReadOnlyMetadata(t *testing.T) {
	_, err := NewClient(Options{
		Metadata: Metadata{Name: "mutable", Resource: "Pod", Description: "mutable analyzer", ReadOnly: false},
		Endpoint: "http://127.0.0.1:43123", AllowInsecureLoopback: true,
	})
	if !errors.Is(err, ErrMetadataInvalid) {
		t.Fatalf("NewClient() error = %v, want ErrMetadataInvalid", err)
	}
}
