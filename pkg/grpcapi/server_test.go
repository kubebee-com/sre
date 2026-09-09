package grpcapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	apiv1 "github.com/kubebee-com/sre/api/v1"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const grpcTestToken = "grpc-test-token"

type testScanner struct {
	mu       sync.Mutex
	issues   []*scanner.Issue
	report   *scanner.ScanReport
	resource interface{}
	scanErr  error
	queryErr error
	scanFn   func(context.Context, scanplan.Plan) (*scanner.ScanReport, error)
	queryFn  func(context.Context, string, string, string) (interface{}, error)
	deadline bool
}

func (s *testScanner) ScanWithPlan(ctx context.Context, plan scanplan.Plan) (*scanner.ScanReport, error) {
	s.mu.Lock()
	s.deadline = false
	if _, ok := ctx.Deadline(); ok {
		s.deadline = true
	}
	s.mu.Unlock()
	if s.scanFn != nil {
		return s.scanFn(ctx, plan)
	}
	if s.scanErr != nil {
		return nil, s.scanErr
	}
	return s.report, nil
}

func (s *testScanner) GetAnalyzers() []scanner.AnalyzerInfo {
	return []scanner.AnalyzerInfo{{
		Name:        "pod-health",
		Resource:    "pods",
		Description: "Finds unhealthy pods",
		DocsURL:     "https://docs.example.test/pod-health",
		Enabled:     true,
		IssueCount:  len(s.issues),
	}}
}

func (s *testScanner) QueryResource(ctx context.Context, kind, namespace, name string) (interface{}, error) {
	if s.queryFn != nil {
		return s.queryFn(ctx, kind, namespace, name)
	}
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	return s.resource, nil
}

type testConfigProvider struct {
	value interface{}
	err   error
}

func (p testConfigProvider) GetConfig(context.Context) (interface{}, error) {
	return p.value, p.err
}

func startGRPCTestServer(t *testing.T, backend Scanner, options Options) (apiv1.AnalyzerServiceClient, apiv1.QueryServiceClient, apiv1.ConfigServiceClient, func()) {
	t.Helper()
	server, err := NewServer(backend, options)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	listener := bufconn.Listen(1 << 20)
	go func() {
		_ = server.Serve(listener)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	cancel()
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("grpc.DialContext() error = %v", err)
	}
	cleanup := func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	}
	return apiv1.NewAnalyzerServiceClient(conn), apiv1.NewQueryServiceClient(conn), apiv1.NewConfigServiceClient(conn), cleanup
}

func authContext() context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), TokenMetadataKey, "Bearer "+grpcTestToken)
}

func TestServerRequiresBearerTokenAndDoesNotEchoAuthenticationSecrets(t *testing.T) {
	backend := &testScanner{}
	analyzers, _, _, cleanup := startGRPCTestServer(t, backend, Options{APIToken: grpcTestToken})
	defer cleanup()

	_, err := analyzers.ListAnalyzers(context.Background(), &apiv1.Empty{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous ListAnalyzers() code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
	if strings.Contains(err.Error(), grpcTestToken) {
		t.Fatalf("anonymous error leaked token: %v", err)
	}

	wrong := metadata.AppendToOutgoingContext(context.Background(), TokenMetadataKey, "Bearer wrong-token")
	_, err = analyzers.ListAnalyzers(wrong, &apiv1.Empty{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid-token ListAnalyzers() code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
	if strings.Contains(err.Error(), grpcTestToken) || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("invalid-token error leaked credential: %v", err)
	}
	rawToken := metadata.AppendToOutgoingContext(context.Background(), TokenMetadataKey, grpcTestToken)
	_, err = analyzers.ListAnalyzers(rawToken, &apiv1.Empty{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("raw-token ListAnalyzers() code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}

	response, err := analyzers.ListAnalyzers(authContext(), &apiv1.Empty{})
	if err != nil {
		t.Fatalf("authenticated ListAnalyzers() error = %v", err)
	}
	if len(response.GetAnalyzers()) != 1 || response.GetAnalyzers()[0].GetName() != "pod-health" {
		t.Fatalf("unexpected analyzer projection: %+v", response.GetAnalyzers())
	}
}

func TestDirectServiceCallsStillRequireMetadataAuthentication(t *testing.T) {
	service, err := NewService(&testScanner{}, Options{APIToken: grpcTestToken})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if _, err := service.ListAnalyzers(context.Background(), &apiv1.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous direct call code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
	incoming := metadata.NewIncomingContext(context.Background(), metadata.Pairs(TokenMetadataKey, "Bearer "+grpcTestToken))
	if _, err := service.ListAnalyzers(incoming, &apiv1.Empty{}); err != nil {
		t.Fatalf("authenticated direct call error = %v", err)
	}
}

func TestNewServiceRequiresConfiguredToken(t *testing.T) {
	if _, err := NewService(&testScanner{}); err == nil {
		t.Fatal("NewService() accepted an empty API token")
	}
}

func TestScanPropagatesContextCancellation(t *testing.T) {
	started := make(chan struct{})
	backend := &testScanner{
		scanFn: func(ctx context.Context, _ scanplan.Plan) (*scanner.ScanReport, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	analyzers, _, _, cleanup := startGRPCTestServer(t, backend, Options{
		APIToken:       grpcTestToken,
		RequestTimeout: time.Second,
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(authContext(), 50*time.Millisecond)
	defer cancel()
	_, err := analyzers.Scan(ctx, &apiv1.ScanRequest{Timeout: "500ms"})
	if status.Code(err) != codes.DeadlineExceeded && status.Code(err) != codes.Canceled {
		t.Fatalf("deadline Scan() code = %v, want deadline/canceled: %v", status.Code(err), err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scanner did not receive the request")
	}
}

func TestScanProjectsSafeReport(t *testing.T) {
	secret := "scan-secret-value"
	now := time.Now().UTC()
	backend := &testScanner{report: &scanner.ScanReport{
		SchemaVersion: scanplan.SchemaVersion,
		Scope:         scanplan.Default().EffectiveScope(),
		Issues: []*scanner.Issue{{
			ID:            "issue-1",
			Namespace:     "ops",
			Kind:          "Pod",
			Name:          "worker",
			Severity:      scanner.SeverityHigh,
			Category:      scanner.CategoryPodLogError,
			Summary:       "pod failed",
			Details:       "password=" + secret,
			LogsSnippet:   "token=" + secret,
			FirstObserved: now,
			LastObserved:  now,
		}},
		Analyzers: []scanner.AnalyzerRun{{
			Info:  scanner.AnalyzerInfo{Name: "pod-health", Resource: "pods", Description: "checks pods"},
			Error: "backend secret=" + secret,
		}},
		StartedAt:  now,
		FinishedAt: now,
		Duration:   "1ms",
	}}
	analyzers, _, _, cleanup := startGRPCTestServer(t, backend, Options{
		APIToken:     grpcTestToken,
		SecretValues: []string{secret},
	})
	defer cleanup()

	response, err := analyzers.Scan(authContext(), &apiv1.ScanRequest{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(response.GetIssues()) != 1 || strings.Contains(response.GetIssues()[0].GetDetails(), secret) || strings.Contains(response.GetIssues()[0].GetLogsSnippet(), secret) {
		t.Fatalf("unsafe issue projection: %+v", response.GetIssues())
	}
	if len(response.GetAnalyzers()) != 1 || response.GetAnalyzers()[0].GetError() != "analyzer failed" {
		t.Fatalf("unsafe analyzer projection: %+v", response.GetAnalyzers())
	}
	backend.mu.Lock()
	deadline := backend.deadline
	backend.mu.Unlock()
	if !deadline {
		t.Fatal("scanner context did not include a deadline")
	}
}

func TestScanRejectsOversizedFieldsWithoutEchoingThem(t *testing.T) {
	backend := &testScanner{report: &scanner.ScanReport{SchemaVersion: scanplan.SchemaVersion}}
	analyzers, _, _, cleanup := startGRPCTestServer(t, backend, Options{
		APIToken:        grpcTestToken,
		MaxStringBytes:  16,
		MaxReceiveBytes: 4096,
		RequestTimeout:  time.Second,
	})
	defer cleanup()

	secret := strings.Repeat("sensitive-selector-", 20)
	_, err := analyzers.Scan(authContext(), &apiv1.ScanRequest{LabelSelector: secret})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized Scan() code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("oversized request error echoed input: %v", err)
	}
}

func TestServerRejectsOversizedWireRequests(t *testing.T) {
	backend := &testScanner{report: &scanner.ScanReport{SchemaVersion: scanplan.SchemaVersion}}
	analyzers, _, _, cleanup := startGRPCTestServer(t, backend, Options{
		APIToken:        grpcTestToken,
		MaxReceiveBytes: 128,
	})
	defer cleanup()

	_, err := analyzers.Scan(authContext(), &apiv1.ScanRequest{
		IncludeNamespaces: []string{strings.Repeat("namespace-", 40)},
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized wire request code = %v, want %v: %v", status.Code(err), codes.ResourceExhausted, err)
	}
}

func TestQueryProjectsSafeJSONAndBoundsResponses(t *testing.T) {
	secret := "query-secret-value"
	backend := &testScanner{resource: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name": "worker",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{map[string]interface{}{
				"name":  "worker",
				"token": secret,
			}},
		},
	}}
	_, query, _, cleanup := startGRPCTestServer(t, backend, Options{
		APIToken:     grpcTestToken,
		SecretValues: []string{secret},
	})
	defer cleanup()

	response, err := query.GetResource(authContext(), &apiv1.QueryRequest{Kind: "Pod", Namespace: "ops", Name: "worker"})
	if err != nil {
		t.Fatalf("GetResource() error = %v", err)
	}
	if strings.Contains(response.GetResourceJson(), secret) {
		t.Fatalf("query response leaked secret: %s", response.GetResourceJson())
	}
	var projected map[string]interface{}
	if err := json.Unmarshal([]byte(response.GetResourceJson()), &projected); err != nil {
		t.Fatalf("query resource JSON is invalid: %v", err)
	}

	backend.queryErr = errors.New("pod/ops/worker contains query-secret-value")
	_, err = query.GetResource(authContext(), &apiv1.QueryRequest{Kind: "Pod", Namespace: "ops", Name: "worker"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("backend query error code = %v, want %v", status.Code(err), codes.Unavailable)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "worker") {
		t.Fatalf("query error leaked resource details: %v", err)
	}
}

func TestQueryRejectsSecretKindsBeforeCallingTheBackend(t *testing.T) {
	called := false
	backend := &testScanner{queryFn: func(context.Context, string, string, string) (interface{}, error) {
		called = true
		return map[string]interface{}{"kind": "Secret", "data": map[string]string{"token": "secret"}}, nil
	}}
	_, query, _, cleanup := startGRPCTestServer(t, backend, Options{APIToken: grpcTestToken})
	defer cleanup()

	_, err := query.GetResource(authContext(), &apiv1.QueryRequest{Kind: "v1/Secret", Namespace: "ops", Name: "credentials"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("secret query code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
	if called {
		t.Fatal("secret query reached the backend")
	}
}

func TestQueryRejectsUnallowlistedKindsBeforeCallingTheBackend(t *testing.T) {
	called := false
	backend := &testScanner{queryFn: func(context.Context, string, string, string) (interface{}, error) {
		called = true
		return map[string]interface{}{"kind": "Event"}, nil
	}}
	_, query, _, cleanup := startGRPCTestServer(t, backend, Options{APIToken: grpcTestToken})
	defer cleanup()

	_, err := query.GetResource(authContext(), &apiv1.QueryRequest{Kind: "Event", Name: "audit"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unallowlisted query code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
	if called {
		t.Fatal("unallowlisted query reached the backend")
	}
}

func TestQueryPropagatesCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	backend := &testScanner{queryFn: func(ctx context.Context, _, _, _ string) (interface{}, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	_, query, _, cleanup := startGRPCTestServer(t, backend, Options{APIToken: grpcTestToken})
	defer cleanup()

	ctx, cancel := context.WithTimeout(authContext(), 50*time.Millisecond)
	defer cancel()
	_, err := query.GetResource(ctx, &apiv1.QueryRequest{Kind: "Pod", Name: "worker"})
	if status.Code(err) != codes.DeadlineExceeded && status.Code(err) != codes.Canceled {
		t.Fatalf("deadline GetResource() code = %v, want deadline/canceled: %v", status.Code(err), err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query backend did not receive the request")
	}
}

func TestQueryRejectsOversizedResponse(t *testing.T) {
	backend := &testScanner{resource: map[string]interface{}{"spec": map[string]string{"description": strings.Repeat("x", 1024)}}}
	_, query, _, cleanup := startGRPCTestServer(t, backend, Options{
		APIToken:              grpcTestToken,
		MaxQueryResponseBytes: 128,
	})
	defer cleanup()

	_, err := query.GetResource(authContext(), &apiv1.QueryRequest{Kind: "Pod", Name: "worker"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized query response code = %v, want %v: %v", status.Code(err), codes.ResourceExhausted, err)
	}
	if strings.Contains(err.Error(), "description") {
		t.Fatalf("oversized response error leaked payload details: %v", err)
	}
}

func TestConfigProjectsSecretsAndUsesBoundedRequestContext(t *testing.T) {
	_, _, config, cleanup := startGRPCTestServer(t, &testScanner{}, Options{
		APIToken: grpcTestToken,
		Config: testConfigProvider{value: map[string]interface{}{
			"provider": "openai",
			"api_key":  "config-secret-value",
			"nested":   map[string]interface{}{"password": "another-secret"},
		}},
	})
	defer cleanup()

	response, err := config.GetConfig(authContext(), &apiv1.Empty{})
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if strings.Contains(response.GetConfigJson(), "config-secret-value") || strings.Contains(response.GetConfigJson(), "another-secret") {
		t.Fatalf("config response leaked secret: %s", response.GetConfigJson())
	}
}

func TestScanMapsBackendErrorsToSafeStatus(t *testing.T) {
	backend := &testScanner{scanErr: fmt.Errorf("namespace=ops/pod=worker password=backend-secret")}
	analyzers, _, _, cleanup := startGRPCTestServer(t, backend, Options{APIToken: grpcTestToken})
	defer cleanup()

	_, err := analyzers.Scan(authContext(), &apiv1.ScanRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("backend scan error code = %v, want %v", status.Code(err), codes.Unavailable)
	}
	for _, value := range []string{"backend-secret", "ops", "worker"} {
		if strings.Contains(err.Error(), value) {
			t.Fatalf("scan error leaked %q: %v", value, err)
		}
	}
}

func TestNewServerRejectsLimitsAboveHardBounds(t *testing.T) {
	backend := &testScanner{}
	if _, err := NewServer(backend, Options{MaxReceiveBytes: hardMaxReceiveSize + 1}); err == nil {
		t.Fatal("NewServer() accepted an unbounded receive limit")
	}
	if _, err := NewServer(backend, Options{MaxItems: hardMaxItems + 1}); err == nil {
		t.Fatal("NewServer() accepted an unbounded item limit")
	}
}

func TestNewServerRequiresAPIToken(t *testing.T) {
	if _, err := NewServer(&testScanner{}); err == nil {
		t.Fatal("NewServer() accepted an empty API token")
	}
}

func TestNewServerRequiresTLSCertificate(t *testing.T) {
	_, err := NewServer(&testScanner{}, Options{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
	if err == nil {
		t.Fatal("NewServer() accepted TLS without a certificate")
	}
}
