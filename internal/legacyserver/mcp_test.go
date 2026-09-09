package legacyserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestMCPStreamableHTTPUsesOfficialSDKAndReadOnlyTools(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "ops"}})
	s := NewServer(0, scanner.NewClusterScanner(clientset), triage.NewRuleBasedProvider(), remediation.NewEngine(clientset), nil, ServerOptions{APIToken: testAPIToken})
	h := testHandler(t, s)
	httpServer := httptest.NewServer(h)
	defer httpServer.Close()

	unauthorizedRequest, err := http.NewRequest(http.MethodPost, httpServer.URL+"/api/v1/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatalf("build unauthorized request: %v", err)
	}
	unauthorizedRequest.Header.Set("Content-Type", "application/json")
	unauthorizedResponse, err := http.DefaultClient.Do(unauthorizedRequest)
	if err != nil {
		t.Fatalf("unauthorized MCP request: %v", err)
	}
	if unauthorizedResponse.StatusCode != http.StatusUnauthorized {
		_ = unauthorizedResponse.Body.Close()
		t.Fatalf("unauthorized MCP status = %d, want %d", unauthorizedResponse.StatusCode, http.StatusUnauthorized)
	}
	_ = unauthorizedResponse.Body.Close()

	authedClient := &http.Client{Transport: bearerRoundTripper{base: http.DefaultTransport, token: testAPIToken}}
	protocolClient := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             httpServer.URL + "/api/v1/mcp",
		HTTPClient:           authedClient,
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := protocolClient.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("MCP Connect() error = %v", err)
	}
	defer session.Close()
	if capabilities := session.InitializeResult().Capabilities; capabilities == nil || capabilities.Prompts == nil || capabilities.Resources == nil {
		t.Fatalf("MCP capabilities = %#v, want prompts and resources", capabilities)
	}

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("MCP ListTools() error = %v", err)
	}
	seen := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		seen[tool.Name] = true
	}
	for _, name := range []string{"scan", "query", "analyzers", "history"} {
		if !seen[name] {
			t.Errorf("MCP tools/list omitted %q", name)
		}
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "query",
		Arguments: map[string]interface{}{
			"kind":      "pod",
			"namespace": "ops",
			"name":      "worker",
		},
	})
	if err != nil {
		t.Fatalf("MCP query tool error = %v", err)
	}
	if result.IsError {
		t.Fatalf("MCP query tool returned error: %#v", result.Content)
	}
	if len(result.Content) == 0 && result.StructuredContent == nil {
		t.Fatal("MCP query tool returned no content")
	}

	prompts, err := session.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("MCP ListPrompts() error = %v", err)
	}
	for _, name := range []string{"review-findings", "triage-issue"} {
		found := false
		for _, prompt := range prompts.Prompts {
			if prompt.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("MCP prompts/list omitted %q", name)
		}
	}
	review, err := session.GetPrompt(ctx, &mcp.GetPromptParams{Name: "review-findings"})
	if err != nil {
		t.Fatalf("MCP review prompt error = %v", err)
	}
	if len(review.Messages) != 1 {
		t.Fatalf("MCP review prompt messages = %d, want 1", len(review.Messages))
	}

	resources, err := session.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("MCP ListResources() error = %v", err)
	}
	if len(resources.Resources) != 3 {
		t.Fatalf("MCP resources/list returned %d resources, want 3", len(resources.Resources))
	}
	resource, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "sre://analyzers"})
	if err != nil {
		t.Fatalf("MCP ReadResource() error = %v", err)
	}
	if len(resource.Contents) != 1 || resource.Contents[0].MIMEType != "application/json" {
		t.Fatalf("MCP analyzer resource contents = %#v, want one application/json item", resource.Contents)
	}
}

func TestMCPStandardPromptsResourcesAndStdioLifecycle(t *testing.T) {
	const secret = "cluster-resource-secret"
	history := scanner.NewMemoryHistoryStore()
	issue := &scanner.Issue{
		ID:        "issue-1",
		Namespace: "ops",
		Kind:      "Pod",
		Name:      "worker",
		Category:  scanner.CategoryPodLogError,
		Severity:  scanner.SeverityHigh,
		Summary:   "token=" + secret,
		Details:   "inspect the failing workload",
	}
	if err := history.Record([]*scanner.Issue{issue}); err != nil {
		t.Fatalf("record history: %v", err)
	}
	clientset := k8sfake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "ops"}})
	s := NewServer(0, scanner.NewClusterScannerWithHistory(clientset, history), triage.NewRuleBasedProvider(), remediation.NewEngine(clientset), nil, ServerOptions{
		APIToken:         testAPIToken,
		RedactionSecrets: []string{secret},
	})
	s.UpdateScanResults([]*scanner.Issue{issue})

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- s.serveMCP(ctx, serverTransport)
	}()

	protocolClient := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := protocolClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("MCP in-memory Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	prompt, err := session.GetPrompt(ctx, &mcp.GetPromptParams{Name: "triage-issue", Arguments: map[string]string{"issue_id": issue.ID}})
	if err != nil {
		t.Fatalf("MCP triage prompt error = %v", err)
	}
	if len(prompt.Messages) != 1 {
		t.Fatalf("MCP triage prompt messages = %d, want 1", len(prompt.Messages))
	}
	promptContent, ok := prompt.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("MCP triage prompt content = %T, want *mcp.TextContent", prompt.Messages[0].Content)
	}
	if strings.Contains(promptContent.Text, secret) || !strings.Contains(promptContent.Text, "issue-1") {
		t.Fatalf("MCP triage prompt leaked or omitted issue data: %q", promptContent.Text)
	}

	issuesResource, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "sre://issues"})
	if err != nil {
		t.Fatalf("MCP issues resource error = %v", err)
	}
	if len(issuesResource.Contents) != 1 || strings.Contains(issuesResource.Contents[0].Text, secret) {
		t.Fatalf("MCP issues resource leaked data: %#v", issuesResource.Contents)
	}
	if !json.Valid([]byte(issuesResource.Contents[0].Text)) {
		t.Fatalf("MCP issues resource is not valid JSON: %q", issuesResource.Contents[0].Text)
	}
	historyResource, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "sre://history"})
	if err != nil {
		t.Fatalf("MCP history resource error = %v", err)
	}
	if len(historyResource.Contents) != 1 || strings.Contains(historyResource.Contents[0].Text, secret) {
		t.Fatalf("MCP history resource leaked data: %#v", historyResource.Contents)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("close MCP client session: %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("MCP in-memory server did not stop after client close")
	}
}

func TestMCPBoundsAndQueryAllowlistRejectBeforeBackend(t *testing.T) {
	backend := &lifecycleQueryScanner{}
	s := NewServer(0, backend, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{APIToken: testAPIToken})
	ctx := actorWithContext(context.Background(), authenticatedActor)

	if _, _, err := s.mcpQuery(ctx, nil, mcpQueryInput{Kind: "Event", Name: "audit"}); err == nil {
		t.Fatal("mcpQuery() accepted an unallowlisted kind")
	}
	if backend.calls != 0 {
		t.Fatalf("mcpQuery() backend calls = %d, want 0", backend.calls)
	}
	if _, _, err := s.mcpScan(ctx, nil, mcpScanInput{MaxConcurrency: -1}); err == nil {
		t.Fatal("mcpScan() accepted negative max concurrency")
	}
	if backend.calls != 0 {
		t.Fatalf("mcpScan() backend calls = %d, want 0", backend.calls)
	}
}

func TestMCPCloseCancelsRunsAndRejectsNewRuns(t *testing.T) {
	s := NewServer(0, &lifecycleQueryScanner{}, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{})
	serverTransport, _ := mcp.NewInMemoryTransports()
	done := make(chan error, 1)
	go func() { done <- s.serveMCP(context.Background(), serverTransport) }()
	// Give Run enough time to register its transport before closing the owner.
	time.Sleep(20 * time.Millisecond)
	if err := s.CloseMCP(); err != nil {
		t.Fatalf("CloseMCP() error = %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("MCP run did not stop after CloseMCP")
	}
	if err := s.serveMCP(context.Background(), serverTransport); !errors.Is(err, errMCPClosed) {
		t.Fatalf("serveMCP() after CloseMCP error = %v, want errMCPClosed", err)
	}
}

func TestMCPHistoryUsesBoundedStoreBeforeResponseMaterialization(t *testing.T) {
	history := &boundedHistoryStore{entries: []scanner.HistoryEntry{{Fingerprint: "bounded"}}}
	s := NewServer(0, &lifecycleQueryScanner{history: history}, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{})
	ctx := actorWithContext(context.Background(), authenticatedActor)

	if _, _, err := s.mcpHistory(ctx, nil, mcpHistoryInput{}); err != nil {
		t.Fatalf("mcpHistory() error = %v", err)
	}
	if _, err := s.mcpHistoryResource(ctx, &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: mcpHistoryResourceURI}}); err != nil {
		t.Fatalf("mcpHistoryResource() error = %v", err)
	}
	if history.limitCalls != 2 || history.listCalls != 0 {
		t.Fatalf("history calls = ListLimit:%d List:%d, want bounded retrieval only", history.limitCalls, history.listCalls)
	}
}

type bearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (t bearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}
