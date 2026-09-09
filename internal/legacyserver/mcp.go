package legacyserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kubebee-com/sre/pkg/buildinfo"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpScanInput struct {
	IncludeNamespaces []string `json:"include_namespaces,omitempty"`
	ExcludeNamespaces []string `json:"exclude_namespaces,omitempty"`
	LabelSelector     string   `json:"label_selector,omitempty"`
	Kinds             []string `json:"kinds,omitempty"`
	Names             []string `json:"names,omitempty"`
	Analyzers         []string `json:"analyzers,omitempty"`
	MaxConcurrency    int      `json:"max_concurrency,omitempty"`
	Timeout           string   `json:"timeout,omitempty"`
}

type mcpQueryInput struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type mcpHistoryInput struct{}

const (
	mcpMaxItems       = maxHistoryItems
	mcpMaxStringBytes = 8 << 10
)

var errMCPClosed = errors.New("MCP server is closed")

const (
	mcpIssuesResourceURI    = "sre://issues"
	mcpAnalyzersResourceURI = "sre://analyzers"
	mcpHistoryResourceURI   = "sre://history"
	mcpReviewPromptName     = "review-findings"
	mcpTriagePromptName     = "triage-issue"
)

func (s *Server) newMCPServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sre-agent",
		Version: buildinfo.String(),
	}, &mcp.ServerOptions{
		Instructions: "This server is read-only. Use the scan and query tools or the registered resources to inspect sanitized Kubernetes state.",
		Capabilities: &mcp.ServerCapabilities{},
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan",
		Description: "Run a bounded, read-only Kubernetes scan and return sanitized findings.",
	}, s.mcpScan)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "query",
		Description: "Read one explicitly allowlisted, non-secret Kubernetes resource by name.",
	}, s.mcpQuery)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "analyzers",
		Description: "List registered analyzer metadata and documentation links.",
	}, s.mcpAnalyzers)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "history",
		Description: "Read sanitized scan history entries.",
	}, s.mcpHistory)

	server.AddPrompt(&mcp.Prompt{
		Name:        mcpReviewPromptName,
		Title:       "Review current findings",
		Description: "Review the current sanitized Kubernetes findings and prioritize read-only investigation.",
	}, s.mcpReviewFindings)
	server.AddPrompt(&mcp.Prompt{
		Name:        mcpTriagePromptName,
		Title:       "Triage one finding",
		Description: "Build a focused, read-only investigation prompt for an active finding.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "issue_id",
			Title:       "Issue ID",
			Description: "The exact ID of an issue from the current scan.",
			Required:    true,
		}},
	}, s.mcpTriageIssue)

	server.AddResource(&mcp.Resource{
		URI:         mcpIssuesResourceURI,
		Name:        "current-issues",
		Title:       "Current issues",
		Description: "The latest sanitized findings recorded by the server.",
		MIMEType:    "application/json",
	}, s.mcpIssuesResource)
	server.AddResource(&mcp.Resource{
		URI:         mcpAnalyzersResourceURI,
		Name:        "analyzers",
		Title:       "Analyzer catalog",
		Description: "Registered analyzer metadata and capability state.",
		MIMEType:    "application/json",
	}, s.mcpAnalyzersResource)
	server.AddResource(&mcp.Resource{
		URI:         mcpHistoryResourceURI,
		Name:        "scan-history",
		Title:       "Scan history",
		Description: "Sanitized historical scan findings and resolution state.",
		MIMEType:    "application/json",
	}, s.mcpHistoryResource)

	return server
}

func (s *Server) newMCPHandler() http.Handler {
	server := s.newMCPServer()
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		MaxRequestBodyBytes:          s.maxBodyBytes,
		PropagateRequestCancellation: true,
	})
	return mcpLifecycleHandler{owner: s, delegate: handler}
}

type mcpLifecycleHandler struct {
	owner    *Server
	delegate http.Handler
}

func (h mcpLifecycleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.owner == nil {
		writeError(w, http.StatusServiceUnavailable, "MCP server is unavailable")
		return
	}
	if !h.owner.mcpIsOpen() {
		writeError(w, http.StatusServiceUnavailable, "MCP server is closed")
		return
	}
	runContext, unregister, err := h.owner.registerMCPRun(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP server is closed")
		return
	}
	defer unregister()
	h.delegate.ServeHTTP(w, r.WithContext(runContext))
}

func (s *Server) mcpIsOpen() bool {
	if s == nil {
		return false
	}
	s.mcpMu.Lock()
	closed := s.mcpClosed
	s.mcpMu.Unlock()
	return !closed
}

// CloseMCP cancels all in-flight stdio/in-memory MCP runs and prevents new
// MCP HTTP requests. The HTTP handler is stateless, so no session resources
// remain after the request returns.
func (s *Server) CloseMCP() error {
	if s == nil {
		return nil
	}
	s.mcpMu.Lock()
	if s.mcpClosed {
		s.mcpMu.Unlock()
		return nil
	}
	s.mcpClosed = true
	cancels := make([]context.CancelFunc, 0, len(s.mcpRunCancels))
	for id, cancel := range s.mcpRunCancels {
		cancels = append(cancels, cancel)
		delete(s.mcpRunCancels, id)
	}
	s.mcpMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return nil
}

// ServeStdio serves the same read-only MCP surface over the SDK's stdio
// transport. Stdio is a local process boundary, so it receives the local actor
// explicitly; HTTP requests continue to get their actor from authentication
// middleware.
func (s *Server) ServeStdio(ctx context.Context) error {
	if s == nil {
		return errors.New("server is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.serveMCP(ctx, &mcp.StdioTransport{})
}

func (s *Server) serveMCP(ctx context.Context, transport mcp.Transport) error {
	if s == nil {
		return errors.New("server is nil")
	}
	if transport == nil {
		return errors.New("MCP transport is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runContext, unregister, err := s.registerMCPRun(ctx)
	if err != nil {
		return err
	}
	defer unregister()
	return s.newMCPServer().Run(actorWithContext(runContext, localActor), transport)
}

func (s *Server) registerMCPRun(parent context.Context) (context.Context, func(), error) {
	if parent == nil {
		parent = context.Background()
	}
	s.mcpMu.Lock()
	defer s.mcpMu.Unlock()
	if s.mcpClosed {
		return nil, nil, errMCPClosed
	}
	if s.mcpRunCancels == nil {
		s.mcpRunCancels = make(map[uint64]context.CancelFunc)
	}
	runContext, cancel := context.WithCancel(parent)
	s.mcpRunSequence++
	id := s.mcpRunSequence
	s.mcpRunCancels[id] = cancel
	return runContext, func() {
		cancel()
		s.mcpMu.Lock()
		delete(s.mcpRunCancels, id)
		s.mcpMu.Unlock()
	}, nil
}

func (s *Server) mcpReviewFindings(ctx context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, err
	}
	return &mcp.GetPromptResult{
		Description: "Read-only review of the current Kubernetes findings.",
		Messages: []*mcp.PromptMessage{{
			Role:    "user",
			Content: &mcp.TextContent{Text: "Review the current Kubernetes findings using the read-only `sre://issues`, `sre://analyzers`, and `sre://history` resources. Prioritize findings by severity and recurrence, explain the evidence, and recommend verification steps without changing cluster state."},
		}},
	}, nil
}

func (s *Server) mcpTriageIssue(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Params == nil {
		return nil, s.safeMCPError(errors.New("issue_id is required"))
	}
	issueID := strings.TrimSpace(req.Params.Arguments["issue_id"])
	if issueID == "" {
		return nil, s.safeMCPError(errors.New("issue_id is required"))
	}
	issue := s.activeIssue(issueID)
	if issue == nil {
		return nil, s.safeMCPError(errors.New("issue was not found in the current scan"))
	}
	safeIssue := scanner.SanitizeIssueWithRedactor(issue, s.redactor)
	safeValue, err := safeJSONValue(safeIssue, s.redactor)
	if err != nil {
		return nil, errors.New("issue could not be serialized")
	}
	encoded, err := json.Marshal(safeValue)
	if err != nil {
		return nil, errors.New("issue could not be serialized")
	}
	return &mcp.GetPromptResult{
		Description: "Read-only investigation prompt for the selected finding.",
		Messages: []*mcp.PromptMessage{{
			Role:    "user",
			Content: &mcp.TextContent{Text: "Investigate this sanitized Kubernetes finding. Explain likely causes, identify read-only checks that can confirm or reject each hypothesis, and propose remediation options without executing changes. Finding:\n" + string(encoded)},
		}},
	}, nil
}

func (s *Server) mcpIssuesResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, err
	}
	active := s.issueSnapshot()
	issues := make([]*scanner.SanitizedIssue, 0, len(active))
	for _, issue := range active {
		if issue != nil {
			issues = append(issues, scanner.SanitizeIssueWithRedactor(issue, s.redactor))
		}
	}
	if len(issues) > mcpMaxItems {
		return nil, s.safeMCPError(errors.New("issue resource exceeds item limit"))
	}
	return s.mcpJSONResource(req, map[string]interface{}{
		"schema_version": scanplan.SchemaVersion,
		"issues":         issues,
	})
}

func (s *Server) mcpAnalyzersResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, err
	}
	if s.scanner == nil {
		return nil, errors.New("scanner is unavailable")
	}
	analyzers := s.scanner.GetAnalyzers()
	if len(analyzers) > mcpMaxItems {
		return nil, s.safeMCPError(errors.New("analyzer resource exceeds item limit"))
	}
	return s.mcpJSONResource(req, map[string]interface{}{
		"schema_version": compatibilitySchemaVersion,
		"analyzers":      analyzers,
	})
}

func (s *Server) mcpHistoryResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, err
	}
	entries := []scanner.HistoryEntry{}
	if s.scanner != nil && s.scanner.History() != nil {
		var err error
		entries, err = listHistory(s.scanner.History(), mcpMaxItems)
		if err != nil {
			return nil, errors.New("scan history is unavailable")
		}
	}
	if len(entries) > mcpMaxItems {
		return nil, s.safeMCPError(errors.New("history resource exceeds item limit"))
	}
	return s.mcpJSONResource(req, map[string]interface{}{
		"schema_version": "scan-history/v1",
		"entries":        entries,
	})
}

func (s *Server) mcpJSONResource(req *mcp.ReadResourceRequest, value interface{}) (*mcp.ReadResourceResult, error) {
	uri := ""
	if req != nil && req.Params != nil {
		uri = req.Params.URI
	}
	if uri == "" {
		return nil, errors.New("resource URI is required")
	}
	safeValue, err := safeJSONValue(value, s.redactor)
	if err != nil {
		return nil, errors.New("resource could not be serialized")
	}
	encoded, err := json.Marshal(safeValue)
	if err != nil {
		return nil, errors.New("resource could not be serialized")
	}
	if err := s.validateMCPResponse(encoded); err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      uri,
			MIMEType: "application/json",
			Text:     string(encoded),
		}},
	}, nil
}

func (s *Server) activeIssue(id string) *scanner.Issue {
	for _, issue := range s.issueSnapshot() {
		if issue != nil && issue.ID == id {
			copy := *issue
			copy.Events = append([]string(nil), issue.Events...)
			if issue.Parent != nil {
				parent := *issue.Parent
				copy.Parent = &parent
			}
			return &copy
		}
	}
	return nil
}

func (s *Server) mcpScan(ctx context.Context, _ *mcp.CallToolRequest, input mcpScanInput) (*mcp.CallToolResult, map[string]interface{}, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, nil, err
	}
	if s.scanner == nil {
		return nil, nil, errors.New("scanner is unavailable")
	}
	if err := s.validateMCPScanInput(input); err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	request := scanRequest{
		IncludeNamespaces: input.IncludeNamespaces,
		ExcludeNamespaces: input.ExcludeNamespaces,
		LabelSelector:     input.LabelSelector,
		Kinds:             input.Kinds,
		Names:             input.Names,
		Analyzers:         input.Analyzers,
		MaxConcurrency:    input.MaxConcurrency,
		Timeout:           input.Timeout,
	}
	plan, err := request.plan()
	if err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	knownAnalyzers := make([]string, 0, mcpMaxItems)
	for _, analyzer := range s.scanner.GetAnalyzers() {
		if len(knownAnalyzers) == mcpMaxItems {
			break
		}
		knownAnalyzers = append(knownAnalyzers, analyzer.Name)
	}
	if err := plan.Validate(knownAnalyzers); err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	report, err := s.scanner.ScanWithPlan(ctx, plan)
	if err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	if report == nil {
		return nil, nil, s.safeMCPError(errors.New("scanner returned no report"))
	}
	if len(report.Issues) > mcpMaxItems || len(report.Analyzers) > mcpMaxItems {
		return nil, nil, s.safeMCPError(errors.New("scan response exceeds item limit"))
	}
	s.UpdateScanResults(report.Issues)
	result := s.safeMCPReport(report)
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, nil, s.safeMCPError(errors.New("scan response could not be serialized"))
	}
	if err := s.validateMCPResponse(encoded); err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	return nil, result, nil
}

func (s *Server) mcpQuery(ctx context.Context, _ *mcp.CallToolRequest, input mcpQueryInput) (*mcp.CallToolResult, map[string]interface{}, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, nil, err
	}
	if s.scanner == nil {
		return nil, nil, errors.New("scanner is unavailable")
	}
	if err := s.validateMCPQueryInput(input); err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	resource, err := s.scanner.QueryResource(ctx, input.Kind, input.Namespace, input.Name)
	if err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	data, err := scanner.SanitizeResourceForKind(input.Kind, resource, s.redactor)
	if err != nil {
		return nil, nil, errors.New("resource could not be serialized")
	}
	result := map[string]interface{}{
		"schema_version": compatibilitySchemaVersion,
		"kind":           strings.TrimSpace(input.Kind),
		"namespace":      strings.TrimSpace(input.Namespace),
		"name":           strings.TrimSpace(input.Name),
		"resource":       data,
	}
	result, err = s.safeMCPMap(result)
	if err != nil {
		return nil, nil, s.safeMCPError(errors.New("resource could not be serialized"))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, nil, s.safeMCPError(errors.New("resource could not be serialized"))
	}
	if err := s.validateMCPResponse(encoded); err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	return nil, result, nil
}

func (s *Server) mcpAnalyzers(ctx context.Context, _ *mcp.CallToolRequest, _ map[string]interface{}) (*mcp.CallToolResult, map[string]interface{}, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, nil, err
	}
	if s.scanner == nil {
		return nil, nil, errors.New("scanner is unavailable")
	}
	analyzers := s.scanner.GetAnalyzers()
	if len(analyzers) > mcpMaxItems {
		return nil, nil, s.safeMCPError(errors.New("analyzer response exceeds item limit"))
	}
	result := map[string]interface{}{
		"schema_version": compatibilitySchemaVersion,
		"analyzers":      analyzers,
	}
	result, err := s.safeMCPMap(result)
	if err != nil {
		return nil, nil, s.safeMCPError(errors.New("analyzer response could not be serialized"))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, nil, s.safeMCPError(errors.New("analyzer response could not be serialized"))
	}
	if err := s.validateMCPResponse(encoded); err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	return nil, result, nil
}

func (s *Server) mcpHistory(ctx context.Context, _ *mcp.CallToolRequest, _ mcpHistoryInput) (*mcp.CallToolResult, map[string]interface{}, error) {
	if err := s.requireMCPActor(ctx); err != nil {
		return nil, nil, err
	}
	if s.scanner == nil || s.scanner.History() == nil {
		return nil, map[string]interface{}{
			"schema_version": "scan-history/v1",
			"entries":        []scanner.HistoryEntry{},
		}, nil
	}
	entries, err := listHistory(s.scanner.History(), mcpMaxItems)
	if err != nil {
		return nil, nil, errors.New("scan history is unavailable")
	}
	if len(entries) > mcpMaxItems {
		return nil, nil, s.safeMCPError(errors.New("history response exceeds item limit"))
	}
	result := map[string]interface{}{
		"schema_version": "scan-history/v1",
		"entries":        entries,
	}
	result, err = s.safeMCPMap(result)
	if err != nil {
		return nil, nil, s.safeMCPError(errors.New("history response could not be serialized"))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, nil, s.safeMCPError(errors.New("history response could not be serialized"))
	}
	if err := s.validateMCPResponse(encoded); err != nil {
		return nil, nil, s.safeMCPError(err)
	}
	return nil, result, nil
}

func (s *Server) validateMCPScanInput(input mcpScanInput) error {
	for name, value := range map[string]string{
		"label_selector": input.LabelSelector,
		"timeout":        input.Timeout,
	} {
		if err := validateMCPString(name, value); err != nil {
			return err
		}
	}
	for name, values := range map[string][]string{
		"include_namespaces": input.IncludeNamespaces,
		"exclude_namespaces": input.ExcludeNamespaces,
		"kinds":              input.Kinds,
		"names":              input.Names,
		"analyzers":          input.Analyzers,
	} {
		if len(values) > mcpMaxItems {
			return fmt.Errorf("%s exceeds item limit", name)
		}
		for _, value := range values {
			if err := validateMCPString(name, value); err != nil {
				return err
			}
		}
	}
	if input.MaxConcurrency < 0 || input.MaxConcurrency > scanplan.MaxConcurrency {
		return errors.New("max concurrency is out of bounds")
	}
	return nil
}

func (s *Server) validateMCPQueryInput(input mcpQueryInput) error {
	for name, value := range map[string]string{
		"kind":      input.Kind,
		"namespace": input.Namespace,
		"name":      input.Name,
	} {
		if err := validateMCPString(name, value); err != nil {
			return err
		}
	}
	if strings.TrimSpace(input.Name) == "" {
		return errors.New("name is required")
	}
	if err := validateServerQueryableKind(input.Kind); err != nil {
		return err
	}
	return nil
}

func validateMCPString(name, value string) error {
	if len(value) > mcpMaxStringBytes || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s exceeds string limit", name)
	}
	return nil
}

func (s *Server) validateMCPResponse(encoded []byte) error {
	limit := int64(1 << 20)
	if s != nil && s.maxBodyBytes > 0 {
		limit = s.maxBodyBytes
	}
	if int64(len(encoded)) > limit {
		return errors.New("MCP response exceeds size limit")
	}
	return nil
}

func (s *Server) safeMCPMap(value map[string]interface{}) (map[string]interface{}, error) {
	safeValue, err := safeJSONValue(value, s.redactor)
	if err != nil {
		return nil, err
	}
	result, ok := safeValue.(map[string]interface{})
	if !ok {
		return nil, errors.New("MCP response is not an object")
	}
	return result, nil
}

func (s *Server) requireMCPActor(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.authenticator != nil && s.authenticator.enabled && strings.TrimSpace(actorFromContext(ctx)) == "" {
		return errors.New("authentication required")
	}
	return nil
}

func (s *Server) safeMCPReport(report *scanner.ScanReport) map[string]interface{} {
	issues := make([]*scanner.SanitizedIssue, 0)
	if report != nil {
		issues = make([]*scanner.SanitizedIssue, 0, len(report.Issues))
		for _, issue := range report.Issues {
			if issue != nil {
				issues = append(issues, scanner.SanitizeIssueWithRedactor(issue, s.redactor))
			}
		}
	}
	value := map[string]interface{}{"schema_version": scanplan.SchemaVersion, "issues": issues}
	if report != nil {
		value = map[string]interface{}{
			"schema_version": report.SchemaVersion,
			"scope":          report.Scope,
			"issues":         issues,
			"analyzers":      report.Analyzers,
			"started_at":     report.StartedAt,
			"finished_at":    report.FinishedAt,
			"duration":       report.Duration,
		}
	}
	safeValue, err := s.safeMCPMap(value)
	if err != nil {
		return map[string]interface{}{"schema_version": scanplan.SchemaVersion, "error": "scan response unavailable"}
	}
	return safeValue
}

func safeJSONValue(value interface{}, redactor interface{ SanitizeValue(interface{}) interface{} }) (interface{}, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, err
	}
	if redactor == nil {
		return decoded, nil
	}
	return redactor.SanitizeValue(decoded), nil
}

func (s *Server) safeMCPError(err error) error {
	redactor := sanitizer.DefaultRedactor()
	if s != nil && s.redactor != nil {
		redactor = s.redactor
	}
	return fmt.Errorf("request failed: %s", safeErrorTextWithRedactor(err, redactor))
}

func safeMCPError(err error) error {
	return fmt.Errorf("request failed: %s", safeErrorTextWithRedactor(err, sanitizer.DefaultRedactor()))
}

func safeErrorTextWithRedactor(err error, redactor *sanitizer.Redactor) string {
	if err == nil {
		return "request failed"
	}
	text := safeErrorText(err)
	if redactor != nil {
		text = redactor.SanitizeText(text)
	}
	return text
}

func safeErrorText(err error) string {
	text := strings.TrimSpace(err.Error())
	if text == "" || len(text) > 256 {
		return "operation could not be completed"
	}
	return text
}
