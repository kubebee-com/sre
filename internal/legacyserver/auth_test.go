package legacyserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

const testAPIToken = "test-api-token-do-not-log"

func testHandler(t *testing.T, s *Server) http.Handler {
	t.Helper()

	h, err := s.newHandler()
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}
	return h
}

func serveTestRequest(handler http.Handler, method, path string, body string, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestAuthenticatedBoundaryProtectsAPIAndStaticRoutes(t *testing.T) {
	s := NewServer(0, nil, triage.NewRuleBasedProvider(), remediation.NewEngine(k8sfake.NewSimpleClientset()), nil, ServerOptions{APIToken: testAPIToken})
	h := testHandler(t, s)

	for _, path := range []string{"/api/status", "/static/index.html", "/static/app.js"} {
		rr := serveTestRequest(h, http.MethodGet, path, "", "")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without credentials status = %d, want %d", path, rr.Code, http.StatusUnauthorized)
		}
		if strings.Contains(rr.Body.String(), testAPIToken) {
			t.Errorf("unauthorized response for %s exposed the API token", path)
		}
	}

	rr := serveTestRequest(h, http.MethodGet, "/", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET / without credentials status = %d, want %d for bootstrap", rr.Code, http.StatusOK)
	}
	bootstrap := rr.Body.String()
	for _, marker := range []string{"bootstrap-token", "loadProtectedDashboard", "sessionStorage", "Authorization", "Bearer ", "/static/index.html"} {
		if !strings.Contains(bootstrap, marker) {
			t.Errorf("public root bootstrap missing marker %q", marker)
		}
	}
	for _, marker := range []string{"stat-issues", "section-approvals", "Active Anomalies", "/static/app.js", "/api/status", "apiFetch", "loadStatus"} {
		if strings.Contains(bootstrap, marker) {
			t.Errorf("public root bootstrap contains protected dashboard marker %q", marker)
		}
	}
	if strings.Contains(bootstrap, testAPIToken) {
		t.Fatal("public root bootstrap exposed the API token")
	}

	rr = serveTestRequest(h, http.MethodGet, "/static/index.html", "", "wrong-token")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET /static/index.html with wrong credentials status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	rr = serveTestRequest(h, http.MethodGet, "/static/index.html", "", testAPIToken)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "stat-issues") {
		t.Fatalf("GET /static/index.html with valid credentials status = %d, want dashboard HTML", rr.Code)
	}

	rr = serveTestRequest(h, http.MethodGet, "/static/app.js", "", testAPIToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /static/app.js with valid credentials status = %d, want %d", rr.Code, http.StatusOK)
	}

	rr = serveTestRequest(h, http.MethodGet, "/api/status", "", testAPIToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/status with valid credentials status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHealthIsPublicAndReadinessStartsFalse(t *testing.T) {
	dependenciesReady := true
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken: testAPIToken,
		Readiness: func() bool {
			return dependenciesReady
		},
	})
	h := testHandler(t, s)

	rr := serveTestRequest(h, http.MethodGet, "/healthz", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", rr.Code, http.StatusOK)
	}

	rr = serveTestRequest(h, http.MethodGet, "/readyz", "", "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz before startup status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}

	s.SetReady(true)
	rr = serveTestRequest(h, http.MethodGet, "/readyz", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /readyz after startup status = %d, want %d", rr.Code, http.StatusOK)
	}

	dependenciesReady = false
	rr = serveTestRequest(h, http.MethodGet, "/readyz", "", "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with unavailable dependency status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestCORSEchoesOnlyConfiguredOrigins(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:       testAPIToken,
		AllowedOrigins: []string{"https://dashboard.example"},
	})
	h := testHandler(t, s)

	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("Origin", "https://dashboard.example")
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example" {
		t.Fatalf("allowed origin header = %q, want exact configured origin", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unconfigured origin header = %q, want empty", got)
	}

	wildcardServer := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:       testAPIToken,
		AllowedOrigins: []string{"*"},
	})
	wildcardHandler := testHandler(t, wildcardServer)
	req = httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("Origin", "https://dashboard.example")
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	rr = httptest.NewRecorder()
	wildcardHandler.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatal("authenticated traffic must never receive wildcard CORS")
	}

	req = httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("Origin", "*")
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	rr = httptest.NewRecorder()
	wildcardHandler.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatal("authenticated traffic must never echo a literal wildcard origin")
	}
}

func TestCORSPreflightRequiresConfiguredOrigin(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:       testAPIToken,
		AllowedOrigins: []string{"https://dashboard.example"},
	})
	h := testHandler(t, s)

	req := httptest.NewRequest(http.MethodOptions, "/api/status", nil)
	req.Header.Set("Origin", "https://dashboard.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("configured preflight status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example" {
		t.Fatalf("configured preflight origin = %q, want exact configured origin", got)
	}

	req = httptest.NewRequest(http.MethodOptions, "/api/status", nil)
	req.Header.Set("Origin", "https://attacker.example")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unconfigured preflight status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unconfigured preflight origin = %q, want empty", got)
	}
}

func TestJSONMutationRequiresJSONContentTypeAndHonorsBodyLimit(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:     testAPIToken,
		MaxBodyBytes: 32,
	})
	h := testHandler(t, s)

	for _, contentType := range []string{"", "text/plain"} {
		req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"hello"}`))
		req.Header.Set("Authorization", "Bearer "+testAPIToken)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Errorf("content type %q status = %d, want %d", contentType, rr.Code, http.StatusUnsupportedMediaType)
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"hello"}`))
	request.Header.Set("Authorization", "Bearer "+testAPIToken)
	request.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
	response := httptest.NewRecorder()
	if !requireJSONContentType(response, request) {
		t.Fatal("case-insensitive application/json content type must be accepted")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"message":"this payload is larger than the configured request limit"}`))
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized JSON status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestRateLimitIsPerClient(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		RequestsPerMinute: 60,
		RequestBurst:      1,
	})
	h := testHandler(t, s)

	first := serveTestRequest(h, http.MethodGet, "/healthz", "", "")
	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", first.Code, http.StatusOK)
	}
	second := serveTestRequest(h, http.MethodGet, "/healthz", "", "")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
}

func TestAuthenticatedActorIsPropagatedAndLegacyIdentityIsRejected(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{APIToken: testAPIToken})
	var gotActor string
	h := s.boundaryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotActor = actorFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("authenticated request status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if gotActor != "api-token" {
		t.Fatalf("authenticated actor = %q, want %q", gotActor, "api-token")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	req.Header.Set("X-User-Email", "attacker@example.com")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("legacy identity header status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if gotActor != "api-token" {
		t.Fatalf("legacy identity request changed actor to %q", gotActor)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	req.Header["X-User-Email"] = []string{""}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty legacy identity header status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestShutdownCancelsPendingStartClaim(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{})
	claimEntered := make(chan struct{})
	releaseClaim := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseClaim) })
	s.beforeStartClaimHook = func() {
		close(claimEntered)
		<-releaseClaim
	}

	startCtx, cancelStart := context.WithCancel(context.Background())
	defer cancelStart()
	startResult := make(chan error, 1)
	go func() {
		startResult <- s.Start(startCtx)
	}()
	select {
	case <-claimEntered:
	case <-time.After(time.Second):
		t.Fatal("Start() did not reach the startup claim boundary")
	}

	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- s.Shutdown(context.Background())
	}()
	select {
	case err := <-shutdownResult:
		t.Fatalf("Shutdown() completed while Start() was pending: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseClaim) })
	select {
	case err := <-shutdownResult:
		if err != nil {
			t.Fatalf("Shutdown() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown() did not finish after canceling pending startup")
	}
	select {
	case err := <-startResult:
		if err != nil {
			t.Fatalf("Start() error after shutdown cancellation = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not finish after shutdown cancellation")
	}

	if s.ready.Load() {
		t.Fatal("pending Start() left the server ready after Shutdown()")
	}
	s.lifecycleMu.Lock()
	started := s.started
	httpServer := s.httpServer
	listener := s.listener
	s.lifecycleMu.Unlock()
	if started || httpServer != nil || listener != nil {
		t.Fatalf("pending Start() left stale lifecycle state: started=%t httpServer=%v listener=%v", started, httpServer, listener)
	}
}

func TestRequiredAPITokenRejectsBlankBeforeListening(t *testing.T) {
	blocker, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("reserve test port: %v", err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port

	s := NewServer(port, nil, nil, nil, nil, ServerOptions{
		APIToken:        " \t",
		RequireAPIToken: true,
	})
	err = s.Start(context.Background())
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "api token is required") {
		t.Fatalf("Start() with blank required API token error = %v, want API token is required", err)
	}
}

func TestProposalRejectionResponsePreservesReason(t *testing.T) {
	engine := remediation.NewEngine(k8sfake.NewSimpleClientset())
	proposal := engine.CreateProposal(&scanner.Issue{ID: "rejection-reason-issue"}, &triage.Diagnosis{
		IssueID:         "rejection-reason-issue",
		Summary:         "summary",
		RootCause:       "root cause",
		Severity:        scanner.SeverityMedium,
		RemediationPlan: "plan",
		ActionType:      triage.ActionManual,
		ProposedCommand: "kubectl get pods -n default",
		ConfidenceScore: 0.5,
	})
	s := NewServer(0, nil, nil, engine, nil, ServerOptions{})
	h := testHandler(t, s)
	reason := "false alarm: duplicate finding confirmed"
	req := httptest.NewRequest(http.MethodPost, "/api/proposals/"+proposal.ID+"/reject", strings.NewReader(`{"reason":"false alarm: duplicate finding confirmed"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("proposal rejection status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"rejection_reason":"`+reason+`"`) {
		t.Fatalf("proposal rejection response omitted reason %q: %s", reason, rr.Body.String())
	}
}

func TestStartHonorsContextAndConfiguresTimeouts(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan error, 1)
	go func() {
		started <- s.Start(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.ready.Load() {
		t.Fatal("server did not become ready after binding")
	}

	s.lifecycleMu.Lock()
	httpServer := s.httpServer
	s.lifecycleMu.Unlock()
	if httpServer == nil {
		t.Fatal("server did not retain HTTP server")
	}
	if httpServer.ReadTimeout <= 0 || httpServer.ReadHeaderTimeout <= 0 || httpServer.WriteTimeout <= 0 || httpServer.IdleTimeout <= 0 {
		t.Fatalf("HTTP timeouts = read %s, header %s, write %s, idle %s; all must be positive", httpServer.ReadTimeout, httpServer.ReadHeaderTimeout, httpServer.WriteTimeout, httpServer.IdleTimeout)
	}

	cancel()
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("Start() after context cancellation error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not stop after context cancellation")
	}

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown() error = %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}
}

func TestServerDoesNotRetainRawToken(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{APIToken: testAPIToken})
	if strings.Contains(fmt.Sprintf("%#v", s), testAPIToken) {
		t.Fatal("server retained the raw API token")
	}
}

func TestDuplicateShutdownHonorsCallerContext(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil)
	done := make(chan struct{})

	s.lifecycleMu.Lock()
	s.httpServer = &http.Server{}
	s.shutdownStarted = true
	s.shutdownDone = done
	s.lifecycleMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	result := make(chan error, 1)
	go func() {
		result <- s.Shutdown(ctx)
	}()

	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("duplicate Shutdown error = %v, want context deadline", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("duplicate Shutdown did not honor caller context")
	}
}

func TestEmbeddedDashboardClientUsesSessionBearerAuth(t *testing.T) {
	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read embedded dashboard app: %v", err)
	}
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read embedded dashboard index: %v", err)
	}

	appText := string(app)
	for _, marker := range []string{
		"sessionStorage",
		"Authorization",
		"Bearer ",
		"showAuthRequired",
		"res.status === 401",
		"apiFetch('/api/status')",
		"async function login()",
	} {
		if !strings.Contains(appText, marker) {
			t.Errorf("dashboard app.js missing auth contract marker %q", marker)
		}
	}
	if strings.Contains(appText, "fetch('/api") || strings.Contains(appText, "fetch(`/api") {
		t.Error("dashboard app.js still makes an API request without the authenticated fetch wrapper")
	}

	indexText := string(index)
	for _, marker := range []string{
		"auth-panel",
		"auth-token",
		"sessionStorage",
		"Authorization",
		"Bearer ",
		"fetch('/static/app.js'",
		"dashboardLogin",
		"dashboardLogout",
	} {
		if !strings.Contains(indexText, marker) {
			t.Errorf("dashboard index.html missing login contract marker %q", marker)
		}
	}
	if strings.Contains(indexText, `<script src="/static/app.js"></script>`) {
		t.Error("dashboard index.html still loads app.js without authentication")
	}
	if strings.Contains(indexText, "https://cdn.tailwindcss.com") {
		t.Error("authenticated dashboard still loads executable Tailwind CDN code")
	}
}

func TestAuthenticationFailureDoesNotConsumeAuthenticatedRateLimit(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:          testAPIToken,
		RequestsPerMinute: 60,
		RequestBurst:      1,
	})
	h := s.boundaryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	failed := serveTestRequest(h, http.MethodGet, "/api/status", "", "wrong-token")
	if failed.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token status = %d, want %d", failed.Code, http.StatusUnauthorized)
	}
	valid := serveTestRequest(h, http.MethodGet, "/api/status", "", testAPIToken)
	if valid.Code != http.StatusNoContent {
		t.Fatalf("valid token after failed authentication status = %d, want %d", valid.Code, http.StatusNoContent)
	}
}

func TestAuthenticationFailuresAreRateLimitedByRemotePeer(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:              testAPIToken,
		TrustedClientIPHeader: "X-Forwarded-For",
		TrustedProxyCIDRs:     []string{"10.0.0.0/8"},
		RequestsPerMinute:     60,
		RequestBurst:          1,
	})
	h := s.boundaryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for index, forwardedFor := range []string{"203.0.113.10", "203.0.113.11"} {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "10.0.0.8:1234"
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		want := http.StatusUnauthorized
		if index == 1 {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("failed authentication %d status = %d, want %d", index+1, rr.Code, want)
		}
	}

	valid := serveTestRequest(h, http.MethodGet, "/api/status", "", testAPIToken)
	if valid.Code != http.StatusNoContent {
		t.Fatalf("valid authentication after failed requests status = %d, want %d", valid.Code, http.StatusNoContent)
	}
}

func TestTrustedClientAddressSeparatesAuthenticatedRateLimitBuckets(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:              testAPIToken,
		TrustedClientIPHeader: "X-Forwarded-For",
		TrustedProxyCIDRs:     []string{"10.0.0.0/8"},
		RequestsPerMinute:     60,
		RequestBurst:          1,
	})
	h := s.boundaryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, forwardedFor := range []string{"203.0.113.10", "203.0.113.11"} {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "10.0.0.8:1234"
		req.Header.Set("Authorization", "Bearer "+testAPIToken)
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("request for forwarded client %s status = %d, want %d", forwardedFor, rr.Code, http.StatusNoContent)
		}
	}
}

func TestUntrustedCallerCannotRotateTrustedForwardedRateLimit(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:              testAPIToken,
		TrustedClientIPHeader: "X-Forwarded-For",
		TrustedProxyCIDRs:     []string{"10.0.0.0/8"},
		RequestsPerMinute:     60,
		RequestBurst:          1,
	})
	h := s.boundaryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for index, forwardedFor := range []string{"203.0.113.10", "203.0.113.11"} {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "192.0.2.10:1234"
		req.Header.Set("Authorization", "Bearer "+testAPIToken)
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		want := http.StatusNoContent
		if index == 1 {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("untrusted forwarded client %s request status = %d, want %d", forwardedFor, rr.Code, want)
		}
	}
}

func TestForwardedClientAddressRequiresExplicitProxyCIDR(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{
		APIToken:              testAPIToken,
		TrustedClientIPHeader: "X-Forwarded-For",
		RequestsPerMinute:     60,
		RequestBurst:          1,
	})
	h := s.boundaryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for index, forwardedFor := range []string{"203.0.113.10", "203.0.113.11"} {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "10.244.12.7:1234"
		req.Header.Set("Authorization", "Bearer "+testAPIToken)
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		want := http.StatusNoContent
		if index == 1 {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("unconfigured forwarded client %s request status = %d, want %d", forwardedFor, rr.Code, want)
		}
	}
}

func TestRateLimiterHasBoundedClientState(t *testing.T) {
	limiter := newClientLimiter(60, 1)
	for i := 0; i < 2048; i++ {
		limiter.allow(fmt.Sprintf("client-%d", i))
	}
	if got := len(limiter.clients); got > 1024 {
		t.Fatalf("tracked client limiters = %d, want at most 1024", got)
	}
}

func TestRateLimiterEvictsIdleClientState(t *testing.T) {
	limiter := newClientLimiter(60, 1)
	if !limiter.allow("idle-client") {
		t.Fatal("first idle-client request was rejected")
	}

	limiter.mu.Lock()
	limiter.clients["idle-client"].lastSeen = time.Now().Add(-clientIdleEvictAfter - time.Second)
	limiter.mu.Unlock()

	if !limiter.allow("fresh-client") {
		t.Fatal("first fresh-client request was rejected")
	}
	limiter.mu.Lock()
	_, stillTracked := limiter.clients["idle-client"]
	limiter.mu.Unlock()
	if stillTracked {
		t.Fatal("idle client state was not evicted")
	}
}

func TestStartCanRetryAfterBindFailure(t *testing.T) {
	blocker, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("reserve test port: %v", err)
	}
	port := blocker.Addr().(*net.TCPAddr).Port
	s := NewServer(port, nil, nil, nil, nil, ServerOptions{})

	if err := s.Start(context.Background()); err == nil {
		t.Fatal("Start() with an occupied port succeeded")
	}
	if err := blocker.Close(); err != nil {
		t.Fatalf("release test port: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan error, 1)
	go func() {
		started <- s.Start(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.ready.Load() {
		t.Fatal("server did not become ready after retry")
	}
	cancel()
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("retry Start() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry Start() did not stop after cancellation")
	}
}

func TestStartCanRetryAfterContextShutdown(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{})
	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- s.Start(firstCtx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.ready.Load() {
		t.Fatal("server did not become ready for first start")
	}
	firstCancel()
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first Start() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Start() did not stop after cancellation")
	}

	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- s.Start(secondCtx)
	}()
	deadline = time.Now().Add(2 * time.Second)
	for !s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.ready.Load() {
		t.Fatal("server did not become ready for second start")
	}
	secondCancel()
	select {
	case err := <-secondResult:
		if err != nil {
			t.Fatalf("second Start() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Start() did not stop after cancellation")
	}
}

func TestShutdownClosesMCPAndRestartReopensIt(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{})

	firstContext := context.Background()
	firstResult := make(chan error, 1)
	go func() { firstResult <- s.Start(firstContext) }()
	deadline := time.Now().Add(2 * time.Second)
	for !s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.ready.Load() {
		t.Fatal("server did not become ready for first start")
	}

	runContext, unregister, err := s.registerMCPRun(context.Background())
	if err != nil {
		t.Fatalf("registerMCPRun() error = %v", err)
	}
	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- s.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownResult:
		if err != nil {
			t.Fatalf("Shutdown() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown() did not stop the first lifecycle")
	}
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first Start() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Start() did not stop after cancellation")
	}
	select {
	case <-runContext.Done():
	case <-time.After(time.Second):
		t.Fatal("Shutdown() did not cancel the active MCP run")
	}
	unregister()
	if s.mcpIsOpen() {
		t.Fatal("MCP remained open after Shutdown()")
	}

	secondContext, secondCancel := context.WithCancel(context.Background())
	secondResult := make(chan error, 1)
	go func() { secondResult <- s.Start(secondContext) }()
	deadline = time.Now().Add(2 * time.Second)
	for !s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.ready.Load() {
		t.Fatal("server did not become ready for restart")
	}
	if !s.mcpIsOpen() {
		t.Fatal("MCP remained closed after lifecycle restart")
	}
	secondCancel()
	select {
	case err := <-secondResult:
		if err != nil {
			t.Fatalf("second Start() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Start() did not stop after cancellation")
	}
}

func TestShutdownDuringStartupPreventsListenerPublication(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{})
	startupEntered := make(chan struct{})
	releaseStartup := make(chan struct{})
	s.beforeListenHook = func() {
		close(startupEntered)
		<-releaseStartup
	}

	startResult := make(chan error, 1)
	go func() {
		startResult <- s.Start(context.Background())
	}()
	select {
	case <-startupEntered:
	case <-time.After(time.Second):
		t.Fatal("Start() did not reach the pre-publication hook")
	}

	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- s.Shutdown(context.Background())
	}()
	deadline := time.Now().Add(time.Second)
	for {
		s.lifecycleMu.Lock()
		shutdownStarted := s.shutdownStarted
		s.lifecycleMu.Unlock()
		if shutdownStarted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Shutdown() did not claim startup before listener publication")
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseStartup)

	if err := <-shutdownResult; err != nil {
		t.Fatalf("startup Shutdown() error = %v, want nil", err)
	}
	if err := <-startResult; err != nil {
		t.Fatalf("Start() after startup Shutdown() error = %v, want nil", err)
	}
	if s.ready.Load() {
		t.Fatal("server became ready after startup was canceled")
	}
	s.lifecycleMu.Lock()
	httpServer := s.httpServer
	s.lifecycleMu.Unlock()
	if httpServer != nil {
		t.Fatal("startup cancellation published an HTTP server")
	}
}

func TestConcurrentShutdownAndRetryCannotOrphanListener(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test port: %v", err)
	}
	port := blocker.Addr().(*net.TCPAddr).Port
	if err := blocker.Close(); err != nil {
		t.Fatalf("release test port: %v", err)
	}

	s := NewServer(port, nil, nil, nil, nil, ServerOptions{})
	listenerAcquired := make(chan struct{})
	releasePublication := make(chan struct{})
	var firstPublication sync.Once
	s.beforePublishHook = func() {
		firstPublication.Do(func() {
			close(listenerAcquired)
			<-releasePublication
		})
	}

	firstResult := make(chan error, 1)
	go func() {
		firstResult <- s.Start(context.Background())
	}()
	select {
	case <-listenerAcquired:
	case <-time.After(time.Second):
		t.Fatal("first Start() did not reach the listener publication boundary")
	}

	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- s.Shutdown(context.Background())
	}()
	select {
	case err := <-shutdownResult:
		t.Fatalf("Shutdown() completed before startup cleanup: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	retryResult := make(chan error, 1)
	go func() {
		retryResult <- s.Start(context.Background())
	}()
	select {
	case err := <-retryResult:
		if err == nil || !strings.Contains(err.Error(), "already started") {
			t.Fatalf("concurrent retry error = %v, want server already started", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent retry did not observe the active startup")
	}

	close(releasePublication)
	if err := <-shutdownResult; err != nil {
		t.Fatalf("Shutdown() after startup cleanup error = %v, want nil", err)
	}
	if err := <-firstResult; err != nil {
		t.Fatalf("first Start() after shutdown error = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- s.Start(ctx)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.ready.Load() {
		t.Fatal("server did not become ready after listener cleanup")
	}
	cancel()
	select {
	case err := <-secondResult:
		if err != nil {
			t.Fatalf("second Start() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Start() did not stop after cancellation")
	}
}

func TestShutdownBeforeServeCannotLeaveStaleReadiness(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{})
	startupReady := make(chan struct{})
	releaseServe := make(chan struct{})
	listenerPublished := false
	s.beforeServeHook = func() {
		s.lifecycleMu.Lock()
		listenerPublished = s.httpServer != nil && s.listener != nil
		s.lifecycleMu.Unlock()
		close(startupReady)
		<-releaseServe
	}

	startResult := make(chan error, 1)
	go func() {
		startResult <- s.Start(context.Background())
	}()
	select {
	case <-startupReady:
	case <-time.After(time.Second):
		t.Fatal("Start() did not reach the pre-Serve boundary")
	}

	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- s.Shutdown(context.Background())
	}()
	select {
	case err := <-shutdownResult:
		if err != nil {
			t.Fatalf("Shutdown() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown() did not complete before Serve()")
	}
	if !listenerPublished {
		t.Fatal("shutdown race did not occur after listener publication")
	}

	close(releaseServe)
	select {
	case err := <-startResult:
		if err != nil {
			t.Fatalf("Start() after pre-Serve shutdown error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not finish after pre-Serve shutdown")
	}
	if s.ready.Load() {
		t.Fatal("server remained ready after Shutdown() won before Serve()")
	}
	s.lifecycleMu.Lock()
	started := s.started
	shutdownComplete := s.shutdownComplete
	httpServer := s.httpServer
	listener := s.listener
	serveStarted := s.serveStarted
	s.lifecycleMu.Unlock()
	if started || !shutdownComplete || httpServer != nil || listener != nil || serveStarted {
		t.Fatalf("stale lifecycle state after pre-Serve shutdown: started=%t shutdownComplete=%t httpServer=%v listener=%v serveStarted=%t", started, shutdownComplete, httpServer, listener, serveStarted)
	}
}

func TestShutdownTimeoutRetainsLifecycleUntilActiveHandlerStops(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{})
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()

	handlerStarted := make(chan struct{})
	handlerCanceled := make(chan struct{})
	handlerFinished := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseHandler) })

	var hookMu sync.Mutex
	hookCount := 0
	secondServeReached := make(chan struct{})
	var secondServeOnce sync.Once
	var serverAddress string
	s.beforeServeHook = func() {
		hookMu.Lock()
		hookCount++
		count := hookCount
		hookMu.Unlock()

		if count == 1 {
			s.lifecycleMu.Lock()
			tracker := s.requestTracker
			listener := s.listener
			if tracker != nil && listener != nil {
				address := listener.Addr().String()
				hookMu.Lock()
				serverAddress = address
				hookMu.Unlock()
				tracker.setHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerStarted)
					<-r.Context().Done()
					close(handlerCanceled)
					<-releaseHandler
					close(handlerFinished)
					w.WriteHeader(http.StatusNoContent)
				}))
			}
			s.lifecycleMu.Unlock()
			return
		}
		if count == 2 {
			secondServeOnce.Do(func() { close(secondServeReached) })
		}
	}

	firstResult := make(chan error, 1)
	go func() {
		firstResult <- s.Start(firstCtx)
	}()
	address := ""
	deadline := time.Now().Add(2 * time.Second)
	for address == "" && time.Now().Before(deadline) {
		hookMu.Lock()
		address = strings.TrimSpace(serverAddress)
		hookMu.Unlock()
		if address == "" {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if address == "" {
		t.Fatal("first Start() did not expose a listener address")
	}
	deadline = time.Now().Add(2 * time.Second)
	for !s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.ready.Load() {
		t.Fatal("first Start() did not become ready")
	}

	requestResult := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + address + "/healthz")
		if response != nil {
			_ = response.Body.Close()
		}
		requestResult <- err
	}()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("active handler did not start")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 25*time.Millisecond)
	shutdownErr := s.Shutdown(shutdownCtx)
	cancelShutdown()
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("timed-out Shutdown() error = %v, want context deadline", shutdownErr)
	}
	select {
	case <-handlerCanceled:
	case <-time.After(time.Second):
		t.Fatal("timed-out Shutdown() did not force-close the active handler connection")
	}

	s.lifecycleMu.Lock()
	startedAfterTimeout := s.started
	shutdownCompleteAfterTimeout := s.shutdownComplete
	s.lifecycleMu.Unlock()
	if !startedAfterTimeout || shutdownCompleteAfterTimeout {
		t.Fatal("timed-out Shutdown() released lifecycle ownership before the active handler stopped")
	}

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSecond()
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- s.Start(secondCtx)
	}()
	secondCompleted := false
	select {
	case <-secondServeReached:
		t.Fatal("retry Start() reached Serve while the prior handler was still active")
	case err := <-secondResult:
		secondCompleted = true
		if err == nil || !strings.Contains(err.Error(), "server already started") {
			t.Fatalf("retry Start() completed while the prior handler was still active: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	select {
	case <-handlerFinished:
	case <-time.After(time.Second):
		t.Fatal("active handler did not finish after forced connection close")
	}
	select {
	case <-firstResult:
	case <-time.After(time.Second):
		t.Fatal("first Start() did not finish after handler cleanup")
	}
	if secondCompleted {
		thirdCtx, cancelThird := context.WithCancel(context.Background())
		thirdResult := make(chan error, 1)
		go func() {
			thirdResult <- s.Start(thirdCtx)
		}()
		select {
		case <-secondServeReached:
		case <-time.After(time.Second):
			t.Fatal("retry Start() did not reach the new generation after handler cleanup")
		}
		cancelThird()
		select {
		case err := <-thirdResult:
			if err != nil {
				t.Fatalf("retry Start() error = %v, want nil", err)
			}
		case <-time.After(time.Second):
			t.Fatal("retry Start() did not stop after cancellation")
		}
	} else {
		select {
		case <-secondServeReached:
		case <-time.After(time.Second):
			t.Fatal("retry Start() did not reach the new generation after handler cleanup")
		}
		cancelSecond()
		select {
		case err := <-secondResult:
			if err != nil {
				t.Fatalf("retry Start() error = %v, want nil", err)
			}
		case <-time.After(time.Second):
			t.Fatal("retry Start() did not stop after cancellation")
		}
	}
	select {
	case <-requestResult:
	case <-time.After(time.Second):
		t.Fatal("active request did not finish after forced connection close")
	}
}

func TestShutdownBeforeServerPublicationHonorsContext(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{})
	done := make(chan struct{})
	s.lifecycleMu.Lock()
	s.started = true
	s.shutdownDone = done
	s.lifecycleMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pre-publication Shutdown() error = %v, want context deadline", err)
	}
	close(done)
}
