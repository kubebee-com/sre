package legacyserver

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubebee-com/sre/pkg/metrics"
	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/playbook"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	triagepkg "github.com/kubebee-com/sre/pkg/triage"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed static/*
var staticFS embed.FS

type ServerOptions struct {
	Playbooks             *playbook.Service
	APIToken              string
	RequireAPIToken       bool
	AllowedOrigins        []string
	MaxBodyBytes          int64
	MaxResponseBytes      int64
	RequestsPerMinute     int
	RequestBurst          int
	TrustedClientIPHeader string
	TrustedProxyCIDRs     []string
	RedactionSecrets      []string
	Readiness             func() bool
	Metrics               *metrics.Registry
	Runtime               RuntimeSettings
}

const (
	maxServerResponseBytes int64 = 16 << 20
	maxHistoryItems              = 256
)

type StatusSettings struct {
	APITokenRequired    bool     `json:"api_token_required"`
	AllowedOrigins      []string `json:"allowed_origins,omitempty"`
	MaxRequestBytes     int64    `json:"max_request_bytes"`
	MaxResponseBytes    int64    `json:"max_response_bytes"`
	RequestsPerMinute   int      `json:"requests_per_minute"`
	RequestBurst        int      `json:"request_burst"`
	ReadinessManaged    bool     `json:"readiness_managed"`
	LLMProvider         string   `json:"llm_provider,omitempty"`
	LLMMode             string   `json:"llm_mode,omitempty"`
	LLMWireAPI          string   `json:"llm_wire_api,omitempty"`
	LLMModel            string   `json:"llm_model,omitempty"`
	LLMBaseURLDisplay   string   `json:"llm_base_url_display,omitempty"`
	ScanInterval        string   `json:"scan_interval,omitempty"`
	ScanJitter          string   `json:"scan_jitter,omitempty"`
	EventDrivenScanning bool     `json:"event_driven_scanning"`
	EventQueueCapacity  int      `json:"event_queue_capacity"`
	EventDebounce       string   `json:"event_debounce,omitempty"`
	CacheEnabled        bool     `json:"cache_enabled"`
	CacheConfigured     bool     `json:"cache_configured"`
	WebhookConfigured   bool     `json:"webhook_configured"`
}

// RuntimeSettings is the sanitized configuration projection supplied by the
// process owner. Secrets, custom headers, cache keys, and raw endpoint paths
// are intentionally outside this type.
type RuntimeSettings struct {
	LLMProvider         string
	LLMMode             string
	LLMWireAPI          string
	LLMModel            string
	LLMBaseURLDisplay   string
	ScanInterval        string
	ScanJitter          string
	EventDrivenScanning bool
	EventQueueCapacity  int
	EventDebounce       string
	CacheEnabled        bool
	CacheConfigured     bool
}

type TokenUsageStatus struct {
	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`
	TotalTokens  uint64 `json:"total_tokens"`
	Estimated    bool   `json:"estimated"`
}

// Scanner is the read-only scanner surface required by the HTTP server.
// Keeping this as an interface lets callers opt into dynamic CRD analyzers
// without weakening the default typed-client scanner.
type Scanner interface {
	Scan(context.Context, string) ([]*scanner.Issue, error)
	ScanWithPlan(context.Context, scanplan.Plan) (*scanner.ScanReport, error)
	GetAnalyzers() []scanner.AnalyzerInfo
	GetPodCleaner() *scanner.PodCleaner
	History() scanner.HistoryStore
	QueryResource(context.Context, string, string, string) (interface{}, error)
}

type metricsScanner interface {
	SetMetricsObserver(scanner.MetricsObserver)
}

type Server struct {
	playbooks             *playbook.Service
	port                  int
	scanner               Scanner
	triage                triagepkg.TriageProvider
	engine                *remediation.Engine
	notifier              *notifier.WebhookNotifier
	authenticator         *tokenAuthenticator
	requireAPIToken       bool
	allowedOrigins        map[string]struct{}
	maxBodyBytes          int64
	maxResponseBytes      int64
	requestsPerMinute     int
	requestBurst          int
	limiter               *clientLimiter
	authFailureLimiter    *clientLimiter
	trustedClientIPHeader string
	trustedProxyNetworks  []*net.IPNet
	readiness             func() bool
	redactor              *sanitizer.Redactor
	redactionSecrets      []string
	metrics               *metrics.Registry
	runtime               RuntimeSettings
	chatSessions          *triagepkg.ChatSessionManager
	mcpMu                 sync.Mutex
	mcpClosed             bool
	mcpRunCancels         map[uint64]context.CancelFunc
	mcpRunSequence        uint64
	statusMetricsMu       sync.Mutex
	statusErrorCounts     map[string]uint64
	inputTokens           atomic.Uint64
	outputTokens          atomic.Uint64
	lastScan              time.Time
	activeIssues          []*scanner.Issue
	activeIssuesExplicit  bool
	mu                    sync.RWMutex
	ready                 atomic.Bool
	lifecycleMu           sync.Mutex
	httpServer            *http.Server
	started               bool
	shutdownStarted       bool
	shutdownDone          chan struct{}
	shutdownErr           error
	shutdownComplete      bool
	lifecycleGeneration   uint64
	startupPending        bool
	startupCancelled      bool
	startupDone           chan struct{}
	beforeListenHook      func()
	beforeStartClaimHook  func()
	beforePublishHook     func()
	beforeServeHook       func()
	listener              net.Listener
	requestTracker        *requestTracker
	serveStarted          bool
	startSlot             chan struct{}
}

type requestTracker struct {
	mu       sync.Mutex
	handler  http.Handler
	active   int
	stopping bool
	done     chan struct{}
}

func newRequestTracker(handler http.Handler) *requestTracker {
	return &requestTracker{
		handler: handler,
		done:    make(chan struct{}),
	}
}

func (t *requestTracker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	if t.stopping {
		t.mu.Unlock()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	t.active++
	handler := t.handler
	t.mu.Unlock()

	defer t.finish()
	if handler == nil {
		http.NotFound(w, r)
		return
	}
	handler.ServeHTTP(w, r)
}

func (t *requestTracker) setHandler(handler http.Handler) {
	t.mu.Lock()
	t.handler = handler
	t.mu.Unlock()
}

func (t *requestTracker) finish() {
	t.mu.Lock()
	t.active--
	if t.stopping && t.active == 0 {
		close(t.done)
	}
	t.mu.Unlock()
}

func (t *requestTracker) stop() {
	t.mu.Lock()
	if !t.stopping {
		t.stopping = true
		if t.active == 0 {
			close(t.done)
		}
	}
	t.mu.Unlock()
}

func (t *requestTracker) wait(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func NewServer(
	port int,
	scanner Scanner,
	triage triagepkg.TriageProvider,
	engine *remediation.Engine,
	notifier *notifier.WebhookNotifier,
	options ...ServerOptions,
) *Server {
	var opts ServerOptions
	if len(options) > 0 {
		opts = options[0]
	}
	defaultMaxBodyBytes, defaultRequestsPerMinute, defaultRequestBurst := defaultServerLimits()
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodyBytes
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = opts.MaxBodyBytes * 4
	}
	if opts.MaxResponseBytes > maxServerResponseBytes {
		opts.MaxResponseBytes = maxServerResponseBytes
	}
	if opts.RequestsPerMinute <= 0 {
		opts.RequestsPerMinute = defaultRequestsPerMinute
	}
	if opts.RequestBurst <= 0 {
		opts.RequestBurst = defaultRequestBurst
	}

	allowedOrigins := make(map[string]struct{}, len(opts.AllowedOrigins))
	for _, origin := range opts.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allowedOrigins[origin] = struct{}{}
		}
	}
	trustedProxyNetworks := parseTrustedProxyCIDRs(opts.TrustedProxyCIDRs)
	sanitizer.ConfigureDefaultRedactor(opts.RedactionSecrets...)
	metricsRegistry := opts.Metrics
	if metricsRegistry == nil {
		metricsRegistry = metrics.NewRegistry()
	}
	if configurable, ok := scanner.(metricsScanner); ok {
		configurable.SetMetricsObserver(metricsRegistry)
	}
	redactor := sanitizer.RedactorForSecrets(opts.RedactionSecrets...)
	chatSessions := triagepkg.NewChatSessionManager(triage, triagepkg.WithChatSessionSecrets(opts.RedactionSecrets...))
	_ = chatSessions.RegisterReadOnlyTool(scannerReadOnlyTool{scanner: scanner, redactor: redactor})

	startSlot := make(chan struct{}, 1)
	startSlot <- struct{}{}

	return &Server{
		playbooks:             opts.Playbooks,
		port:                  port,
		scanner:               scanner,
		triage:                triage,
		engine:                engine,
		notifier:              notifier,
		authenticator:         newTokenAuthenticator(opts.APIToken),
		requireAPIToken:       opts.RequireAPIToken,
		allowedOrigins:        allowedOrigins,
		maxBodyBytes:          opts.MaxBodyBytes,
		maxResponseBytes:      opts.MaxResponseBytes,
		requestsPerMinute:     opts.RequestsPerMinute,
		requestBurst:          opts.RequestBurst,
		limiter:               newClientLimiter(opts.RequestsPerMinute, opts.RequestBurst),
		authFailureLimiter:    newClientLimiter(opts.RequestsPerMinute, opts.RequestBurst),
		trustedClientIPHeader: opts.TrustedClientIPHeader,
		trustedProxyNetworks:  trustedProxyNetworks,
		readiness:             opts.Readiness,
		redactor:              redactor,
		redactionSecrets:      append([]string(nil), opts.RedactionSecrets...),
		metrics:               metricsRegistry,
		runtime:               opts.Runtime,
		chatSessions:          chatSessions,
		mcpRunCancels:         make(map[uint64]context.CancelFunc),
		statusErrorCounts:     make(map[string]uint64),
		startSlot:             startSlot,
	}
}

func (s *Server) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := s.startupValidationError(); err != nil {
		return err
	}

	s.lifecycleMu.Lock()
	if s.started || s.startupPending {
		s.lifecycleMu.Unlock()
		return errors.New("server already started")
	}
	s.startupPending = true
	s.startupCancelled = false
	s.startupDone = make(chan struct{})
	beforeStartClaimHook := s.beforeStartClaimHook
	s.lifecycleMu.Unlock()
	if beforeStartClaimHook != nil {
		beforeStartClaimHook()
	}

	startSlot, acquired := s.acquireStartSlot(ctx)
	if !acquired {
		s.finishPendingStartup()
		return ctx.Err()
	}
	defer s.releaseStartSlot(startSlot)

	s.lifecycleMu.Lock()
	if s.started {
		s.lifecycleMu.Unlock()
		s.finishPendingStartup()
		return errors.New("server already started")
	}
	if s.startupCancelled {
		s.lifecycleMu.Unlock()
		s.finishPendingStartup()
		return nil
	}
	startupDone := s.startupDone
	s.startupPending = false
	s.startupDone = nil
	if startupDone != nil {
		close(startupDone)
	}
	s.started = true
	s.lifecycleGeneration++
	generation := s.lifecycleGeneration
	s.shutdownStarted = false
	s.shutdownDone = make(chan struct{})
	s.shutdownErr = nil
	s.shutdownComplete = false
	s.httpServer = nil
	s.requestTracker = nil
	s.mcpMu.Lock()
	s.mcpClosed = false
	s.mcpRunCancels = make(map[uint64]context.CancelFunc)
	s.mcpMu.Unlock()
	s.lifecycleMu.Unlock()
	s.SetReady(false)

	handler, err := s.newHandler()
	if err != nil {
		s.completeLifecycle(generation, nil)
		return err
	}
	s.lifecycleMu.Lock()
	beforeListenHook := s.beforeListenHook
	s.lifecycleMu.Unlock()
	if beforeListenHook != nil {
		beforeListenHook()
	}

	trackedHandler := newRequestTracker(handler)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           trackedHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Server: Starting server on port %d...", s.port)
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		s.completeLifecycle(generation, nil)
		return fmt.Errorf("listen on %s: %w", httpServer.Addr, err)
	}
	log.Printf("Server: net.Listen succeeded on %s", httpServer.Addr)

	select {
	case <-ctx.Done():
		_ = listener.Close()
		s.completeLifecycle(generation, nil)
		return ctx.Err()
	default:
	}

	s.lifecycleMu.Lock()
	beforePublishHook := s.beforePublishHook
	s.lifecycleMu.Unlock()
	if beforePublishHook != nil {
		beforePublishHook()
	}

	s.lifecycleMu.Lock()
	sameGeneration := generation == s.lifecycleGeneration
	shutdownRequested := s.shutdownStarted
	ctxErr := ctx.Err()
	if !sameGeneration || shutdownRequested || ctxErr != nil {
		s.lifecycleMu.Unlock()
		_ = listener.Close()
		if sameGeneration {
			s.completeLifecycle(generation, nil)
		}
		if ctxErr != nil && !shutdownRequested {
			return ctxErr
		}
		return nil
	}
	s.httpServer = httpServer
	s.listener = listener
	s.requestTracker = trackedHandler
	s.lifecycleMu.Unlock()

	select {
	case <-ctx.Done():
		_ = listener.Close()
		s.completeLifecycle(generation, nil)
		return ctx.Err()
	default:
	}

	s.lifecycleMu.Lock()
	sameGeneration = generation == s.lifecycleGeneration
	shutdownRequested = sameGeneration && s.shutdownStarted
	ctxErr = ctx.Err()
	if sameGeneration && !shutdownRequested && ctxErr == nil {
		s.serveStarted = true
		s.lifecycleMu.Unlock()
	} else {
		s.lifecycleMu.Unlock()
		_ = listener.Close()
		if sameGeneration {
			s.completeLifecycle(generation, nil)
		}
		if ctxErr != nil && !shutdownRequested {
			return ctxErr
		}
		return nil
	}

	s.lifecycleMu.Lock()
	beforeServeHook := s.beforeServeHook
	s.lifecycleMu.Unlock()
	if beforeServeHook != nil {
		beforeServeHook()
	}

	var serveDone chan struct{}
	var serveResult chan error
	s.lifecycleMu.Lock()
	sameGeneration = generation == s.lifecycleGeneration
	shutdownRequested = sameGeneration && s.shutdownStarted
	ctxErr = ctx.Err()
	ownsLifecycle := sameGeneration && s.httpServer == httpServer && s.listener == listener
	if !ownsLifecycle || shutdownRequested || ctxErr != nil {
		s.lifecycleMu.Unlock()
		_ = listener.Close()
		if sameGeneration {
			s.completeLifecycle(generation, nil)
		}
		if ctxErr != nil && !shutdownRequested {
			return ctxErr
		}
		return nil
	}

	// Keep readiness and the handoff to Serve in one lifecycle-owned transition.
	s.SetReady(true)
	serveDone = make(chan struct{})
	serveResult = make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout())
			_ = s.shutdownForGeneration(shutdownCtx, generation)
			cancel()
		case <-serveDone:
		}
	}()
	go func() {
		serveResult <- httpServer.Serve(listener)
	}()
	s.lifecycleMu.Unlock()

	log.Printf("SRE Dashboard and API running on http://0.0.0.0:%d", s.port)

	err = <-serveResult
	close(serveDone)
	s.lifecycleMu.Lock()
	sameGeneration = generation == s.lifecycleGeneration
	shutdownRequested = sameGeneration && s.shutdownStarted
	s.lifecycleMu.Unlock()
	if !sameGeneration {
		trackedHandler.stop()
		_ = httpServer.Close()
		_ = trackedHandler.wait(context.Background())
		_ = listener.Close()
		return nil
	}
	trackedHandler.stop()
	if !shutdownRequested {
		_ = httpServer.Close()
	}
	_ = trackedHandler.wait(context.Background())
	if errors.Is(err, http.ErrServerClosed) {
		s.completeLifecycle(generation, nil)
		return nil
	}
	if shutdownRequested {
		if errors.Is(err, net.ErrClosed) {
			s.SetReady(false)
			s.completeLifecycle(generation, nil)
			return nil
		}
	}
	s.completeLifecycle(generation, err)
	return err
}

func (s *Server) acquireStartSlot(ctx context.Context) (chan struct{}, bool) {
	s.lifecycleMu.Lock()
	if s.startSlot == nil {
		s.startSlot = make(chan struct{}, 1)
		s.startSlot <- struct{}{}
	}
	startSlot := s.startSlot
	s.lifecycleMu.Unlock()

	select {
	case <-startSlot:
		return startSlot, true
	case <-ctx.Done():
		return startSlot, false
	}
}

func (s *Server) releaseStartSlot(startSlot chan struct{}) {
	startSlot <- struct{}{}
}

func (s *Server) finishPendingStartup() {
	s.lifecycleMu.Lock()
	if !s.startupPending {
		s.lifecycleMu.Unlock()
		return
	}
	s.startupPending = false
	s.startupCancelled = false
	done := s.startupDone
	s.startupDone = nil
	if done != nil {
		close(done)
	}
	s.lifecycleMu.Unlock()
}

func (s *Server) completeLifecycle(generation uint64, err error) {
	s.lifecycleMu.Lock()
	if generation != s.lifecycleGeneration || s.shutdownComplete {
		s.lifecycleMu.Unlock()
		return
	}
	if err != nil || s.shutdownErr == nil {
		s.shutdownErr = err
	}
	s.shutdownComplete = true
	s.started = false
	s.serveStarted = false
	listener := s.listener
	s.listener = nil
	tracker := s.requestTracker
	s.requestTracker = nil
	s.httpServer = nil
	if s.shutdownDone != nil {
		close(s.shutdownDone)
	}
	s.lifecycleMu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if tracker != nil {
		tracker.stop()
	}
	s.SetReady(false)
}

func (s *Server) waitForLifecycle(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
	default:
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	s.lifecycleMu.Lock()
	err := s.shutdownErr
	s.lifecycleMu.Unlock()
	return err
}

func (s *Server) newHandler() (http.Handler, error) {
	if err := s.startupValidationError(); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()

	// Public health endpoints are intentionally registered separately from the API.
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)

	// REST API Endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/metrics/status", s.handleStatus)
	mux.HandleFunc("/api/issues", s.handleListIssues)
	mux.HandleFunc("/api/proposals", s.handleListProposals)
	mux.HandleFunc("/api/proposals/", s.handleProposalAction)
	mux.HandleFunc("/api/audit", s.handleAudit)
	mux.HandleFunc("/api/scan", s.handleTriggerScan)
	mux.HandleFunc("/api/analyzers", s.handleListAnalyzers)
	mux.HandleFunc("/api/clean/pods", s.handleCleanPods)
	mux.HandleFunc("/api/chat", s.handleChat)
	mux.HandleFunc("/api/chat/sessions", s.handleChatSessions)
	mux.HandleFunc("/api/chat/sessions/", s.handleChatSessionAction)
	mux.HandleFunc("/api/notify/test", s.handleTestNotification)
	mux.HandleFunc("/api/config", s.handleConfig)

	// Versioned compatibility endpoints reuse the same authenticated boundary.
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/playbooks", s.handlePlaybookList)
	mux.HandleFunc("/api/v1/playbooks/status", s.handlePlaybookStatus)
	mux.HandleFunc("/api/v1/playbooks/settings", s.handlePlaybookSettings)
	mux.HandleFunc("/api/v1/playbooks/import", s.handlePlaybookImport)
	mux.HandleFunc("/api/v1/playbooks/", s.handlePlaybookTransition)
	mux.HandleFunc("/api/v1/issues", s.handleListIssues)
	mux.HandleFunc("/api/v1/analyzers", s.handleListAnalyzers)
	mux.HandleFunc("/api/v1/scan", s.handleValidatedVersionedScan)
	mux.HandleFunc("/api/v1/history", s.handleScanHistory)
	mux.HandleFunc("/api/v1/query", s.handleAllowlistedQueryResource)
	mux.HandleFunc("/api/v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("/api/v1/support-bundle", s.handleSupportBundle)
	mux.HandleFunc("/api/v1/chat/sessions", s.handleChatSessions)
	mux.HandleFunc("/api/v1/chat/sessions/", s.handleChatSessionAction)
	mux.Handle("/api/v1/mcp", s.newMCPHandler())
	mux.Handle("/metrics", promhttp.HandlerFor(s.metrics.Gatherer(), promhttp.HandlerOpts{}))

	// Embedded Static Assets
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("sub static fs: %w", err)
	}
	mux.HandleFunc("/static/index.html", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedHTML(w, r, "static/index.html")
	})
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page := "static/index.html"
		if s.authenticator.enabled {
			page = "static/bootstrap.html"
		}
		serveEmbeddedHTML(w, r, page)
	})

	return s.structuredAPIErrorMiddleware(s.boundaryMiddleware(mux)), nil
}

func (s *Server) structuredAPIErrorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/v1/mcp" {
			next.ServeHTTP(w, r)
			return
		}
		capture := &apiErrorCaptureWriter{ResponseWriter: w}
		next.ServeHTTP(capture, r)
		capture.finish(s)
	})
}

type apiErrorCaptureWriter struct {
	http.ResponseWriter
	status  int
	capture bool
	body    []byte
}

func (w *apiErrorCaptureWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	contentType := strings.ToLower(w.Header().Get("Content-Type"))
	w.capture = status >= 400 && strings.HasPrefix(contentType, "text/plain")
	if !w.capture {
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *apiErrorCaptureWriter) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if !w.capture {
		return w.ResponseWriter.Write(value)
	}
	const maxCapturedErrorBytes = 4096
	remaining := maxCapturedErrorBytes - len(w.body)
	if remaining > 0 {
		originalLength := len(value)
		if len(value) > remaining {
			value = value[:remaining]
		}
		w.body = append(w.body, value...)
		return originalLength, nil
	}
	return len(value), nil
}

func (w *apiErrorCaptureWriter) finish(s *Server) {
	if !w.capture {
		return
	}
	message := strings.TrimSpace(string(w.body))
	if message == "" {
		message = "request failed"
	}
	s.writeError(w.ResponseWriter, w.status, message)
}

func (s *Server) startupValidationError() error {
	if s.requireAPIToken && !s.authenticator.enabled {
		return errors.New("API token is required")
	}
	return nil
}

func serveEmbeddedHTML(w http.ResponseWriter, r *http.Request, page string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	content, err := staticFS.ReadFile(page)
	if err != nil {
		http.Error(w, "dashboard page not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(content)
	}
}

func (s *Server) UpdateScanResults(issues []*scanner.Issue) {
	snapshot := make([]*scanner.Issue, len(issues))
	copy(snapshot, issues)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastScan = time.Now()
	s.activeIssues = snapshot
	s.activeIssuesExplicit = false
}

// issueSnapshot uses reconciled history so targeted results cannot hide other
// active findings. Explicit overrides and injected scanners remain supported.
func (s *Server) issueSnapshot() []*scanner.Issue {
	s.mu.RLock()
	active := append([]*scanner.Issue(nil), s.activeIssues...)
	explicit := s.activeIssuesExplicit
	s.mu.RUnlock()
	if explicit || s.scanner == nil || s.scanner.History() == nil {
		return active
	}
	entries, err := s.scanner.History().List()
	if err != nil || len(entries) == 0 {
		return active
	}
	issues := make([]*scanner.Issue, 0, len(entries))
	for _, entry := range entries {
		if entry.Resolved || entry.Issue == nil {
			continue
		}
		issues = append(issues, entry.Issue.AsIssue())
	}
	return issues
}

func (s *Server) SetActiveIssues(issues []*scanner.Issue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastScan = time.Now()
	s.activeIssues = append([]*scanner.Issue(nil), issues...)
	s.activeIssuesExplicit = true
}

func (s *Server) SetReady(ready bool) {
	s.ready.Store(ready)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ready := s.ready.Load()
	if ready && s.readiness != nil {
		ready = s.readiness()
	}
	if !ready {
		http.Error(w, "not ready\n", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.shutdownForGeneration(ctx, 0)
}

func (s *Server) shutdownForGeneration(ctx context.Context, generation uint64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	if generation != 0 && generation != s.lifecycleGeneration {
		s.lifecycleMu.Unlock()
		return nil
	}
	if err := s.CloseMCP(); err != nil {
		s.lifecycleMu.Unlock()
		return err
	}
	if s.startupPending && !s.started {
		done := s.startupDone
		s.startupCancelled = true
		s.lifecycleMu.Unlock()
		s.SetReady(false)
		return waitForDone(ctx, done)
	}
	if s.shutdownStarted {
		done := s.shutdownDone
		s.lifecycleMu.Unlock()
		return s.waitForLifecycle(ctx, done)
	}
	if !s.started {
		if s.shutdownComplete {
			err := s.shutdownErr
			s.lifecycleMu.Unlock()
			s.SetReady(false)
			return err
		}
		s.lifecycleMu.Unlock()
		s.SetReady(false)
		return nil
	}
	s.shutdownStarted = true
	done := s.shutdownDone
	if done == nil {
		done = make(chan struct{})
		s.shutdownDone = done
	}
	httpServer := s.httpServer
	tracker := s.requestTracker
	serveStarted := s.serveStarted
	lifecycleGeneration := s.lifecycleGeneration
	s.lifecycleMu.Unlock()

	if httpServer == nil || !serveStarted {
		return s.waitForLifecycle(ctx, done)
	}

	if tracker != nil {
		tracker.stop()
	}
	s.SetReady(false)
	err := httpServer.Shutdown(ctx)
	if err != nil {
		_ = httpServer.Close()
		s.lifecycleMu.Lock()
		if lifecycleGeneration == s.lifecycleGeneration && !s.shutdownComplete {
			s.shutdownErr = err
		}
		s.lifecycleMu.Unlock()
		return err
	}
	if tracker != nil {
		_ = tracker.wait(context.Background())
	}
	s.completeLifecycle(lifecycleGeneration, nil)
	return err
}

func waitForDone(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
