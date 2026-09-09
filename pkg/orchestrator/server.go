// Package orchestrator exposes the scoped control plane without cluster credentials.
package orchestrator

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/delivery"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/feedback"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/messaging"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"golang.org/x/oauth2"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed static/index.html static/app.js static/style.css static/orchestrator.js
var assets embed.FS

type Verifier interface {
	Verify(context.Context, string) (identity.Principal, error)
}
type Config struct {
	Messaging      []messaging.Config
	AuthStore      AuthStore
	Queue          *investigation.Queue
	Notifications  *delivery.Service
	Execution      *execution.Service
	Fleet          *fleet.Service
	OAuth          *oauth2.Config
	AuthHTTPClient *http.Client
	DB             *postgres.Store
	Policy         *authorization.Policy
	Verifier       Verifier
	Investigations *investigation.Service
	PublicURL      string
}
type Server struct {
	requests   chan struct{}
	authMu     sync.Mutex
	challenges map[string]challenge
	sessions   map[string]browserSession
	config     Config
	handler    http.Handler
	feedback   *feedback.Service
}
type principalKey struct{}

func New(config Config) (*Server, error) {
	parsed, err := url.Parse(config.PublicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.Fragment != "" || config.DB == nil || config.Policy == nil || config.Verifier == nil {
		return nil, errors.New("database, verified identity, policy and HTTPS public URL required")
	}
	if config.OAuth != nil {
		if config.OAuth.RedirectURL != strings.TrimRight(config.PublicURL, "/")+"/auth/callback" {
			return nil, errors.New("OIDC callback must match public origin")
		}
		for _, endpoint := range []string{config.OAuth.Endpoint.AuthURL, config.OAuth.Endpoint.TokenURL} {
			u, err := url.Parse(endpoint)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
				return nil, errors.New("HTTPS identity endpoints required")
			}
		}
	}
	s := &Server{requests: make(chan struct{}, 64), config: config, feedback: &feedback.Service{DB: config.DB, Policy: config.Policy}}
	s.initAuth()
	mux := http.NewServeMux()
	channels, err := messaging.New(config.Messaging, s.messagingCommand)
	if err != nil {
		return nil, err
	}
	mux.Handle("/channels/", channels)
	s.registerInteractionRoutes(mux)
	mux.HandleFunc("POST /agent/diagnostics/claim", s.agentDiagnosticClaim)
	mux.HandleFunc("POST /agent/diagnostics/{job}/heartbeat", s.agentDiagnosticHeartbeat)
	mux.HandleFunc("POST /agent/diagnostics/{job}/refresh", s.agentDiagnosticRefresh)
	mux.HandleFunc("POST /agent/diagnostics/{job}/complete", s.agentDiagnosticComplete)
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if config.DB.Ready(ctx) != nil {
			writeError(w, 503, "storage unavailable")
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /api/incidents/{incident}/jobs", s.diagnosticJobs)
	mux.HandleFunc("POST /api/jobs/{job}/cancel", s.cancelDiagnosticJob)
	mux.HandleFunc("GET /api/notifications", s.notifications)
	mux.HandleFunc("POST /api/notifications/{notification}/acknowledge", s.acknowledgeNotification)
	mux.HandleFunc("POST /api/adjudications", s.adjudicate)
	mux.HandleFunc("GET /api/items/{item}/adjudications", s.adjudications)
	mux.HandleFunc("POST /api/corroborations", s.corroborate)
	mux.HandleFunc("GET /api/golden-cases", s.goldenCases)
	mux.HandleFunc("POST /api/golden-cases", s.candidate)
	mux.HandleFunc("POST /api/golden-cases/{case}/review", s.reviewGolden)
	mux.HandleFunc("GET /api/quality", s.qualityMetrics)
	mux.HandleFunc("GET /api/operations", s.operations)
	mux.HandleFunc("GET /api/environment", s.getEnvironment)
	mux.HandleFunc("POST /api/environment", s.setEnvironment)
	mux.HandleFunc("POST /api/recovery-profile", s.setRecoveryProfile)
	mux.HandleFunc("GET /api/recovery-profile", s.getRecoveryProfile)
	mux.HandleFunc("POST /api/incidents/{incident}/recovery", s.assessRecovery)
	mux.HandleFunc("POST /api/incidents/{incident}/close", s.closeIncident)
	mux.HandleFunc("GET /api/actions", s.listActions)
	mux.HandleFunc("POST /api/actions", s.proposeAction)
	mux.HandleFunc("POST /api/actions/{action}/approve", s.approveAction)
	mux.HandleFunc("POST /api/actions/{action}/cancel", s.cancelAction)
	mux.HandleFunc("POST /api/actions/{action}/reconcile", s.reconcileAction)
	mux.HandleFunc("GET /agent/actions", s.executorActions)
	mux.HandleFunc("POST /agent/actions/{action}/claim", s.claimAction)
	mux.HandleFunc("POST /agent/actions/{action}/receipt", s.actionReceipt)
	mux.HandleFunc("GET /api/capabilities", s.capabilities)
	mux.HandleFunc("GET /api/setup-scopes", s.setupScopes)
	mux.HandleFunc("GET /api/agents", s.listAgents)
	mux.HandleFunc("POST /api/agents/bootstrap", s.bootstrap)
	mux.HandleFunc("POST /api/agents/{agent}/revoke", s.revokeAgent)
	mux.HandleFunc("POST /agent/enroll", s.enroll)
	mux.HandleFunc("POST /agent/renew", s.renewAgent)
	mux.HandleFunc("POST /agent/checks", s.collectionChecks)
	mux.HandleFunc("POST /agent/reports", s.collectReport)
	mux.HandleFunc("GET /api/scopes", s.scopes)
	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("GET /api/incidents", s.incidents)
	mux.HandleFunc("GET /api/incidents/{incident}/items", s.items)
	mux.HandleFunc("GET /api/profiles", s.profiles)
	mux.HandleFunc("POST /api/incidents/{incident}/investigate", s.investigate)
	mux.HandleFunc("POST /api/incidents/{incident}/feedback", s.submitFeedback)
	mux.HandleFunc("GET /api/incidents/{incident}/items/{item}/feedback", s.feedbackHistory)
	files, _ := fs.Sub(assets, "static")
	static := http.FileServer(http.FS(files))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
	s.handler = mux
	return s, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case s.requests <- struct{}{}:
		defer func() { <-s.requests }()
	default:
		writeError(w, 503, "request capacity reached")
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if origin := r.Header.Get("Origin"); origin != "" && origin != strings.TrimRight(s.config.PublicURL, "/") {
		writeError(w, 403, "origin denied")
		return
	}
	for _, header := range []string{"X-User-Email", "X-User", "X-Actor", "X-Remote-User", "X-Authenticated-User"} {
		if r.Header.Get(header) != "" {
			writeError(w, 400, "asserted caller identity is not accepted")
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		p, csrf, err := s.authenticate(r)
		if err != nil {
			writeError(w, 401, "sign in required")
			return
		}
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), principalKey{}, p), csrfKey{}, csrf))
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	s.handler.ServeHTTP(w, r)
}
func principal(r *http.Request) identity.Principal {
	p, _ := r.Context().Value(principalKey{}).(identity.Principal)
	return p
}
func (s *Server) scope(r *http.Request, permission authorization.Permission) (identity.Scope, error) {
	q := r.URL.Query()
	scope := identity.Scope{OrganizationID: q.Get("organization_id"), ClusterID: q.Get("cluster_id"), ApplicationID: q.Get("application_id")}
	if err := scope.Validate(); err != nil {
		return scope, authorization.ErrForbidden
	}
	return scope, s.config.Policy.Authorize(principal(r), scope, permission)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 2<<20 {
		writeError(w, 503, "response unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(encoded)
}
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func respondError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authorization.ErrForbidden):
		writeError(w, 403, "application permission required")
	case errors.Is(err, postgres.ErrNotFound):
		writeError(w, 404, "record not found")
	case errors.Is(err, postgres.ErrConflict):
		writeError(w, 409, "state changed; refresh before retrying")
	case errors.Is(err, postgres.ErrInvalid):
		writeError(w, 400, "invalid request")
	case errors.Is(err, investigation.ErrBusy):
		writeError(w, 429, "investigation capacity reached; retry later")
	default:
		writeError(w, 503, "service unavailable")
	}
}
