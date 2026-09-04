package server

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	port         int
	scanner      *scanner.ClusterScanner
	triage       triage.TriageProvider
	engine       *remediation.Engine
	notifier     *notifier.WebhookNotifier
	lastScan     time.Time
	activeIssues []*scanner.Issue
	mu           sync.RWMutex
	httpServer   *http.Server
}

func NewServer(
	port int,
	scanner *scanner.ClusterScanner,
	triage triage.TriageProvider,
	engine *remediation.Engine,
	notifier *notifier.WebhookNotifier,
) *Server {
	return &Server{
		port:     port,
		scanner:  scanner,
		triage:   triage,
		engine:   engine,
		notifier: notifier,
	}
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// REST API Endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/issues", s.handleListIssues)
	mux.HandleFunc("/api/proposals", s.handleListProposals)
	mux.HandleFunc("/api/proposals/", s.handleProposalAction)
	mux.HandleFunc("/api/scan", s.handleTriggerScan)
	mux.HandleFunc("/api/analyzers", s.handleListAnalyzers)
	mux.HandleFunc("/api/clean/pods", s.handleCleanPods)
	mux.HandleFunc("/api/chat", s.handleChat)
	mux.HandleFunc("/api/notify/test", s.handleTestNotification)
	mux.HandleFunc("/api/config", s.handleConfig)

	// Embedded Static Assets
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("sub static fs: %w", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		indexHTML, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: corsMiddleware(mux),
	}

	log.Printf("SRE Dashboard and API running on http://0.0.0.0:%d", s.port)
	return s.httpServer.ListenAndServe()
}

func (s *Server) UpdateScanResults(issues []*scanner.Issue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastScan = time.Now()
	s.activeIssues = issues
}

func (s *Server) SetActiveIssues(issues []*scanner.Issue) {
	s.UpdateScanResults(issues)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
