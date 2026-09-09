package legacyserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	localActor           = "local-development"
	authenticatedActor   = "api-token"
	maxTrackedClients    = 1024
	clientIdleEvictAfter = 10 * time.Minute
)

type actorContextKey struct{}

type tokenAuthenticator struct {
	hash    [sha256.Size]byte
	enabled bool
}

func newTokenAuthenticator(token string) *tokenAuthenticator {
	token = strings.TrimSpace(token)
	auth := &tokenAuthenticator{}
	if token == "" {
		return auth
	}

	auth.hash = sha256.Sum256([]byte(token))
	auth.enabled = true
	return auth
}

func (a *tokenAuthenticator) authenticate(r *http.Request) (string, bool) {
	if !a.enabled {
		return localActor, true
	}

	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}

	presentedHash := sha256.Sum256([]byte(parts[1]))
	if subtle.ConstantTimeCompare(presentedHash[:], a.hash[:]) != 1 {
		return "", false
	}

	return authenticatedActor, true
}

func actorWithContext(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

func actorFromContext(ctx context.Context) string {
	actor, _ := ctx.Value(actorContextKey{}).(string)
	return actor
}

type clientLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	clients map[string]*clientLimiterEntry
}

type clientLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newClientLimiter(requestsPerMinute, requestBurst int) *clientLimiter {
	return &clientLimiter{
		limit:   rate.Limit(float64(requestsPerMinute) / 60),
		burst:   requestBurst,
		clients: make(map[string]*clientLimiterEntry),
	}
}

func (l *clientLimiter) allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for key, entry := range l.clients {
		if now.Sub(entry.lastSeen) >= clientIdleEvictAfter {
			delete(l.clients, key)
		}
	}

	entry, ok := l.clients[client]
	if !ok {
		if len(l.clients) >= maxTrackedClients {
			l.evictOldest()
		}
		entry = &clientLimiterEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.clients[client] = entry
	}
	entry.lastSeen = now
	return entry.limiter.Allow()
}

func (l *clientLimiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range l.clients {
		if oldestKey == "" || entry.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = entry.lastSeen
		}
	}
	if oldestKey != "" {
		delete(l.clients, oldestKey)
	}
}

func remoteClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func (s *Server) clientKey(r *http.Request) string {
	if header := strings.TrimSpace(s.trustedClientIPHeader); header != "" && s.isTrustedProxy(r) {
		forwarded := strings.TrimSpace(r.Header.Get(header))
		if comma := strings.IndexByte(forwarded, ','); comma >= 0 {
			forwarded = strings.TrimSpace(forwarded[:comma])
		}
		if forwarded != "" {
			if host, _, err := net.SplitHostPort(forwarded); err == nil && host != "" {
				forwarded = host
			}
			return "forwarded:" + forwarded
		}
	}
	return "remote:" + remoteClientKey(r)
}

func (s *Server) isTrustedProxy(r *http.Request) bool {
	host := r.RemoteAddr
	if parsedHost, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = parsedHost
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, network := range s.trustedProxyNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseTrustedProxyCIDRs(values []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(strings.TrimSpace(value))
		if err == nil {
			networks = append(networks, network)
		}
	}
	return networks
}

func (s *Server) boundaryMiddleware(next http.Handler) http.Handler {
	handler := s.rateLimitMiddleware(next)
	handler = s.authMiddleware(handler)
	handler = rejectLegacyIdentityMiddleware(handler)
	handler = s.bodyLimitMiddleware(handler)
	return s.corsMiddleware(handler)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		actor, ok := s.authenticator.authenticate(r)
		if !ok {
			if s.authFailureLimiter != nil && !s.authFailureLimiter.allow("remote:"+remoteClientKey(r)) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "authentication rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(actorWithContext(r.Context(), actor)))
	})
}

func isPublicEndpoint(path string) bool {
	return path == "/" || path == "/healthz" || path == "/readyz"
}

func rejectLegacyIdentityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasLegacyIdentityHeader(r) {
			writeError(w, http.StatusBadRequest, "caller-controlled identity headers are not accepted")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > s.maxBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := actorFromContext(r.Context())
		if actor == "" {
			actor = "public"
		}
		if !s.limiter.allow(actor + "|" + s.clientKey(r)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowOrigin := s.allowedOriginHeader(origin)
		if origin != "" {
			w.Header().Add("Vary", "Origin")
		}
		if allowOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}

		if r.Method == http.MethodOptions && origin != "" {
			if allowOrigin == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if hasLegacyIdentityHeader(r) {
				writeError(w, http.StatusBadRequest, "caller-controlled identity headers are not accepted")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func hasLegacyIdentityHeader(r *http.Request) bool {
	return len(r.Header.Values("X-User-Email")) > 0
}

func (s *Server) allowedOriginHeader(origin string) string {
	if origin == "" {
		return ""
	}
	if origin == "*" && s.authenticator.enabled {
		return ""
	}
	if _, ok := s.allowedOrigins[origin]; ok {
		return origin
	}
	if _, wildcardConfigured := s.allowedOrigins["*"]; wildcardConfigured && !s.authenticator.enabled {
		return "*"
	}
	return ""
}

func defaultServerLimits() (int64, int, int) {
	return 1 << 20, 600, 20
}

func defaultShutdownTimeout() time.Duration {
	return 5 * time.Second
}
