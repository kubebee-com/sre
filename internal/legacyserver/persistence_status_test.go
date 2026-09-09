package legacyserver

import (
	"github.com/kubebee-com/sre/pkg/remediation"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProposalReadFailureIsUnavailable(t *testing.T) {
	store := remediation.NewMemoryProposalStore()
	engine := remediation.NewEngineWithOptions(nil, remediation.EngineOptions{Store: store})
	defer engine.Close()
	server := NewServer(0, nil, nil, engine, nil)
	store.Close()
	for _, handler := range []http.HandlerFunc{server.handleListProposals, server.handleStatus} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("got %d: %s", response.Code, response.Body.String())
		}
	}
}
