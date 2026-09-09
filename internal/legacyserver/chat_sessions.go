package legacyserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

const chatSchemaVersion = "chat/v1"

type chatSessionCreateRequest struct {
	IssueID string `json:"issue_id,omitempty"`
}

type chatMessageRequest struct {
	Message string `json:"message"`
}

type chatQueryRequest struct {
	Tool    string                      `json:"tool"`
	Request triage.ReadOnlyQueryRequest `json:"request"`
}

type chatSessionResponse struct {
	SchemaVersion string              `json:"schema_version"`
	Session       *triage.ChatSession `json:"session,omitempty"`
}

type chatReplyResponse struct {
	SchemaVersion string `json:"schema_version"`
	SessionID     string `json:"session_id"`
	Reply         string `json:"reply"`
}

func (s *Server) handleChatSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	if s.chatSessions == nil {
		s.writeError(w, http.StatusServiceUnavailable, "chat sessions are unavailable")
		return
	}
	var request chatSessionCreateRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	var issue *scanner.Issue
	if issueID := strings.TrimSpace(request.IssueID); issueID != "" {
		for _, candidate := range s.issueSnapshot() {
			if candidate != nil && candidate.ID == issueID {
				issue = candidate
				break
			}
		}
		if issue == nil {
			s.writeError(w, http.StatusNotFound, "issue was not found")
			return
		}
	}
	session, err := s.chatSessions.Create(r.Context(), requestActor(s, r), issue)
	if err != nil {
		s.writeChatError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, chatSessionResponse{SchemaVersion: chatSchemaVersion, Session: session})
}

func (s *Server) handleChatSessionAction(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/chat/sessions/"
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/v1/chat/sessions/") {
		path = "/api" + strings.TrimPrefix(path, "/api/v1")
	}
	if !strings.HasPrefix(path, prefix) {
		s.writeError(w, http.StatusNotFound, "chat session was not found")
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) == 0 || parts[0] == "" || len(parts) > 2 || (len(parts) == 2 && parts[1] == "") {
		s.writeError(w, http.StatusNotFound, "chat session was not found")
		return
	}
	sessionID := parts[0]
	if len(parts) == 1 {
		s.handleChatSession(w, r, sessionID)
		return
	}
	switch parts[1] {
	case "messages":
		s.handleChatSessionMessage(w, r, sessionID)
	case "query":
		s.handleChatSessionQuery(w, r, sessionID)
	default:
		s.writeError(w, http.StatusNotFound, "chat session action was not found")
	}
}

func (s *Server) handleChatSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	if s.chatSessions == nil {
		s.writeError(w, http.StatusServiceUnavailable, "chat sessions are unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		session, err := s.chatSessions.Get(r.Context(), requestActor(s, r), sessionID)
		if err != nil {
			s.writeChatError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, chatSessionResponse{SchemaVersion: chatSchemaVersion, Session: session})
	case http.MethodDelete:
		if err := s.chatSessions.Close(r.Context(), requestActor(s, r), sessionID); err != nil {
			s.writeChatError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]string{"schema_version": chatSchemaVersion, "status": "closed"})
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleChatSessionMessage(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	if s.chatSessions == nil {
		s.writeError(w, http.StatusServiceUnavailable, "chat sessions are unavailable")
		return
	}
	var request chatMessageRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	reply, err := s.chatSessions.Send(r.Context(), requestActor(s, r), sessionID, request.Message)
	if err != nil {
		s.writeChatError(w, err)
		return
	}
	s.recordTokenUsage(request.Message, reply)
	s.writeJSON(w, http.StatusOK, chatReplyResponse{SchemaVersion: chatSchemaVersion, SessionID: sessionID, Reply: reply})
}

func (s *Server) handleChatSessionQuery(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	if s.chatSessions == nil {
		s.writeError(w, http.StatusServiceUnavailable, "chat sessions are unavailable")
		return
	}
	var request chatQueryRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := s.chatSessions.Query(r.Context(), requestActor(s, r), sessionID, strings.TrimSpace(request.Tool), request.Request)
	if err != nil {
		s.writeChatError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"schema_version": chatSchemaVersion,
		"session_id":     sessionID,
		"result":         result,
	})
}

func (s *Server) writeChatError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "chat request failed"
	var chatErr *triage.ChatError
	switch {
	case errors.As(err, &chatErr):
		switch chatErr.Kind {
		case triage.ChatErrorInvalid:
			status = http.StatusBadRequest
		case triage.ChatErrorUnauthorized:
			status = http.StatusUnauthorized
		case triage.ChatErrorNotFound:
			status = http.StatusNotFound
		case triage.ChatErrorExpired:
			status = http.StatusGone
		case triage.ChatErrorLimit:
			status = http.StatusTooManyRequests
		case triage.ChatErrorTool:
			status = http.StatusForbidden
		case triage.ChatErrorProvider:
			status = http.StatusBadGateway
		}
		message = chatErr.Error()
	case errors.Is(err, context.Canceled):
		status = http.StatusRequestTimeout
		message = "chat request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
		message = "chat request timed out"
	}
	s.writeError(w, status, message)
}

type scannerReadOnlyTool struct {
	scanner  Scanner
	redactor *sanitizer.Redactor
}

func (t scannerReadOnlyTool) Name() string { return "resource.get" }

func (t scannerReadOnlyTool) Query(ctx context.Context, request triage.ReadOnlyQueryRequest) (triage.ReadOnlyQueryResult, error) {
	if t.scanner == nil || strings.TrimSpace(request.LabelSelector) != "" || strings.TrimSpace(request.FieldSelector) != "" {
		return triage.ReadOnlyQueryResult{}, triage.ErrChatInvalidRequest
	}
	if err := validateServerQueryableKind(request.Resource); err != nil {
		return triage.ReadOnlyQueryResult{}, triage.ErrChatInvalidRequest
	}
	if strings.TrimSpace(request.Name) == "" || strings.ContainsAny(request.Resource+request.Namespace+request.Name, "\x00\r\n") {
		return triage.ReadOnlyQueryResult{}, triage.ErrChatInvalidRequest
	}
	resource, err := t.scanner.QueryResource(ctx, request.Resource, request.Namespace, request.Name)
	if err != nil {
		return triage.ReadOnlyQueryResult{}, err
	}
	// Convert typed client-go objects to JSON-shaped data so the session manager
	// can apply field-aware redaction before the result reaches a provider.
	safeResource, err := scanner.SanitizeResourceForKind(request.Resource, resource, t.redactor)
	if err != nil {
		return triage.ReadOnlyQueryResult{}, err
	}
	encoded, err := json.Marshal(safeResource)
	if err != nil {
		return triage.ReadOnlyQueryResult{}, err
	}
	var data interface{}
	if err := json.Unmarshal(encoded, &data); err != nil {
		return triage.ReadOnlyQueryResult{}, err
	}
	return triage.ReadOnlyQueryResult{Resource: request.Resource, Namespace: request.Namespace, Name: request.Name, Data: data}, nil
}
