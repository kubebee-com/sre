package falco

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const MaxWebhookPayloadBytes = 1024 * 1024 // 1 MB limit for webhook payloads

var (
	ErrUnauthorized    = errors.New("invalid or missing webhook authentication token")
	ErrPayloadTooLarge = errors.New("webhook payload exceeds maximum permitted size")
	ErrInvalidJSON     = errors.New("invalid JSON payload")
)

func AuthenticateRequest(r *http.Request, expectedToken string) bool {
	if expectedToken == "" {
		// When no secret is configured, permit requests (e.g. in-cluster webhook forwarding)
		return true
	}

	token := r.Header.Get("X-Falco-Token")
	if token == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			token = strings.TrimSpace(auth[7:])
		}
	}
	if token == "" {
		token = r.URL.Query().Get("token")
	}

	if token == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1
}

// ParseWebhookPayload reads, limits, parses, and sanitizes Falco events from an HTTP request.
func ParseWebhookPayload(w http.ResponseWriter, r *http.Request, secretToken string) ([]*Event, error) {
	if !AuthenticateRequest(r, secretToken) {
		return nil, ErrUnauthorized
	}

	// Bound incoming payload size to protect against memory exhaustion
	limitedReader := http.MaxBytesReader(w, r.Body, MaxWebhookPayloadBytes)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, ErrPayloadTooLarge
		}
		return nil, err
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, ErrInvalidJSON
	}

	var rawEvents []*Event
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &rawEvents); err != nil {
			return nil, ErrInvalidJSON
		}
	} else {
		var single Event
		if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
			return nil, ErrInvalidJSON
		}
		rawEvents = []*Event{&single}
	}

	sanitizedEvents := make([]*Event, 0, len(rawEvents))
	for _, ev := range rawEvents {
		if ev != nil {
			sanitizedEvents = append(sanitizedEvents, SanitizeEvent(ev))
		}
	}

	return sanitizedEvents, nil
}
