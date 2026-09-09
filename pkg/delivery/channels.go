package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/kubebee-com/sre/pkg/incident"
)

// Channel selects a native, link-only notification adapter. Secrets are resolved
// from environment variables at validation and immediately before each send.
// WhatsApp templates must have four text body parameters, in order: event kind,
// incident ID, notification ID, authenticated SRE URL. Matrix requires a room ID
// in an unencrypted room; this adapter does not implement end-to-end encryption.
type Channel struct {
	Provider    string `json:"provider"`
	EndpointEnv string `json:"endpoint_env,omitempty"`
	TokenEnv    string `json:"token_env,omitempty"`
	Destination string `json:"destination,omitempty"`
	Template    string `json:"template,omitempty"`
	Language    string `json:"language,omitempty"`
}

var (
	channelEnv          = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	telegramToken       = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)
	telegramDestination = regexp.MustCompile(`^(?:-?[0-9]+|@[A-Za-z0-9_]{5,32})$`)
	whatsappEndpoint    = regexp.MustCompile(`^/v[0-9]+\.[0-9]+/[0-9]+/messages$`)
	whatsappDestination = regexp.MustCompile(`^[1-9][0-9]{6,14}$`)
	whatsappTemplate    = regexp.MustCompile(`^[a-z0-9_]{1,512}$`)
	whatsappLanguage    = regexp.MustCompile(`^[a-z]{2,3}(?:_[A-Z]{2})?$`)
)

// Validate checks both configuration and the current environment without sending.
func (c Channel) Validate() error { _, _, err := c.credentials(); return err }

func (c Channel) credentials() (string, string, error) {
	fail := func() (string, string, error) { return "", "", ErrDelivery }
	if c.Provider != "whatsapp" && (c.Template != "" || c.Language != "") {
		return fail()
	}
	token := ""
	switch c.Provider {
	case "telegram", "whatsapp", "matrix":
		if !channelEnv.MatchString(c.TokenEnv) {
			return fail()
		}
		token = os.Getenv(c.TokenEnv)
		if token == "" || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") {
			return fail()
		}
	default:
		if c.TokenEnv != "" || c.Destination != "" {
			return fail()
		}
	}
	if c.Provider == "telegram" {
		if c.EndpointEnv != "" || !telegramToken.MatchString(token) || !telegramDestination.MatchString(c.Destination) {
			return fail()
		}
		return "https://api.telegram.org/bot" + token + "/sendMessage", "", nil
	}
	if !channelEnv.MatchString(c.EndpointEnv) {
		return fail()
	}
	endpoint := os.Getenv(c.EndpointEnv)
	if ValidateEndpoint(endpoint) != nil {
		return fail()
	}
	u, _ := url.Parse(endpoint)
	host := u.Hostname()
	switch c.Provider {
	case "slack":
		if host != "hooks.slack.com" || !validPathSegments(u.Path, 4) || !strings.HasPrefix(u.Path, "/services/") || u.RawQuery != "" {
			return fail()
		}
	case "teams":
		if !(strings.HasSuffix(host, ".logic.azure.com") || strings.HasSuffix(host, ".environment.api.powerplatform.com")) || !strings.HasSuffix(u.Path, "/invoke") || u.Query().Get("sig") == "" {
			return fail()
		}
	case "discord":
		if host != "discord.com" || !validPathSegments(u.Path, 4) || !strings.HasPrefix(u.Path, "/api/webhooks/") {
			return fail()
		}
		q := u.Query()
		q.Set("wait", "true")
		u.RawQuery = q.Encode()
		endpoint = u.String()
	case "google_chat":
		if host != "chat.googleapis.com" || !strings.HasPrefix(u.Path, "/v1/spaces/") || !strings.HasSuffix(u.Path, "/messages") || u.Query().Get("key") == "" || u.Query().Get("token") == "" {
			return fail()
		}
	case "whatsapp":
		if host != "graph.facebook.com" || !whatsappEndpoint.MatchString(u.Path) || u.RawQuery != "" || !whatsappDestination.MatchString(c.Destination) || !whatsappTemplate.MatchString(c.Template) || !whatsappLanguage.MatchString(c.Language) {
			return fail()
		}
	case "matrix":
		if u.RawQuery != "" || (u.Path != "" && u.Path != "/") || !strings.HasPrefix(c.Destination, "!") || !strings.Contains(c.Destination, ":") || len(c.Destination) > 255 || strings.ContainsAny(c.Destination, " \t\r\n/?#") {
			return fail()
		}
	default:
		return fail()
	}
	return endpoint, token, nil
}

func validPathSegments(path string, expected int) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segments) != expected {
		return false
	}
	for _, segment := range segments {
		if segment == "" {
			return false
		}
	}
	return true
}

// SendChannel uses the same bounded, public-address-only transport as Send.
// Provider response bodies and credential-bearing request URLs never escape in errors.
func (s *HTTPSender) SendChannel(ctx context.Context, c Channel, n incident.Notification) error {
	endpoint, token, err := c.credentials()
	if err != nil {
		return ErrDelivery
	}
	raw, err := SlackPayload(s.publicURL, n)
	if err != nil {
		return ErrDelivery
	}
	// SlackPayload is the common validation gate for the fixed event projection.
	// Build the same authenticated link for providers with other wire formats.
	q := url.Values{"organization_id": {n.Scope.OrganizationID}, "cluster_id": {n.Scope.ClusterID}, "application_id": {n.Scope.ApplicationID}, "incident_id": {n.IncidentID}}
	link := strings.TrimRight(s.publicURL, "/") + "/?" + q.Encode()
	summary := "SRE " + n.Kind + " · incident " + n.IncidentID + " · notification " + n.ID
	text := summary + "\n" + link
	var payload any
	method := http.MethodPost
	switch c.Provider {
	case "teams":
		payload = map[string]any{"type": "message", "attachments": []any{map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": nil, "content": map[string]any{"type": "AdaptiveCard", "version": "1.2", "body": []any{map[string]any{"type": "TextBlock", "text": summary, "wrap": true}}, "actions": []any{map[string]any{"type": "Action.OpenUrl", "title": "Open authenticated SRE", "url": link}}}}}}
	case "discord":
		payload = map[string]any{"content": text, "allowed_mentions": map[string]any{"parse": []string{}}}
	case "telegram":
		payload = map[string]any{"chat_id": c.Destination, "text": text, "link_preview_options": map[string]bool{"is_disabled": true}}
	case "google_chat":
		payload = map[string]string{"text": text}
	case "whatsapp":
		params := []any{}
		for _, value := range []string{n.Kind, n.IncidentID, n.ID, link} {
			params = append(params, map[string]string{"type": "text", "text": value})
		}
		payload = map[string]any{"messaging_product": "whatsapp", "to": c.Destination, "type": "template", "template": map[string]any{"name": c.Template, "language": map[string]string{"code": c.Language}, "components": []any{map[string]any{"type": "body", "parameters": params}}}}
	case "matrix":
		method = http.MethodPut
		endpoint = strings.TrimRight(endpoint, "/") + "/_matrix/client/v3/rooms/" + url.PathEscape(c.Destination) + "/send/m.room.message/" + url.PathEscape(n.ID)
		payload = map[string]string{"msgtype": "m.text", "body": text}
	}
	if payload != nil {
		raw, _ = json.Marshal(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return ErrDelivery
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", n.ID)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := s.client.Do(req)
	if err != nil {
		return ErrDelivery
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrDelivery
	}
	if c.Provider == "telegram" {
		var result struct {
			OK bool `json:"ok"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) != nil || !result.OK {
			return ErrDelivery
		}
	}
	return nil
}
