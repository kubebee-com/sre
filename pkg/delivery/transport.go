package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"net"
	"net/http"
	"net/url"
	"time"
)

var ErrDelivery = errors.New("notification delivery unavailable")

func publicIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}
func ValidateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return ErrDelivery
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !publicIP(ip) {
		return ErrDelivery
	}
	return nil
}

type HTTPSender struct {
	client    *http.Client
	publicURL string
}

func NewHTTPSender(publicURL ...string) *HTTPSender {
	ui := ""
	if len(publicURL) == 1 {
		ui = publicURL[0]
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrDelivery
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, ErrDelivery
		}
		for _, candidate := range ips {
			if !publicIP(candidate.IP) {
				continue
			}
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, ErrDelivery
	}
	return &HTTPSender{publicURL: ui, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDelivery }}}
}
func (s *HTTPSender) Send(ctx context.Context, endpoint string, n incident.Notification) error {
	if ValidateEndpoint(endpoint) != nil || n.Scope.Validate() != nil || !identity.ValidID(n.ID) || !identity.ValidID(n.IncidentID) {
		return ErrDelivery
	}
	switch n.Kind {
	case "INCIDENT_CREATED", "INVESTIGATION_RECORDED", "ACTION_UPDATED", "CLAIM_CORROBORATED", "ADJUDICATION_RECORDED", "KNOWLEDGE_PUBLISHED", "RECOVERY_CHANGED", "CLARIFICATION_REQUESTED":
	default:
		return ErrDelivery
	}
	// Fixed projection: no event body, logs, claim prose, addresses or credentials.
	payload := struct {
		ID         string         `json:"id"`
		Scope      identity.Scope `json:"scope"`
		Kind       string         `json:"kind"`
		IncidentID string         `json:"incident_id"`
	}{n.ID, n.Scope, n.Kind, n.IncidentID}
	raw, _ := json.Marshal(payload)
	endpointURL, _ := url.Parse(endpoint)
	if endpointURL.Hostname() == "hooks.slack.com" {
		var err error
		raw, err = SlackPayload(s.publicURL, n)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if err != nil {
		return ErrDelivery
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", n.ID)
	response, err := s.client.Do(req)
	if err != nil {
		return ErrDelivery
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrDelivery
	}
	return nil
}
