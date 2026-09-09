package delivery

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"net/url"
	"strings"
)

// SlackPayload is an outgoing adapter for the durable notification service.
// Without a verified workspace/user-to-principal binding Slack remains link-only:
// the authenticated central UI performs all answers, acknowledgements and approvals.
func SlackPayload(publicURL string, n incident.Notification) ([]byte, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || n.Scope.Validate() != nil || !identity.ValidID(n.ID) || !identity.ValidID(n.IncidentID) {
		return nil, ErrDelivery
	}
	switch n.Kind {
	case "INCIDENT_CREATED", "INVESTIGATION_RECORDED", "ACTION_UPDATED", "CLAIM_CORROBORATED", "ADJUDICATION_RECORDED", "KNOWLEDGE_PUBLISHED", "RECOVERY_CHANGED", "CLARIFICATION_REQUESTED":
	default:
		return nil, ErrDelivery
	}
	q := url.Values{"organization_id": {n.Scope.OrganizationID}, "cluster_id": {n.Scope.ClusterID}, "application_id": {n.Scope.ApplicationID}, "incident_id": {n.IncidentID}}
	link := strings.TrimRight(publicURL, "/") + "/?" + q.Encode()
	// Plain text avoids interpreting scope identifiers as Slack mention markup.
	return json.Marshal(map[string]any{"text": "SRE notification: " + n.Kind, "unfurl_links": false, "unfurl_media": false, "blocks": []any{map[string]any{"type": "section", "text": map[string]string{"type": "plain_text", "text": "SRE " + n.Kind + " · incident " + n.IncidentID + " · notification " + n.ID}}, map[string]any{"type": "actions", "elements": []any{map[string]any{"type": "button", "url": link, "text": map[string]string{"type": "plain_text", "text": "Open authenticated SRE"}}}}}})
}
