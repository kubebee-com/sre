// Package interaction defines human clarification and terminal transport. Action
// approval and notification acknowledgement retain their separate authorities.
package interaction

import (
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

const Clarification = "CLARIFICATION"

var ErrInvalid = errors.New("invalid interaction")

type Request struct {
	Scope      identity.Scope `json:"scope"`
	ID         string         `json:"id"`
	IncidentID string         `json:"incident_id"`
	JobID      string         `json:"job_id,omitempty"`
	Kind       string         `json:"kind"`
	Question   string         `json:"question"`
	Version    int64          `json:"version"`
	Status     string         `json:"status"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Answer     string         `json:"answer,omitempty"`
	ActorID    string         `json:"actor_id,omitempty"`
	CreatedBy  string         `json:"created_by"`
	AnsweredAt *time.Time     `json:"answered_at,omitempty"`
}

func Options(question string) []string {
	switch question {
	case "CHANGE_CONTEXT":
		return []string{"RECENT_CHANGE", "NO_KNOWN_CHANGE", "UNKNOWN"}
	case "IMPACT":
		return []string{"USER_VISIBLE", "INTERNAL_ONLY", "UNKNOWN"}
	case "CONTINUE_DIAGNOSIS":
		return []string{"CONTINUE", "STOP", "UNKNOWN"}
	}
	return nil
}
func Prompt(question string) string {
	switch question {
	case "CHANGE_CONTEXT":
		return "Was there a recent application change?"
	case "IMPACT":
		return "Is the incident affecting users?"
	case "CONTINUE_DIAGNOSIS":
		return "Should read-only diagnosis continue?"
	}
	return "Unknown clarification"
}
func (r Request) Accepts(answer string) bool {
	for _, v := range Options(r.Question) {
		if answer == v {
			return true
		}
	}
	return false
}
func (r Request) Validate(now time.Time) error {
	if r.Scope.Validate() != nil || !identity.ValidID(r.ID) || !identity.ValidID(r.IncidentID) || (r.JobID != "" && !identity.ValidID(r.JobID)) || r.Kind != Clarification || len(Options(r.Question)) == 0 || r.Version != 1 || r.Status != "PENDING" || !r.ExpiresAt.After(now) || r.ExpiresAt.After(now.Add(24*time.Hour)) || r.Answer != "" || r.ActorID != "" || r.AnsweredAt != nil {
		return ErrInvalid
	}
	return nil
}

// Context is the provider-safe projection of a human answer. It carries no human
// identity, request identifiers, timestamps or arbitrary operator prose.
type Context struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}
