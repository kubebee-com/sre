package scanner

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSanitizeIssueProducesTypedProjectionAndReport(t *testing.T) {
	configured := "issue-literal.[secret]"
	now := time.Now()
	raw := &Issue{
		ID:            "issue-1",
		Namespace:     "production",
		Kind:          "Pod",
		Name:          "payments",
		Severity:      SeverityHigh,
		Category:      CategoryCrashLoop,
		Summary:       "startup failed with password=" + configured,
		Details:       "{\"root_cause\":\"api_key=nested-api-key\",\"note\":\"keep this context\"}",
		LogsSnippet:   "Authorization: Bearer log-token",
		Events:        []string{"event secret=event-secret"},
		SpecSnippet:   "env:\n  - name: CLIENT_SECRET\n    value: spec-secret",
		FirstObserved: now,
		LastObserved:  now,
	}

	projection := SanitizeIssue(raw, configured)
	if projection == nil {
		t.Fatal("SanitizeIssue() returned nil")
	}
	if projection.ID != raw.ID || projection.Name != raw.Name || projection.Category != raw.Category {
		t.Fatalf("SanitizeIssue() changed issue identity or category: %#v", projection)
	}
	if projection.Report.RedactedCount == 0 {
		t.Fatal("SanitizeIssue() returned an empty redaction report")
	}
	if strings.Contains(projection.Summary, configured) || strings.Contains(projection.LogsSnippet, "log-token") || strings.Contains(projection.Events[0], "event-secret") || strings.Contains(projection.SpecSnippet, "spec-secret") {
		t.Fatalf("SanitizeIssue() leaked a raw secret: %#v", projection)
	}
	if raw.Summary == "" || !strings.Contains(raw.Summary, configured) {
		t.Fatal("SanitizeIssue() mutated the original issue")
	}

	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("json.Marshal(SanitizedIssue) error = %v", err)
	}
	if strings.Contains(string(encoded), configured) || strings.Contains(string(encoded), "nested-api-key") {
		t.Fatalf("serialized sanitized issue leaked a secret: %s", encoded)
	}
}

func TestIssueJSONSerializationUsesSanitizedProjection(t *testing.T) {
	raw := &Issue{
		ID:          "issue-2",
		Namespace:   "default",
		Kind:        "Pod",
		Name:        "worker",
		Severity:    SeverityMedium,
		Category:    CategoryPodFailed,
		Summary:     "token=issue-token",
		Details:     "password=issue-password",
		LogsSnippet: "x-api-key: issue-api-key",
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal(Issue) error = %v", err)
	}
	for _, secret := range []string{"issue-token", "issue-password", "issue-api-key"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("json.Marshal(Issue) leaked %q: %s", secret, encoded)
		}
	}
}
