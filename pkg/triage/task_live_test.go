package triage

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"
)

// Explicitly opt in: this test sends a small synthetic prompt to the configured
// endpoint. It never reads local credentials or prints prompts/response bodies.
func TestLiveStructuredPlaybookTask(t *testing.T) {
	if os.Getenv("SRE_TEST_LIVE_STRUCTURED") != "1" {
		t.Skip("set SRE_TEST_LIVE_STRUCTURED=1 for an authorized live provider smoke test")
	}
	key, endpoint := os.Getenv("LLM_API_KEY"), os.Getenv("LLM_BASE_URL")
	if key == "" || endpoint == "" {
		t.Fatal("live provider credential and endpoint are required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		t.Fatal("live endpoint must be an explicit HTTPS URL")
	}
	p, err := NewProviderFromProfile(ProviderProfile{Provider: "codex", Model: "gpt-5.5", WireAPI: WireAPIResponses, Endpoint: endpoint, EndpointAllowlist: []string{endpoint}, APIKey: key, Timeout: 45 * time.Second})
	if err != nil {
		t.Fatalf("live provider construction failed (%T)", err)
	}
	runner, ok := p.(StructuredTaskRunner)
	if !ok {
		t.Fatal("provider lacks structured tasks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	result, err := runner.RunStructured(ctx, StructuredTask{Operation: "playbook.digest", SystemPrompt: "Return only a JSON object with marker equal to playbook-live-ok and review_required equal to true.", UserPrompt: "Synthetic smoke test: inspecting pod events requires review. Return the requested JSON object.", MaxOutputBytes: 65536})
	if err != nil {
		var providerErr *ProviderError
		if errors.As(err, &providerErr) {
			t.Fatalf("live structured task failed: kind=%s HTTP=%d; no response body logged", providerErr.Kind, providerErr.StatusCode)
		}
		t.Fatalf("live structured task failed (%T); no response body logged", err)
	}
	var output struct {
		Marker         string `json:"marker"`
		ReviewRequired bool   `json:"review_required"`
	}
	if json.Unmarshal([]byte(result.Text), &output) != nil || output.Marker != "playbook-live-ok" || !output.ReviewRequired {
		t.Fatal("live response did not satisfy the expected JSON contract")
	}
	t.Logf("gpt-5.5 Responses structured task passed; reported tokens: input=%d output=%d total=%d", result.Usage.InputTokens, result.Usage.OutputTokens, result.Usage.TotalTokens)
}
