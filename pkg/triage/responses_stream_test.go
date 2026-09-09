package triage

import (
	"errors"
	"testing"
)

func TestResponsesStreamRequiresCompletedEnvelope(t *testing.T) {
	completed := `data: {"type":"response.completed","response":{"status":"completed","output_text":"{\"ok\":true}","usage":{"input_tokens":9,"output_tokens":4,"total_tokens":13}}}` + "\n\n"
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"completed", "event: response.created\ndata: {\"type\":\"response.created\"}\n\n" + completed + "data: [DONE]\n\n", true},
		{"completed items", `data: {"type":"response.output_item.done","output_index":0,"item":{"type":"message","content":[{"type":"output_text","text":"{\"ok\":true}"}]}}` + "\n\n" + `data: {"type":"response.completed","response":{"status":"completed","output":[],"usage":{"input_tokens":9,"output_tokens":4,"total_tokens":13}}}` + "\n\n", true},
		{"completed item without completion", `data: {"type":"response.output_item.done","output_index":0,"item":{"type":"message","content":[{"type":"output_text","text":"{\"ok\":true}"}]}}` + "\n\n", false},
		{"early done", "data: [DONE]\n\n" + completed, false},
		{"unbounded index", `data: {"type":"response.output_item.done","output_index":256,"item":{}}` + "\n\n" + completed, false},
		{"delta after completion", completed + `data: {"type":"response.output_text.delta","delta":"later"}` + "\n\n", false},
		{"partial only", "data: {\"type\":\"response.output_text.delta\",\"delta\":\"unsafe partial\"}\n\n", false},
		{"failed", "data: {\"type\":\"response.failed\"}\n\n" + completed, false},
		{"duplicate completed", completed + completed, false},
		{"malformed", "data: {\n\n" + completed, false},
		{"incomplete final", `data: {"type":"response.completed","response":{"status":"incomplete","output_text":"partial"}}` + "\n\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, err := extractResponsesText([]byte(tc.body))
			if tc.valid {
				if err != nil || text != `{"ok":true}` {
					t.Fatalf("text=%q err=%v", text, err)
				}
				usage := extractResponsesUsage([]byte(tc.body))
				if usage.TotalTokens != 13 {
					t.Fatalf("usage=%+v", usage)
				}
			} else if !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("partial/invalid stream accepted: %q %v", text, err)
			}
		})
	}
}
