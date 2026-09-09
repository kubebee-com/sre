package triage

import (
	"bytes"
	"encoding/json"
	"strings"
)

// responsesEnvelope decodes the already byte-bounded HTTP body. Some gateways
// always emit SSE. Never treat text deltas or an early [DONE] as final output.
func responsesEnvelope(body []byte) ([]byte, error) {
	if json.Valid(body) {
		return body, nil
	}
	var completed json.RawMessage
	items := map[int]json.RawMessage{}
	var frame strings.Builder
	seenDone := false
	flush := func() error {
		data := strings.TrimSpace(frame.String())
		frame.Reset()
		if data == "" {
			return nil
		}
		if data == "[DONE]" {
			if len(completed) == 0 || seenDone {
				return ErrProviderResponse
			}
			seenDone = true
			return nil
		}
		if seenDone || len(completed) != 0 {
			return ErrProviderResponse
		}
		var event struct {
			Type        string          `json:"type"`
			Response    json.RawMessage `json:"response"`
			Item        json.RawMessage `json:"item"`
			OutputIndex *int            `json:"output_index"`
		}
		if json.Unmarshal([]byte(data), &event) != nil || event.Type == "" {
			return ErrProviderResponse
		}
		switch event.Type {
		case "error", "response.failed", "response.incomplete":
			return ErrProviderResponse
		case "response.output_item.done":
			if event.OutputIndex == nil || *event.OutputIndex < 0 || *event.OutputIndex >= 256 || !json.Valid(event.Item) {
				return ErrProviderResponse
			}
			if _, exists := items[*event.OutputIndex]; exists {
				return ErrProviderResponse
			}
			items[*event.OutputIndex] = event.Item
		case "response.completed":
			if len(completed) != 0 || !json.Valid(event.Response) {
				return ErrProviderResponse
			}
			var response struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(event.Response, &response) != nil || response.Status != "completed" {
				return ErrProviderResponse
			}
			completed = event.Response
			var envelope map[string]json.RawMessage
			if json.Unmarshal(completed, &envelope) != nil {
				return ErrProviderResponse
			}
			var output []json.RawMessage
			if raw := envelope["output"]; len(raw) > 0 && json.Unmarshal(raw, &output) != nil {
				return ErrProviderResponse
			}
			if len(output) == 0 && len(items) > 0 {
				for i := 0; i < len(items); i++ {
					item, ok := items[i]
					if !ok {
						return ErrProviderResponse
					}
					output = append(output, item)
				}
				envelope["output"], _ = json.Marshal(output)
				completed, _ = json.Marshal(envelope)
			}
		}
		return nil
	}
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			value := bytes.TrimPrefix(line, []byte("data:"))
			value = bytes.TrimPrefix(value, []byte(" "))
			frame.Write(value)
			frame.WriteByte('\n')
		} else if !bytes.HasPrefix(line, []byte(":")) && !bytes.HasPrefix(line, []byte("event:")) && !bytes.HasPrefix(line, []byte("id:")) && !bytes.HasPrefix(line, []byte("retry:")) {
			return nil, ErrProviderResponse
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if len(completed) == 0 {
		return nil, ErrProviderResponse
	}
	return completed, nil
}
