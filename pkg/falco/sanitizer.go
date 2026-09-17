package falco

import (
	"github.com/kubebee-com/sre/pkg/sanitizer"
)

const maxStringFieldLength = 4096

// SanitizeEvent returns a deep-sanitized copy of the given Falco Event, redacting
// credentials, tokens, and private keys from output strings and output fields.
func SanitizeEvent(ev *Event) *Event {
	if ev == nil {
		return nil
	}

	sanitized := &Event{
		UUID:     ev.UUID,
		Priority: ev.Priority,
		Rule:     ev.Rule,
		Time:     ev.Time,
		Source:   ev.Source,
		Hostname: ev.Hostname,
	}

	// Sanitize primary output string
	sanitized.Output = truncate(sanitizer.SanitizeText(ev.Output), maxStringFieldLength)

	// Copy and sanitize tags
	if len(ev.Tags) > 0 {
		sanitized.Tags = make([]string, len(ev.Tags))
		for i, tag := range ev.Tags {
			sanitized.Tags[i] = truncate(sanitizer.SanitizeText(tag), 256)
		}
	}

	// Sanitize structured output fields
	if ev.OutputFields != nil {
		sanitized.OutputFields = make(map[string]interface{}, len(ev.OutputFields))
		for k, v := range ev.OutputFields {
			switch val := v.(type) {
			case string:
				sanitized.OutputFields[k] = truncate(sanitizer.SanitizeText(val), maxStringFieldLength)
			case map[string]string:
				sanitized.OutputFields[k] = sanitizer.SanitizeEnvMap(val)
			default:
				sanitized.OutputFields[k] = sanitizer.SanitizeValue(val)
			}
		}
	}

	return sanitized
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[TRUNCATED]"
}
