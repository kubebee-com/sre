package playbook

import (
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"strings"
)

type textSanitizer struct{ redactor *sanitizer.Redactor }

func (s *textSanitizer) clean(input, output any) error {
	b, err := json.Marshal(input)
	if err != nil {
		return ErrServiceInvalid
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return ErrServiceInvalid
	}
	v = s.redactor.SanitizeValue(v)
	var cleanErr error
	var urls func(any) any
	urls = func(v any) any {
		switch x := v.(type) {
		case string:
			safe, err := s.sanitizeServiceText(x)
			if err != nil {
				cleanErr = err
				return ""
			}
			return catalogURLPattern.ReplaceAllStringFunc(safe, s.redactor.SanitizeURL)
		case map[string]any:
			for k, e := range x {
				x[k] = urls(e)
			}
		case []any:
			for i, e := range x {
				x[i] = urls(e)
			}
		}
		return v
	}
	b, err = json.Marshal(urls(v))
	if cleanErr != nil {
		return cleanErr
	}
	if err != nil || json.Unmarshal(b, output) != nil {
		return ErrServiceInvalid
	}
	return nil
}

// sanitizeServiceText handles every Markdown fence and JSON fragment, including
// nested JSON stored in string fields. Parsing work is bounded by input size.
func (s *textSanitizer) sanitizeServiceText(input string) (string, error) {
	lines := strings.SplitAfter(input, "\n")
	var fenced strings.Builder
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		marker := ""
		if strings.HasPrefix(trimmed, "```") {
			marker = "```"
		} else if strings.HasPrefix(trimmed, "~~~") {
			marker = "~~~"
		}
		if marker == "" {
			fenced.WriteString(lines[i])
			continue
		}
		fenced.WriteString(lines[i])
		i++
		var body strings.Builder
		for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), marker) {
			body.WriteString(lines[i])
			i++
		}
		text := s.redactor.SanitizeStructuredText(body.String())
		fenced.WriteString(text)
		if i < len(lines) {
			if text != "" && !strings.HasSuffix(text, "\n") {
				fenced.WriteByte('\n')
			}
			fenced.WriteString(lines[i])
		}
	}
	text := s.redactor.SanitizeStructuredText(fenced.String())
	var out strings.Builder
	position, work := 0, 0
	for position < len(text) {
		relative := strings.IndexAny(text[position:], "{[")
		if relative < 0 {
			out.WriteString(text[position:])
			break
		}
		start := position + relative
		out.WriteString(text[position:start])
		decoder := json.NewDecoder(strings.NewReader(text[start:]))
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			cost := len(text) - start
			var syntax *json.SyntaxError
			if errors.As(err, &syntax) {
				cost = int(syntax.Offset)
			}
			work += cost
			if work > 8*len(text)+1024 {
				return "", ErrServiceInvalid
			}
			out.WriteByte(text[start])
			position = start + 1
			continue
		}
		work += len(raw)
		if work > 8*len(text)+1024 || validateJSONKeys(string(raw)) != nil {
			return "", ErrServiceInvalid
		}
		var value, cleaned any
		if json.Unmarshal(raw, &value) != nil {
			return "", ErrServiceInvalid
		}
		if err := s.clean(value, &cleaned); err != nil {
			return "", err
		}
		encoded, err := json.Marshal(cleaned)
		if err != nil {
			return "", ErrServiceInvalid
		}
		out.Write(encoded)
		position = start + int(decoder.InputOffset())
	}
	return out.String(), nil
}
