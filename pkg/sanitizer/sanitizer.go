package sanitizer

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	// RedactionSchema identifies the field and token policy used by all
	// provider, cache, and output projections.
	RedactionSchema    = "sre-redaction-v2"
	redactedValue      = "[REDACTED]"
	redactedToken      = "[REDACTED_TOKEN]"
	redactedJWT        = "[REDACTED_JWT]"
	redactedPrivateKey = "[REDACTED_PRIVATE_KEY]"
)

var (
	privateKeyRegex          = regexp.MustCompile(`(?is)-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----`)
	pgpKeyRegex              = regexp.MustCompile(`(?is)-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----`)
	bearerRegex              = regexp.MustCompile(`(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]+`)
	jwtRegex                 = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	knownKeyRegex            = regexp.MustCompile(`(?i)\b(?:sk-(?:ant-)?[A-Za-z0-9][A-Za-z0-9_-]{7,}|xox[baprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{10,}|npm_[A-Za-z0-9]{10,}|pypi-[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16})\b`)
	headerAssignmentRegex    = regexp.MustCompile(`(?i)(?:[\"']?(?:authorization|proxy-authorization|x-api-keys?|api-keys?)[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;{}\x5b\x5d]+)`)
	sensitiveAssignmentRegex = regexp.MustCompile(`(?i)(?:[\"']?(?:access[_-]?tokens?|api[_-]?keys?|apikeys?|auths?|client[_-]?secrets?|credential(?:s)?|pass(?:words?|wd|phrases?)?|private[_-]?keys?|refresh[_-]?tokens?|secrets?(?:[_-]?keys?)?|tokens?)[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;{}\x5b\x5d]+)`)
	yamlSecretValueRegex     = regexp.MustCompile(`(?im)(?:^|\n)[ \t-]*name\s*:\s*[^\r\n]*(?:password|secret|token|api[_-]?key|credential|private[_-]?key)[^\r\n]*\r?\n[ \t]*value\s*:\s*(?:\"[^\"]*\"|'[^']*'|[^\r\n#]+)`)
)

// RedactionReport describes what a redactor removed without retaining removed values.
type RedactionReport struct {
	RedactedCount int      `json:"redacted_count"`
	Fields        []string `json:"fields,omitempty"`
}

func (r *RedactionReport) add(count int) {
	if r == nil || count <= 0 {
		return
	}
	r.RedactedCount += count
}

func (r *RedactionReport) addField(field string, count int) {
	if r == nil || count <= 0 {
		return
	}
	r.add(count)
	for _, existing := range r.Fields {
		if existing == field {
			return
		}
	}
	r.Fields = append(r.Fields, field)
}

func (r *RedactionReport) merge(field string, other RedactionReport) {
	if r == nil || other.RedactedCount == 0 {
		return
	}
	r.addField(field, other.RedactedCount)
}

// Redactor applies built-in patterns and configured literal secret values.
// The configured values are copied and sorted so each instance is immutable after construction.
type Redactor struct {
	literalSecrets []string
}

func NewRedactor(secretValues ...string) *Redactor {
	secrets := make([]string, 0, len(secretValues))
	for _, secret := range secretValues {
		if secret != "" {
			secrets = append(secrets, secret)
		}
	}
	sort.SliceStable(secrets, func(i, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	return &Redactor{literalSecrets: secrets}
}

var (
	defaultRedactorMu sync.RWMutex
	defaultRedactor   = NewRedactor()
)

// ConfigureDefaultRedactor installs the process-wide policy used by implicit
// serialization and sink helpers. Redactor instances remain immutable after
// construction, so readers can safely retain the returned pointer.
func ConfigureDefaultRedactor(secretValues ...string) {
	configured := NewRedactor(secretValues...)
	defaultRedactorMu.Lock()
	defaultRedactor = configured
	defaultRedactorMu.Unlock()
}

// DefaultRedactor returns the current process-wide redaction policy.
func DefaultRedactor() *Redactor {
	defaultRedactorMu.RLock()
	configured := defaultRedactor
	defaultRedactorMu.RUnlock()
	return configured
}

// RedactorForSecrets uses the process policy when no component-specific
// secrets are supplied, while preserving explicit policies for providers.
func RedactorForSecrets(secretValues ...string) *Redactor {
	if len(secretValues) == 0 {
		return DefaultRedactor()
	}
	return NewRedactor(secretValues...)
}

// SanitizeText strips sensitive credentials, tokens, and keys from text.
func SanitizeText(input string) string {
	return DefaultRedactor().SanitizeText(input)
}

// SanitizeTextWithSecrets redacts built-in patterns and supplied literal values.
func SanitizeTextWithSecrets(input string, secretValues ...string) string {
	return RedactorForSecrets(secretValues...).SanitizeText(input)
}

// SanitizeTextWithReport is the report-bearing form of SanitizeTextWithSecrets.
func SanitizeTextWithReport(input string, secretValues ...string) (string, RedactionReport) {
	return RedactorForSecrets(secretValues...).SanitizeTextWithReport(input)
}

// SanitizeBytes applies the configured text/structured redaction policy to a
// UTF-8 payload. Non-text bytes are copied unchanged because cache values are
// allowed to be opaque application data.
func SanitizeBytes(input []byte) []byte {
	return DefaultRedactor().SanitizeBytes(input)
}

func (r *Redactor) SanitizeBytes(input []byte) []byte {
	if len(input) == 0 {
		return nil
	}
	if !utf8.Valid(input) {
		return append([]byte(nil), input...)
	}
	return []byte(r.SanitizeStructuredText(string(input)))
}

func (r *Redactor) SanitizeText(input string) string {
	sanitized, _ := r.SanitizeTextWithReport(input)
	return sanitized
}

func (r *Redactor) SanitizeTextWithReport(input string) (string, RedactionReport) {
	if input == "" {
		return "", RedactionReport{}
	}
	if r == nil {
		r = DefaultRedactor()
	}

	var report RedactionReport
	out := input
	for _, secret := range r.literalSecrets {
		if secret == "" || !strings.Contains(out, secret) {
			continue
		}
		count := strings.Count(out, secret)
		out = strings.ReplaceAll(out, secret, redactedValue)
		report.add(count)
	}
	out = replaceMatches(out, privateKeyRegex, redactedPrivateKey, &report)
	out = replaceMatches(out, pgpKeyRegex, redactedPrivateKey, &report)
	out = replaceMatches(out, bearerRegex, "Bearer "+redactedToken, &report)
	out = replaceMatches(out, jwtRegex, redactedJWT, &report)
	out = replaceMatches(out, knownKeyRegex, redactedValue, &report)
	out = replaceYAMLSecretValues(out, &report)
	out = replaceAssignments(out, headerAssignmentRegex, &report)
	out = replaceAssignments(out, sensitiveAssignmentRegex, &report)
	return out, report
}

func replaceMatches(input string, pattern *regexp.Regexp, replacement string, report *RedactionReport) string {
	return pattern.ReplaceAllStringFunc(input, func(_ string) string {
		report.add(1)
		return replacement
	})
}

func replaceAssignments(input string, pattern *regexp.Regexp, report *RedactionReport) string {
	return pattern.ReplaceAllStringFunc(input, func(match string) string {
		delimiter := strings.IndexAny(match, ":=")
		if delimiter < 0 {
			return match
		}

		valueStart := delimiter + 1
		for valueStart < len(match) && (match[valueStart] == ' ' || match[valueStart] == '\t') {
			valueStart++
		}
		value := match[valueStart:]
		unquoted := strings.Trim(value, "\"'")
		if strings.HasPrefix(unquoted, "[REDACTED") || unquoted == "{" || unquoted == "[" || strings.EqualFold(unquoted, "bearer") || strings.HasPrefix(strings.ToLower(unquoted), "bearer "+strings.ToLower(redactedToken)) {
			return match
		}

		report.add(1)
		prefix := match[:valueStart]
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			return prefix + value[:1] + redactedValue + value[len(value)-1:]
		}
		return prefix + redactedValue
	})
}

func replaceYAMLSecretValues(input string, report *RedactionReport) string {
	return yamlSecretValueRegex.ReplaceAllStringFunc(input, func(match string) string {
		valueMarker := regexp.MustCompile(`(?i)value\s*:\s*`)
		location := valueMarker.FindStringIndex(match)
		if location == nil {
			return match
		}
		value := match[location[1]:]
		if strings.HasPrefix(strings.TrimSpace(value), "[REDACTED") {
			return match
		}
		report.add(1)
		prefix := match[:location[1]]
		trimmed := strings.TrimRight(value, " \t")
		trailing := value[len(trimmed):]
		if len(trimmed) >= 2 && ((trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"') || (trimmed[0] == '\'' && trimmed[len(trimmed)-1] == '\'')) {
			return prefix + trimmed[:1] + redactedValue + trimmed[len(trimmed)-1:] + trailing
		}
		return prefix + redactedValue + trailing
	})
}

// IsSensitiveField reports whether a structured field name normally carries a secret value.
func IsSensitiveField(field string) bool {
	key := normalizedField(field)
	return isSensitiveFieldKey(key) || (strings.HasSuffix(key, "s") && isSensitiveFieldKey(strings.TrimSuffix(key, "s")))
}

func isSensitiveFieldKey(key string) bool {
	switch key {
	case "key", "apikey", "authtoken", "authorization", "accesstoken", "refreshtoken", "idtoken", "auth", "pass",
		"clientsecret", "credential", "credentials", "password", "passwd", "passphrase",
		"privatekey", "secret", "secretkey", "token":
		return true
	}
	return strings.HasSuffix(key, "password") ||
		strings.HasSuffix(key, "secret") ||
		strings.HasSuffix(key, "token") ||
		strings.HasSuffix(key, "credential") ||
		strings.HasSuffix(key, "privatekey")
}

func normalizedField(field string) string {
	compact := strings.ToLower(strings.TrimSpace(field))
	var normalized strings.Builder
	for _, r := range compact {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			normalized.WriteRune(r)
		}
	}
	return normalized.String()
}

// SanitizeValue recursively redacts maps and slices while preserving their shape.
func SanitizeValue(value interface{}) interface{} {
	return DefaultRedactor().SanitizeValue(value)
}

func (r *Redactor) SanitizeValue(value interface{}) interface{} {
	sanitized, _ := r.sanitizeValue(value)
	return sanitized
}

func (r *Redactor) sanitizeValue(value interface{}) (interface{}, RedactionReport) {
	if r == nil {
		r = DefaultRedactor()
	}

	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		var report RedactionReport
		sensitiveNamedValue := hasSensitiveNamedValue(typed)
		for originalKey, nested := range typed {
			key, keyReport := r.SanitizeTextWithReport(originalKey)
			if keyReport.RedactedCount > 0 {
				report.RedactedCount += keyReport.RedactedCount
				report.Fields = appendUnique(report.Fields, "map_key")
			}
			if IsSensitiveField(originalKey) || (sensitiveNamedValue && normalizedField(originalKey) == "value") {
				out[key] = redactedValue
				report.addField(key, 1)
				continue
			}
			sanitized, nestedReport := r.sanitizeValue(nested)
			out[key] = sanitized
			report.merge(key, nestedReport)
		}
		return out, report
	case map[string]string:
		out := make(map[string]string, len(typed))
		var report RedactionReport
		sensitiveNamedValue := hasSensitiveNamedStringValue(typed)
		for originalKey, nested := range typed {
			key, keyReport := r.SanitizeTextWithReport(originalKey)
			if keyReport.RedactedCount > 0 {
				report.RedactedCount += keyReport.RedactedCount
				report.Fields = appendUnique(report.Fields, "map_key")
			}
			if IsSensitiveField(originalKey) || (sensitiveNamedValue && normalizedField(originalKey) == "value") {
				out[key] = redactedValue
				report.addField(key, 1)
				continue
			}
			sanitized, nestedReport := r.SanitizeTextWithReport(nested)
			out[key] = sanitized
			report.merge(key, nestedReport)
		}
		return out, report
	case []interface{}:
		out := make([]interface{}, len(typed))
		var report RedactionReport
		for i, nested := range typed {
			sanitized, nestedReport := r.sanitizeValue(nested)
			out[i] = sanitized
			report.RedactedCount += nestedReport.RedactedCount
			report.Fields = appendUnique(report.Fields, nestedReport.Fields...)
		}
		return out, report
	case []string:
		out := make([]string, len(typed))
		var report RedactionReport
		for i, nested := range typed {
			sanitized, nestedReport := r.SanitizeTextWithReport(nested)
			out[i] = sanitized
			report.RedactedCount += nestedReport.RedactedCount
			report.Fields = appendUnique(report.Fields, nestedReport.Fields...)
		}
		return out, report
	case string:
		return r.SanitizeTextWithReport(typed)
	default:
		return value, RedactionReport{}
	}
}

func hasSensitiveNamedValue(values map[string]interface{}) bool {
	for key, value := range values {
		if normalizedField(key) != "name" && normalizedField(key) != "field" && normalizedField(key) != "key" && normalizedField(key) != "env" {
			continue
		}
		name, ok := value.(string)
		if ok && (IsSensitiveField(name) || isSensitiveEnvironmentKey(name)) {
			return true
		}
	}
	return false
}

func hasSensitiveNamedStringValue(values map[string]string) bool {
	for key, value := range values {
		if normalizedField(key) != "name" && normalizedField(key) != "field" && normalizedField(key) != "key" && normalizedField(key) != "env" {
			continue
		}
		if IsSensitiveField(value) || isSensitiveEnvironmentKey(value) {
			return true
		}
	}
	return false
}

func appendUnique(values []string, additions ...string) []string {
	for _, addition := range additions {
		found := false
		for _, value := range values {
			if value == addition {
				found = true
				break
			}
		}
		if !found {
			values = append(values, addition)
		}
	}
	return values
}

// SanitizeStructuredText preserves valid JSON/YAML structure while applying
// field-aware redaction, then falls back to text redaction for ordinary text.
func (r *Redactor) SanitizeStructuredText(input string) string {
	sanitized, _ := r.SanitizeStructuredTextWithReport(input)
	return sanitized
}

// SanitizeStructuredTextWithReport is the report-bearing structured sanitizer.
func (r *Redactor) SanitizeStructuredTextWithReport(input string) (string, RedactionReport) {
	if input == "" {
		return "", RedactionReport{}
	}
	if r == nil {
		r = DefaultRedactor()
	}

	trimmed := strings.TrimSpace(input)
	var value interface{}
	if err := json.Unmarshal([]byte(trimmed), &value); err == nil {
		return marshalSanitizedJSON(r, value)
	}

	if looksLikeStructuredText(trimmed) {
		if err := yaml.Unmarshal([]byte(input), &value); err == nil {
			if sanitized, report := r.sanitizeValue(value); sanitized != nil {
				if encoded, err := yaml.Marshal(sanitized); err == nil {
					return string(encoded), report
				}
			}
		}
	}

	if sanitized, report, ok := sanitizeEmbeddedJSON(input, r); ok {
		return sanitized, report
	}
	return r.SanitizeTextWithReport(input)
}

func marshalSanitizedJSON(r *Redactor, value interface{}) (string, RedactionReport) {
	sanitized, report := r.sanitizeValue(value)
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return r.SanitizeTextWithReport(string(mustJSON(value)))
	}
	return string(encoded), report
}

func mustJSON(value interface{}) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func looksLikeStructuredText(input string) bool {
	if input == "" {
		return false
	}
	if strings.HasPrefix(input, "{") || strings.HasPrefix(input, "[") || strings.HasPrefix(input, "- ") || input == "-" {
		return true
	}
	if !strings.Contains(input, "\n") {
		return false
	}
	firstLine := strings.TrimSpace(strings.SplitN(input, "\n", 2)[0])
	return strings.Contains(firstLine, ":") && !strings.HasPrefix(firstLine, "http:") && !strings.HasPrefix(firstLine, "https:")
}

func sanitizeEmbeddedJSON(input string, r *Redactor) (string, RedactionReport, bool) {
	var output strings.Builder
	var report RedactionReport
	cursor, attempts := 0, 0
	found := false
	for start := 0; start < len(input); start++ {
		if input[start] != '{' && input[start] != '[' {
			continue
		}
		attempts++
		if attempts > 256 {
			output.WriteString(input[cursor:start])
			output.WriteString(redactedValue)
			report.add(1)
			found = true
			cursor = len(input)
			break
		}
		end := balancedJSONEnd(input, start)
		if end <= start {
			continue
		}
		var value interface{}
		if json.Unmarshal([]byte(input[start:end]), &value) != nil {
			continue
		}
		sanitized, itemReport := r.sanitizeValue(value)
		encoded, err := json.Marshal(sanitized)
		if err != nil {
			continue
		}
		output.WriteString(input[cursor:start])
		output.Write(encoded)
		report.merge("embedded", itemReport)
		found = true
		cursor = end
		start = end - 1
	}
	if !found {
		return input, RedactionReport{}, false
	}
	output.WriteString(input[cursor:])
	text, textReport := r.SanitizeTextWithReport(output.String())
	report.merge("text", textReport)
	return text, report, true
}

func balancedJSONEnd(input string, start int) int {
	depth := 0
	inString := false
	escaped := false
	for index := start; index < len(input); index++ {
		current := input[index]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
				continue
			}
			if current == '"' {
				inString = false
			}
			continue
		}
		switch current {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return index + 1
			}
			if depth < 0 {
				return -1
			}
		}
	}
	return -1
}

// SanitizeJSON keeps valid JSON structure and falls back to text redaction for JSON-like snippets.
func (r *Redactor) SanitizeJSON(input string) string {
	if input == "" {
		return ""
	}
	var value interface{}
	if err := json.Unmarshal([]byte(input), &value); err == nil {
		sanitized := r.SanitizeValue(value)
		if encoded, err := json.Marshal(sanitized); err == nil {
			return string(encoded)
		}
	}
	return r.SanitizeText(input)
}

func SanitizeJSON(input string) string {
	return DefaultRedactor().SanitizeJSON(input)
}

// SanitizeURL preserves the destination host while masking userinfo, secret
// query parameters, and token-shaped path components.
func (r *Redactor) SanitizeURL(input string) string {
	if input == "" {
		return ""
	}
	if r == nil {
		r = DefaultRedactor()
	}
	parsed, err := url.Parse(input)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "[REDACTED_URL]"
	}
	parsed.User = nil
	parsed.Path = sanitizeURLPath(parsed.Path, r)
	parsed.RawPath = ""
	query := parsed.Query()
	for key, values := range query {
		if IsSensitiveField(key) {
			for index := range values {
				values[index] = redactedValue
			}
			query[key] = values
			continue
		}
		for index, value := range values {
			value = r.SanitizeText(value)
			if likelySecretURLComponent(value) {
				value = redactedValue
			}
			values[index] = value
		}
		query[key] = values
	}
	parsed.RawQuery = query.Encode()
	if parsed.Fragment != "" {
		parsed.Fragment = r.SanitizeText(parsed.Fragment)
		if likelySecretURLComponent(parsed.Fragment) {
			parsed.Fragment = redactedValue
		}
	}
	return r.SanitizeText(parsed.String())
}

// SanitizeURL applies structural URL redaction using the process policy.
func SanitizeURL(input string) string {
	return DefaultRedactor().SanitizeURL(input)
}

func sanitizeURLPath(path string, r *Redactor) string {
	segments := strings.Split(path, "/")
	maskRest := false
	for index, segment := range segments {
		lower := strings.ToLower(segment)
		if maskRest {
			if segment != "" {
				segments[index] = redactedValue
			}
			continue
		}
		if lower == "services" || lower == "webhooks" || lower == "incomingwebhook" || lower == "webhook" || lower == "hook" || lower == "token" || lower == "secret" || lower == "signature" || lower == "sig" {
			maskRest = true
			continue
		}
		segment = r.SanitizeText(segment)
		if likelySecretURLComponent(segment) {
			segment = redactedValue
		}
		segments[index] = segment
	}
	return strings.Join(segments, "/")
}

func likelySecretURLComponent(value string) bool {
	if value == "" || strings.HasPrefix(value, "[REDACTED") {
		return false
	}
	if len(value) < 16 {
		return false
	}
	letters, digits := false, false
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z':
			letters = true
		case character >= '0' && character <= '9':
			digits = true
		case strings.ContainsRune("._~-/+=", character):
		default:
			return false
		}
	}
	return letters && digits
}

// SafeLogValue removes credentials, control characters, and excessive data
// before an untrusted value is interpolated into a process log line.
func (r *Redactor) SafeLogValue(input string) string {
	if r == nil {
		r = DefaultRedactor()
	}
	value := r.SanitizeText(input)
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value)
	runes := []rune(value)
	const maxLogValueRunes = 512
	if len(runes) > maxLogValueRunes {
		return string(runes[:maxLogValueRunes]) + "..."
	}
	return string(runes)
}

// SafeLogValue applies the process policy before returning a log-safe value.
func SafeLogValue(input string) string {
	return DefaultRedactor().SafeLogValue(input)
}

// SanitizeEnvMap preserves environment variable keys while masking sensitive values.
func SanitizeEnvMap(envs map[string]string) map[string]string {
	return DefaultRedactor().SanitizeEnvMap(envs)
}

func SanitizeEnvMapWithSecrets(envs map[string]string, secretValues ...string) map[string]string {
	return RedactorForSecrets(secretValues...).SanitizeEnvMap(envs)
}

func (r *Redactor) SanitizeEnvMap(envs map[string]string) map[string]string {
	sanitized := make(map[string]string, len(envs))
	for key, value := range envs {
		if IsSensitiveField(key) || isSensitiveEnvironmentKey(key) {
			sanitized[key] = redactedValue
			continue
		}
		sanitized[key] = r.SanitizeText(value)
	}
	return sanitized
}

func isSensitiveEnvironmentKey(key string) bool {
	upperKey := strings.ToUpper(key)
	for _, substring := range []string{"PASS", "SECRET", "KEY", "TOKEN", "AUTH", "CREDENTIAL", "PRIVATE"} {
		if strings.Contains(upperKey, substring) {
			return true
		}
	}
	return false
}
