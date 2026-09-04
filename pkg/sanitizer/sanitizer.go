package sanitizer

import (
	"regexp"
	"strings"
)

var (
	bearerRegex    = regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9_\-\.]+`)
	tokenRegex     = regexp.MustCompile(`(?i)(token|password|secret|api[_-]?key|auth)=["']?[^"'\s\n]+["']?`)
	privateKeyReg  = regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----`)
	base64JwtRegex = regexp.MustCompile(`ey[A-Za-z0-9-_]+\.ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)
)

// SanitizeText strips sensitive credentials, tokens, and keys from logs and events
func SanitizeText(input string) string {
	if input == "" {
		return ""
	}
	out := privateKeyReg.ReplaceAllString(input, "[REDACTED_PRIVATE_KEY]")
	out = bearerRegex.ReplaceAllString(out, "Bearer [REDACTED_TOKEN]")
	out = base64JwtRegex.ReplaceAllString(out, "[REDACTED_JWT]")
	out = tokenRegex.ReplaceAllStringFunc(out, func(match string) string {
		parts := strings.SplitN(match, "=", 2)
		if len(parts) == 2 {
			return parts[0] + "=[REDACTED]"
		}
		return match
	})
	return out
}

// SanitizeEnvMap preserves environment variable keys while masking values for known sensitive keys
func SanitizeEnvMap(envs map[string]string) map[string]string {
	sanitized := make(map[string]string, len(envs))
	sensitiveSubstrings := []string{"PASS", "SECRET", "KEY", "TOKEN", "AUTH", "CREDENTIAL", "PRIVATE"}

	for k, v := range envs {
		isSensitive := false
		upperKey := strings.ToUpper(k)
		for _, sub := range sensitiveSubstrings {
			if strings.Contains(upperKey, sub) {
				isSensitive = true
				break
			}
		}
		if isSensitive {
			sanitized[k] = "[REDACTED]"
		} else {
			sanitized[k] = SanitizeText(v)
		}
	}
	return sanitized
}
