package supportbundle

import "strings"

// keyHelpURLs is intentionally a closed map of HTTPS destinations. The
// package never opens these URLs; callers may display the returned value in a
// trusted UI or documentation link after their own policy checks.
var keyHelpURLs = map[string]string{
	"anthropic": "https://console.anthropic.com/settings/keys",
	"claude":    "https://console.anthropic.com/settings/keys",
	"codex":     "https://platform.openai.com/api-keys",
	"deepseek":  "https://platform.deepseek.com/api_keys",
	"groq":      "https://console.groq.com/keys",
	"openai":    "https://platform.openai.com/api-keys",
}

var providerAliases = map[string]string{
	"anthropic": "anthropic",
	"claude":    "claude",
	"codex":     "codex",
	"deepseek":  "deepseek",
	"groq":      "groq",
	"openai":    "openai",
}

// ProviderKeyHelpURL returns an allowlisted HTTPS page where a provider key
// can be managed. Unknown, local, custom, and user-supplied providers return
// an empty URL and false; no URL is constructed from input.
func ProviderKeyHelpURL(provider string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(provider))
	canonical, ok := providerAliases[key]
	if !ok {
		return "", false
	}
	url, ok := keyHelpURLs[canonical]
	if !ok || !strings.HasPrefix(url, "https://") {
		return "", false
	}
	return url, true
}

// KeyHelpURL is a convenience form for callers that only need a displayable
// URL. It returns an empty string for providers outside the allowlist.
func KeyHelpURL(provider string) string {
	url, _ := ProviderKeyHelpURL(provider)
	return url
}
