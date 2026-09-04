package config

import (
	"flag"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Kubeconfig     string
	Port           int
	ScanInterval   time.Duration
	Namespace      string
	LLMProvider    string
	LLMAPIKey      string
	LLMModel       string
	LLMBaseURL     string
	HarnessCommand string
	WebhookURL     string
	PublicURL      string
}

func LoadConfig() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Kubeconfig, "kubeconfig", getEnv("KUBECONFIG", ""), "Path to kubeconfig file (empty for in-cluster)")
	flag.IntVar(&cfg.Port, "port", getEnvInt("PORT", 8080), "HTTP server listen port")
	flag.DurationVar(&cfg.ScanInterval, "scan-interval", getEnvDuration("SCAN_INTERVAL", 2*time.Minute), "Interval between automatic cluster scans")
	flag.StringVar(&cfg.Namespace, "namespace", getEnv("NAMESPACE", ""), "Namespace to scan (empty for all namespaces)")
	flag.StringVar(&cfg.LLMProvider, "llm-provider", getEnv("LLM_PROVIDER", "claude"), "Triage provider: claude, codex, deepseek, harness, rule-based")
	flag.StringVar(&cfg.LLMAPIKey, "llm-api-key", getEnv("LLM_API_KEY", ""), "API Key for LLM provider")
	flag.StringVar(&cfg.LLMModel, "llm-model", getEnv("LLM_MODEL", ""), "Model override (e.g. claude-3-7-sonnet, gpt-4o, deepseek-chat)")
	flag.StringVar(&cfg.LLMBaseURL, "llm-base-url", getEnv("LLM_BASE_URL", ""), "Base URL override for LLM provider API")
	flag.StringVar(&cfg.HarnessCommand, "harness-command", getEnv("HARNESS_COMMAND", ""), "Command path for agent harness CLI")
	flag.StringVar(&cfg.WebhookURL, "webhook-url", getEnv("WEBHOOK_URL", ""), "Webhook URL for notifications (Slack/Discord)")
	flag.StringVar(&cfg.PublicURL, "public-url", getEnv("PUBLIC_URL", "https://sre.kubebee.com"), "Public URL for web dashboard")

	flag.Parse()
	return cfg
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return fallback
}
