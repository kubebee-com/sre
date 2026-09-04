package triage

import (
	"context"

	"github.com/kubebee-com/sre/pkg/scanner"
)

type DeepSeekProvider struct {
	codex *CodexProvider
}

func NewDeepSeekProvider(apiKey, model, baseURL string) *DeepSeekProvider {
	if model == "" {
		model = "deepseek-chat"
	}
	if baseURL == "" {
		baseURL = "https://api.deepseek.com/v1"
	}
	return &DeepSeekProvider{
		codex: NewCodexProvider(apiKey, model, baseURL),
	}
}

func (p *DeepSeekProvider) Name() string {
	return "DeepSeek (" + p.codex.model + ")"
}

func (p *DeepSeekProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	return p.codex.Diagnose(ctx, issue)
}

func (p *DeepSeekProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	return p.codex.Explain(ctx, query, issue)
}
