package triage

import (
	"context"

	"github.com/kubebee-com/sre/pkg/scanner"
)

type DeepSeekProvider struct {
	codex *CodexProvider
}

func NewDeepSeekProvider(apiKey, model, baseURL string, secretValues ...string) *DeepSeekProvider {
	if model == "" {
		model = "deepseek-chat"
	}
	if baseURL == "" {
		baseURL = "https://api.deepseek.com/v1"
	}
	return &DeepSeekProvider{
		codex: newCodexProvider(apiKey, model, baseURL, WireAPIChat, secretValues...),
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

func (p *DeepSeekProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	if p == nil || p.codex == nil {
		operation := safeStructuredTaskOperationLabel(task.Operation)
		err := providerError(ProviderErrorValidation, "deepseek", operation, ErrProviderValidation)
		observeProviderError(ctx, "deepseek", operation, err)
		return StructuredTaskResult{}, err
	}
	return p.codex.RunStructured(ctx, task)
}
