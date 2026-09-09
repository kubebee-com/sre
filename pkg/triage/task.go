package triage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
)

// StructuredTask is a bounded prompt request for provider-native JSON-mode
// output. The current contract guarantees a valid sanitized JSON response; it
// does not accept caller-supplied JSON Schema. Operation is intentionally
// low-cardinality so provider metrics and cache identities stay stable.
type StructuredTask struct {
	Operation      string
	SystemPrompt   string
	UserPrompt     string
	MaxOutputBytes int
}

// StructuredTaskResult is the sanitized provider output plus token accounting.
type StructuredTaskResult struct {
	Text  string
	Usage ProviderTokenUsage
}

// StructuredTaskRunner exposes provider-native JSON-mode output without
// falling back to diagnosis prompts or fabricating deterministic output.
type StructuredTaskRunner interface {
	RunStructured(context.Context, StructuredTask) (StructuredTaskResult, error)
}

var ErrStructuredTaskUnsupported = errors.New("structured task is not supported by provider")

type preparedStructuredTask struct {
	Operation      string
	SystemPrompt   string
	UserPrompt     string
	MaxOutputBytes int
}

var allowedStructuredTaskOperations = map[string]struct{}{
	"investigation.assess": {},
	"playbook.digest":      {},
	"playbook.normalize":   {},
	"playbook.resolve":     {},
	"playbook.learn":       {},
}

func prepareStructuredTask(ctx context.Context, provider string, task StructuredTask, redactor *sanitizer.Redactor, limits ...int) (context.Context, preparedStructuredTask, error) {
	ctx = normalizeContext(ctx)
	operation, err := normalizeStructuredTaskOperation(task.Operation)
	if err != nil {
		return ctx, preparedStructuredTask{}, providerError(ProviderErrorValidation, provider, "structured", err)
	}
	if err := checkProviderContext(ctx); err != nil {
		return ctx, preparedStructuredTask{}, classifyContextProviderError(err, provider, operation, ctx)
	}
	if redactor == nil {
		redactor = sanitizer.DefaultRedactor()
	}
	maxPromptBytes := defaultMaxRequestBytes
	defaultOutputBytes := maxProviderResponseBytes
	if len(limits) > 0 && limits[0] > 0 {
		maxPromptBytes = limits[0]
	}
	if len(limits) > 1 && limits[1] > 0 {
		defaultOutputBytes = limits[1]
	}
	maxOutputBytes := task.MaxOutputBytes
	if maxOutputBytes == 0 {
		maxOutputBytes = defaultOutputBytes
	}
	if maxOutputBytes < 0 || maxOutputBytes > defaultOutputBytes {
		return ctx, preparedStructuredTask{}, providerError(ProviderErrorValidation, provider, operation, ErrProviderValidation)
	}
	systemPrompt := redactor.SanitizeText(task.SystemPrompt)
	userPrompt := redactor.SanitizeText(task.UserPrompt)
	if exceedsStructuredPromptLimit(systemPrompt, userPrompt, maxPromptBytes) {
		return ctx, preparedStructuredTask{}, providerError(ProviderErrorLimit, provider, operation, ErrProviderResponseTooLarge)
	}
	return ctx, preparedStructuredTask{
		Operation:      operation,
		SystemPrompt:   systemPrompt,
		UserPrompt:     userPrompt,
		MaxOutputBytes: maxOutputBytes,
	}, nil
}

func normalizeStructuredTaskOperation(operation string) (string, error) {
	operation = strings.TrimSpace(operation)
	if _, ok := allowedStructuredTaskOperations[operation]; !ok {
		return "", ErrProviderValidation
	}
	return operation, nil
}

func exceedsStructuredPromptLimit(systemPrompt, userPrompt string, limit int) bool {
	if limit <= 0 {
		limit = defaultMaxRequestBytes
	}
	return len(systemPrompt) > limit ||
		len(userPrompt) > limit ||
		len(systemPrompt)+len(userPrompt) > limit
}

func finalizeStructuredTaskResult(provider string, task preparedStructuredTask, result StructuredTaskResult, redactor *sanitizer.Redactor) (StructuredTaskResult, error) {
	if redactor == nil {
		redactor = sanitizer.DefaultRedactor()
	}
	result.Text = strings.TrimSpace(redactor.SanitizeStructuredText(result.Text))
	if len(result.Text) == 0 || !json.Valid([]byte(result.Text)) {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, provider, task.Operation, ErrProviderResponse)
	}
	if len([]byte(result.Text)) > task.MaxOutputBytes {
		return StructuredTaskResult{}, providerError(ProviderErrorLimit, provider, task.Operation, ErrProviderResponseTooLarge)
	}
	result.Usage = boundProviderTokenUsage(result.Usage)
	return result, nil
}

func structuredTaskUnsupported(provider string, task StructuredTask) error {
	operation, err := normalizeStructuredTaskOperation(task.Operation)
	if err != nil {
		operation = "structured"
	}
	return providerError(ProviderErrorDisabled, provider, operation, ErrStructuredTaskUnsupported)
}

func safeStructuredTaskOperationLabel(operation string) string {
	if normalized, err := normalizeStructuredTaskOperation(operation); err == nil {
		return normalized
	}
	return "structured"
}

func structuredTaskProviderLimits(provider TriageProvider) (int, int) {
	switch typed := provider.(type) {
	case *OpenAICompatibleProvider:
		return typed.profile.MaxRequestBytes, typed.profile.MaxResponseBytes
	case *CloudProvider:
		return typed.profile.MaxRequestBytes, typed.profile.MaxResponseBytes
	case *BedrockProvider:
		return typed.profile.MaxRequestBytes, typed.profile.MaxResponseBytes
	case *SageMakerProvider:
		return typed.profile.MaxRequestBytes, typed.profile.MaxResponseBytes
	case *CachedProvider:
		return structuredTaskProviderLimits(typed.provider)
	case *deadlineProvider:
		return structuredTaskProviderLimits(typed.provider)
	default:
		return defaultMaxRequestBytes, maxProviderResponseBytes
	}
}

func structuredTaskReadLimit(providerLimit int, taskLimits ...int) int {
	if providerLimit <= 0 {
		providerLimit = maxProviderResponseBytes
	}
	limit := providerLimit
	if len(taskLimits) > 0 && taskLimits[0] > 0 && taskLimits[0] < limit {
		limit = taskLimits[0]
	}
	return limit
}

func (p *NoOpProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	provider := p.Name()
	if _, _, err := prepareStructuredTask(ctx, provider, task, sanitizer.DefaultRedactor()); err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	err := structuredTaskUnsupported(provider, task)
	observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
	return StructuredTaskResult{}, err
}

func (p *RuleBasedProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	provider := p.Name()
	if _, _, err := prepareStructuredTask(ctx, provider, task, p.redactor); err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	err := structuredTaskUnsupported(provider, task)
	observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
	return StructuredTaskResult{}, err
}
