package triage

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

type HarnessProvider struct {
	commandPath  string
	extraArgs    []string
	secretValues []string
}

func (b *boundedBuffer) ReadFrom(reader io.Reader) (int64, error) {
	var total int64
	buffer := make([]byte, 32*1024)
	for {
		read, err := reader.Read(buffer)
		if read > 0 {
			_, _ = b.Write(buffer[:read])
			total += int64(read)
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

func NewHarnessProvider(commandPath string, extraArgs []string, secretValues ...string) *HarnessProvider {
	return &HarnessProvider{
		commandPath:  commandPath,
		extraArgs:    extraArgs,
		secretValues: append([]string(nil), secretValues...),
	}
}

func (p *HarnessProvider) Name() string {
	return "Agent Harness (" + p.commandPath + ")"
}

func (p *HarnessProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	prompt := fmt.Sprintf("%s\n\n%s", SystemPrompt, BuildPromptWithSecrets(issue, p.secretValues...))

	cmd := exec.CommandContext(ctx, p.commandPath, p.extraArgs...)
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		classified := classifyContextProviderError(err, p.Name(), "diagnose", ctx)
		observeProviderError(ctx, p.Name(), "diagnose", classified)
		return nil, classified
	}
	if stdout.truncated || stderr.truncated {
		err := providerError(ProviderErrorLimit, p.Name(), "diagnose", ErrProviderResponseTooLarge)
		observeProviderError(ctx, p.Name(), "diagnose", err)
		return nil, err
	}

	diagnosis, err := ParseDiagnosisJSON(stdout.String(), issue.ID, p.Name(), p.secretValues...)
	if err != nil {
		classified := providerError(ProviderErrorResponse, p.Name(), "diagnose", ErrProviderResponse)
		observeProviderError(ctx, p.Name(), "diagnose", classified)
		return nil, classified
	}
	return diagnosis, nil
}

func (p *HarnessProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	redactor := sanitizer.NewRedactor(p.secretValues...)
	query = redactor.SanitizeText(query)
	prompt := fmt.Sprintf("%s\n\nUser Question: %s", ChatSystemPrompt, query)
	if issue != nil {
		prompt = fmt.Sprintf("%s\n\n%s\n\nUser Question: %s", ChatSystemPrompt, BuildPromptWithSecrets(issue, p.secretValues...), query)
	}

	cmd := exec.CommandContext(ctx, p.commandPath, p.extraArgs...)
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		classified := classifyContextProviderError(err, p.Name(), "explain", ctx)
		observeProviderError(ctx, p.Name(), "explain", classified)
		return "", classified
	}
	if stdout.truncated || stderr.truncated {
		err := providerError(ProviderErrorLimit, p.Name(), "explain", ErrProviderResponseTooLarge)
		observeProviderError(ctx, p.Name(), "explain", err)
		return "", err
	}

	return redactor.SanitizeText(stdout.String()), nil
}

func (p *HarnessProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	provider := p.Name()
	redactor := sanitizer.NewRedactor(p.secretValues...)
	ctx, prepared, err := prepareStructuredTask(ctx, provider, task, redactor)
	if err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	prompt := fmt.Sprintf("%s\n\n%s", prepared.SystemPrompt, prepared.UserPrompt)

	cmd := exec.CommandContext(ctx, p.commandPath, p.extraArgs...)
	cmd.WaitDelay = 100 * time.Millisecond
	configureStructuredCommandCancellation(cmd)
	cmd.Stdin = strings.NewReader(prompt)

	stdout := boundedBuffer{limit: prepared.MaxOutputBytes}
	stderr := boundedBuffer{limit: prepared.MaxOutputBytes}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		classified := classifyContextProviderError(err, provider, prepared.Operation, ctx)
		observeProviderError(ctx, provider, prepared.Operation, classified)
		return StructuredTaskResult{}, classified
	}
	if stdout.truncated || stderr.truncated {
		err := providerError(ProviderErrorLimit, provider, prepared.Operation, ErrProviderResponseTooLarge)
		observeProviderError(ctx, provider, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}
	result, err := finalizeStructuredTaskResult(provider, prepared, StructuredTaskResult{Text: stdout.String()}, redactor)
	if err != nil {
		observeProviderError(ctx, provider, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}
	return result, nil
}
