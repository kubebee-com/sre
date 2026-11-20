package agentharness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

// LocalRunner executes `codex` (default) or `agy` directly as a local
// subprocess for non-cluster development or CLI usage.
type LocalRunner struct {
	cfg Config
}

func NewLocalRunner(cfg Config) *LocalRunner {
	return &LocalRunner{cfg: cfg.Normalized()}
}

func (r *LocalRunner) Config() Config {
	return r.cfg
}

func (r *LocalRunner) CreateSolution(ctx context.Context, issue *scanner.Issue, requested HarnessKind) (*Solution, error) {
	if issue == nil {
		return nil, errors.New("issue is required")
	}
	harness, err := r.cfg.ResolveHarness(string(requested))
	if err != nil {
		return nil, err
	}
	prompt := BuildPlanPrompt(issue, r.cfg.GitOpsRepoURL, r.cfg.SecretValues...)
	output, err := r.run(ctx, harness, PhasePlan, prompt)
	if err != nil {
		return nil, err
	}
	return ParseSolutionOutput(output, harness, "local", r.cfg.SecretValues...)
}

func (r *LocalRunner) ApplySolution(ctx context.Context, req ApplyRequest) (string, error) {
	if strings.TrimSpace(req.ProposalID) == "" {
		return "", errors.New("proposal ID is required")
	}
	if strings.TrimSpace(req.ApprovedBy) == "" {
		return "", errors.New("approved actor is required before running apply agent")
	}
	harness, err := r.cfg.ResolveHarness(string(req.Harness))
	if err != nil {
		return "", err
	}
	prompt := BuildApplyPrompt(req, r.cfg.GitOpsRepoURL, r.cfg.SecretValues...)
	output, err := r.run(ctx, harness, PhaseApply, prompt)
	if err != nil {
		return "", err
	}
	redactor := sanitizer.RedactorForSecrets(r.cfg.SecretValues...)
	summary := strings.TrimSpace(redactor.SanitizeText(output))
	if summary == "" {
		return fmt.Sprintf("Local agent harness %s completed remediation", harness), nil
	}
	if len(summary) > 4000 {
		summary = summary[len(summary)-4000:]
	}
	return fmt.Sprintf("Local agent harness %s: %s", harness, summary), nil
}

func (r *LocalRunner) run(ctx context.Context, harness HarnessKind, phase Phase, prompt string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	spec, err := BuildCommandSpec(r.cfg, harness, phase, prompt)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(runCtx, spec.Binary, spec.Args...)
	if spec.UseStdin {
		cmd.Stdin = strings.NewReader(spec.PromptText)
	}
	var stdout, stderr cappedBuffer
	stdout.limit = MaxCapturedLogBytes
	stderr.limit = MaxCapturedLogBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		redactor := sanitizer.RedactorForSecrets(r.cfg.SecretValues...)
		errDetail := strings.TrimSpace(redactor.SanitizeText(stderr.String()))
		if errDetail != "" {
			return "", fmt.Errorf("agent harness %s failed: %w (%s)", harness, err, errDetail)
		}
		return "", fmt.Errorf("agent harness %s failed: %w", harness, err)
	}
	return stdout.String(), nil
}

type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return b.buf.Write(p)
	}
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) <= remaining {
			_, _ = b.buf.Write(p)
		} else {
			_, _ = b.buf.Write(p[:remaining])
		}
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	return b.buf.String()
}
