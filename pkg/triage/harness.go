package triage

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/kubebee-com/sre/pkg/scanner"
)

type HarnessProvider struct {
	commandPath string
	extraArgs   []string
}

func NewHarnessProvider(commandPath string, extraArgs []string) *HarnessProvider {
	return &HarnessProvider{
		commandPath: commandPath,
		extraArgs:   extraArgs,
	}
}

func (p *HarnessProvider) Name() string {
	return "Agent Harness (" + p.commandPath + ")"
}

func (p *HarnessProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	prompt := fmt.Sprintf("%s\n\n%s", SystemPrompt, BuildPrompt(issue))

	cmd := exec.CommandContext(ctx, p.commandPath, p.extraArgs...)
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("harness exec failed (%w): %s", err, stderr.String())
	}

	return parseJSONResponse(issue.ID, stdout.String(), p.Name())
}
