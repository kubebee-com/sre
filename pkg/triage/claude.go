package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

type ClaudeProvider struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

func NewClaudeProvider(apiKey, model, baseURL string) *ClaudeProvider {
	if model == "" {
		model = "claude-3-7-sonnet-20250219"
	}
	if baseURL == "" {
		baseURL = "https://api.anthropic.com/v1"
	}
	return &ClaudeProvider{
		apiKey:  apiKey,
		model:   model,
		baseURL: baseURL,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *ClaudeProvider) Name() string {
	return "Anthropic Claude (" + p.model + ")"
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *ClaudeProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	prompt := BuildPrompt(issue)

	reqBody := anthropicRequest{
		Model:     p.model,
		MaxTokens: 2048,
		System:    SystemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	}

	raw, err := p.sendRequest(ctx, reqBody)
	if err != nil {
		return nil, err
	}

	return ParseDiagnosisJSON(raw, issue.ID, p.Name())
}

func (p *ClaudeProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	userContent := query
	if issue != nil {
		userContent = fmt.Sprintf("Cluster Anomaly Context:\n%s\n\nUser Question:\n%s", BuildPrompt(issue), query)
	}

	reqBody := anthropicRequest{
		Model:     p.model,
		MaxTokens: 2048,
		System:    ChatSystemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userContent},
		},
	}

	return p.sendRequest(ctx, reqBody)
}

func (p *ClaudeProvider) sendRequest(ctx context.Context, reqBody anthropicRequest) (string, error) {
	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/messages", bytes.NewReader(payloadBytes))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("claude api call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("claude api error (%d): %s", resp.StatusCode, string(body))
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(body, &anthropicResp); err != nil {
		return "", fmt.Errorf("unmarshal claude response: %w", err)
	}

	if len(anthropicResp.Content) == 0 {
		return "", fmt.Errorf("claude returned empty content")
	}

	return anthropicResp.Content[0].Text, nil
}
