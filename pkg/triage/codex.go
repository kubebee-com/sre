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

type CodexProvider struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

func NewCodexProvider(apiKey, model, baseURL string) *CodexProvider {
	if model == "" {
		model = "gpt-4o"
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &CodexProvider{
		apiKey:  apiKey,
		model:   model,
		baseURL: baseURL,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *CodexProvider) Name() string {
	return "OpenAI/Codex (" + p.model + ")"
}

type openAIRequest struct {
	Model          string          `json:"model"`
	Messages       []openAIMessage `json:"messages"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *CodexProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	prompt := BuildPrompt(issue)

	reqBody := openAIRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{Role: "system", Content: SystemPrompt},
			{Role: "user", Content: prompt},
		},
		ResponseFormat: &responseFormat{Type: "json_object"},
	}

	raw, err := p.sendRequest(ctx, reqBody)
	if err != nil {
		return nil, err
	}

	return ParseDiagnosisJSON(raw, issue.ID, p.Name())
}

func (p *CodexProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	userContent := query
	if issue != nil {
		userContent = fmt.Sprintf("Cluster Anomaly Context:\n%s\n\nUser Question:\n%s", BuildPrompt(issue), query)
	}

	reqBody := openAIRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{Role: "system", Content: ChatSystemPrompt},
			{Role: "user", Content: userContent},
		},
	}

	return p.sendRequest(ctx, reqBody)
}

func (p *CodexProvider) sendRequest(ctx context.Context, reqBody openAIRequest) (string, error) {
	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/chat/completions", bytes.NewReader(payloadBytes))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai api call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai api error (%d): %s", resp.StatusCode, string(body))
	}

	var openAIResp openAIResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return "", fmt.Errorf("unmarshal openai response: %w", err)
	}

	if openAIResp.Error != nil {
		return "", fmt.Errorf("openai returned error: %s", openAIResp.Error.Message)
	}

	if len(openAIResp.Choices) == 0 {
		return "", fmt.Errorf("openai returned no choices")
	}

	return openAIResp.Choices[0].Message.Content, nil
}
