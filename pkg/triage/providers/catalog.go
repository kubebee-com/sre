// Package providers contains the discoverable provider catalog. Provider
// behavior stays in pkg/triage so callers share one validation, redaction,
// cancellation, and error contract.
package providers

import (
	"sort"
	"strings"

	"github.com/kubebee-com/sre/pkg/triage"
)

type Spec struct {
	Name             string `json:"name"`
	DisplayName      string `json:"display_name"`
	WireProtocol     string `json:"wire_protocol"`
	DocsURL          string `json:"docs_url"`
	CredentialEnv    string `json:"credential_env,omitempty"`
	RequiresEndpoint bool   `json:"requires_endpoint"`
	Cloud            bool   `json:"cloud"`
}

var catalog = map[string]Spec{
	"azureopenai": {Name: "azureopenai", DisplayName: "Azure OpenAI", WireProtocol: "openai-chat", DocsURL: "https://learn.microsoft.com/azure/ai-services/openai/reference", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: true, Cloud: true},
	"bedrock":     {Name: "bedrock", DisplayName: "Amazon Bedrock", WireProtocol: "bedrock-generate", DocsURL: "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html", CredentialEnv: "AWS workload identity", RequiresEndpoint: true, Cloud: true},
	"claude":      {Name: "claude", DisplayName: "Anthropic Claude", WireProtocol: "anthropic-messages", DocsURL: "https://docs.anthropic.com/en/api/messages", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: false},
	"cohere":      {Name: "cohere", DisplayName: "Cohere", WireProtocol: "cohere-chat", DocsURL: "https://docs.cohere.com/reference/chat", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: true, Cloud: true},
	"custom":      {Name: "custom", DisplayName: "Custom OpenAI-compatible", WireProtocol: "openai-chat", DocsURL: "https://github.com/openai/openai-openapi", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: true},
	"deepseek":    {Name: "deepseek", DisplayName: "DeepSeek", WireProtocol: "openai-chat", DocsURL: "https://api-docs.deepseek.com/", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: false},
	"gemini":      {Name: "gemini", DisplayName: "Google Gemini", WireProtocol: "gemini-content", DocsURL: "https://ai.google.dev/api/generate-content", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: true, Cloud: true},
	"groq":        {Name: "groq", DisplayName: "Groq", WireProtocol: "openai-chat", DocsURL: "https://console.groq.com/docs/api-reference", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: false},
	"harness":     {Name: "harness", DisplayName: "External CLI harness", WireProtocol: "stdin-stdout", DocsURL: "https://github.com/kubebee-com/sre", RequiresEndpoint: false},
	"huggingface": {Name: "huggingface", DisplayName: "Hugging Face", WireProtocol: "inference", DocsURL: "https://huggingface.co/docs/api-inference/index", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: true, Cloud: true},
	"ibm":         {Name: "ibm", DisplayName: "IBM watsonx.ai", WireProtocol: "watsonx-generation", DocsURL: "https://www.ibm.com/docs/en/watsonx", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: true, Cloud: true},
	"litellm":     {Name: "litellm", DisplayName: "LiteLLM", WireProtocol: "openai-chat", DocsURL: "https://docs.litellm.ai/docs/", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: false},
	"localai":     {Name: "localai", DisplayName: "LocalAI", WireProtocol: "openai-chat", DocsURL: "https://localai.io/features/openai-compatibility/", RequiresEndpoint: false},
	"noop":        {Name: "noop", DisplayName: "No explanation", WireProtocol: "none", DocsURL: "https://github.com/kubebee-com/sre", RequiresEndpoint: false},
	"oci":         {Name: "oci", DisplayName: "Oracle Cloud Infrastructure Generative AI", WireProtocol: "oci-generate", DocsURL: "https://docs.oracle.com/en-us/iaas/api/#/en/generative-ai-inference/", CredentialEnv: "OCI workload identity", RequiresEndpoint: true, Cloud: true},
	"ollama":      {Name: "ollama", DisplayName: "Ollama", WireProtocol: "openai-chat", DocsURL: "https://github.com/ollama/ollama/blob/main/docs/openai.md", RequiresEndpoint: false},
	"openai":      {Name: "openai", DisplayName: "OpenAI", WireProtocol: "openai-chat", DocsURL: "https://platform.openai.com/docs/api-reference/chat", CredentialEnv: "LLM_API_KEY", RequiresEndpoint: false},
	"rule":        {Name: "rule", DisplayName: "Deterministic rule engine", WireProtocol: "local-rules", DocsURL: "https://github.com/kubebee-com/sre", RequiresEndpoint: false},
	"sagemaker":   {Name: "sagemaker", DisplayName: "Amazon SageMaker", WireProtocol: "sagemaker-invoke", DocsURL: "https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_runtime_InvokeEndpoint.html", CredentialEnv: "AWS workload identity", RequiresEndpoint: true, Cloud: true},
	"vertex":      {Name: "vertex", DisplayName: "Google Vertex AI", WireProtocol: "gemini-content", DocsURL: "https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/inference", CredentialEnv: "Google workload identity", RequiresEndpoint: true, Cloud: true},
}

func Supported() []Spec {
	result := make([]Spec, 0, len(catalog))
	for _, spec := range catalog {
		result = append(result, spec)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func Lookup(name string) (Spec, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	canonical := name
	if aliases := map[string]string{"azure": "azureopenai", "azure-openai": "azureopenai", "aws-bedrock": "bedrock", "cohere": "cohere", "gemini": "gemini", "vertex-ai": "vertex", "hugging-face": "huggingface", "watsonx": "ibm", "oracle": "oci", "aws-sagemaker": "sagemaker"}; aliases[name] != "" {
		canonical = aliases[name]
	}
	spec, ok := catalog[canonical]
	return spec, ok
}

func New(profile triage.ProviderProfile) (triage.TriageProvider, error) {
	return triage.NewProviderFromProfile(profile)
}
