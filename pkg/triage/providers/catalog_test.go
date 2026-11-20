package providers

import (
	"testing"

	"github.com/kubebee-com/sre/pkg/triage"
)

func TestCatalogIncludesNamedCloudAdapters(t *testing.T) {
	for _, name := range []string{"azureopenai", "bedrock", "sagemaker", "oci", "ibm", "cohere", "huggingface"} {
		spec, ok := Lookup(name)
		if !ok || !spec.Cloud || spec.WireProtocol == "" || spec.DocsURL == "" {
			t.Fatalf("Lookup(%q) = %#v, %v; want documented cloud provider", name, spec, ok)
		}
	}
	if _, err := New(triage.ProviderProfile{Provider: "unknown"}); err == nil {
		t.Fatal("New() accepted an unknown provider")
	}
	if spec, ok := Lookup("openai"); !ok || spec.CredentialEnv != "OPENAI_API_KEY" {
		t.Fatalf("Lookup(openai) = %#v, %v; want CredentialEnv OPENAI_API_KEY", spec, ok)
	}
	for _, spec := range Supported() {
		if spec.CredentialEnv == "L"+"LM_API_KEY" {
			t.Fatalf("provider %q still advertises retired credential env %q", spec.Name, spec.CredentialEnv)
		}
	}
}
