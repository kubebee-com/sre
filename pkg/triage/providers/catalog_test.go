package providers

import (
	"testing"

	"github.com/kubebee-com/sre/pkg/triage"
)

func TestCatalogIncludesNamedCloudAdapters(t *testing.T) {
	for _, name := range []string{"azureopenai", "bedrock", "sagemaker", "gemini", "vertex", "oci", "ibm", "cohere", "huggingface"} {
		spec, ok := Lookup(name)
		if !ok || !spec.Cloud || spec.WireProtocol == "" || spec.DocsURL == "" {
			t.Fatalf("Lookup(%q) = %#v, %v; want documented cloud provider", name, spec, ok)
		}
	}
	if _, err := New(triage.ProviderProfile{Provider: "unknown"}); err == nil {
		t.Fatal("New() accepted an unknown provider")
	}
}
