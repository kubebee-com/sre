package legacyserver

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDeploymentProbesUsePublicHealthEndpoints(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate deployment manifest")
	}
	manifestPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "deploy", "k8s", "deployment.yaml")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read deployment manifest: %v", err)
	}

	manifestText := string(manifest)
	if !strings.Contains(manifestText, "path: /healthz") {
		t.Error("deployment liveness probe does not use public /healthz")
	}
	if !strings.Contains(manifestText, "path: /readyz") {
		t.Error("deployment readiness probe does not use public /readyz")
	}
	if strings.Contains(manifestText, "path: /api/status") {
		t.Error("deployment probes still use protected /api/status")
	}
	if strings.Contains(manifestText, "name: sre-agent-secrets\n                optional: true") {
		t.Error("deployment allows the API token secret to be absent")
	}
	if !strings.Contains(manifestText, "key: SRE_API_TOKEN") {
		t.Error("deployment does not require the SRE_API_TOKEN secret key")
	}
	if !strings.Contains(manifestText, "name: SRE_REQUIRE_API_TOKEN\n              value: \"true\"") {
		t.Error("deployment does not explicitly require a nonblank API token at startup")
	}
	if !strings.Contains(manifestText, "name: SRE_TRUSTED_CLIENT_IP_HEADER\n              value: X-Forwarded-For") {
		t.Error("deployment does not configure the trusted client address header")
	}
	if !strings.Contains(manifestText, "name: SRE_TRUSTED_PROXY_CIDRS\n              value: \"\"") {
		t.Error("deployment trusts forwarded client addresses without an operator-supplied proxy CIDR")
	}
	if strings.Contains(manifestText, "name: SRE_TRUSTED_PROXY_CIDRS\n              value: 10.244.0.0/16") {
		t.Error("deployment still uses the broad pod CIDR as a trusted proxy boundary")
	}

	examplePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "deploy", "k8s", "secret.example.yaml")
	example, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("read secret example: %v", err)
	}
	if !strings.Contains(string(example), "SRE_API_TOKEN:") {
		t.Error("secret example does not document the required API token")
	}

	ingressPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "deploy", "k8s", "ingress.yaml")
	ingress, err := os.ReadFile(ingressPath)
	if err != nil {
		t.Fatalf("read ingress manifest: %v", err)
	}
	if strings.Contains(string(ingress), "compute-full-forwarded-for") {
		t.Error("application Ingress carries a controller-wide forwarded-for setting")
	}

	readmePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "docs", "legacy-standalone.md")
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read trusted ingress documentation: %v", err)
	}
	readmeText := string(readme)
	for _, marker := range []string{
		"ingress-nginx controller ConfigMap",
		`use-forwarded-headers: "false"`,
		`compute-full-forwarded-for: "false"`,
	} {
		if !strings.Contains(readmeText, marker) {
			t.Errorf("trusted ingress documentation missing controller setting %q", marker)
		}
	}
}
