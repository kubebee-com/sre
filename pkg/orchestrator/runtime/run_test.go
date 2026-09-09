package runtime

import (
	"context"
	"testing"
)

func TestUnifiedSettingsOverrideLegacy(t *testing.T) {
	t.Setenv("SRE_CONFIG", "new")
	t.Setenv("SRE_ENTERPRISE_CONFIG", "old")
	if got := setting("SRE_CONFIG", "SRE_ENTERPRISE_CONFIG"); got != "new" {
		t.Fatal(got)
	}
	t.Setenv("SRE_CONFIG", "")
	if got := setting("SRE_CONFIG", "SRE_ENTERPRISE_CONFIG"); got != "" {
		t.Fatal("empty explicit setting used old credential", got)
	}
}
func TestMissingConfigurationFailsBeforeStarting(t *testing.T) {
	t.Setenv("SRE_CONFIG", "/nonexistent-sre-config")
	if err := Run(context.Background()); err == nil {
		t.Fatal("missing configuration accepted")
	}
}
