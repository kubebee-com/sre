package orchestrator

import (
	"strings"
	"testing"
)

func TestDeploymentConfigCannotEnableLegacyHarnessOrInlineSecrets(t *testing.T) {
	valid := `{"applications":[{"scope":{"organization_id":"o","cluster_id":"c","application_id":"a"},"owner_group":"team"}],"bindings":[],"providers":[{"id":"safe","provider":"rule","scopes":[{"organization_id":"o","cluster_id":"c","application_id":"a"}]}]}`
	if _, err := ReadDeploymentConfig(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(valid, `"provider":"rule"`, `"provider":"harness"`, 1), strings.Replace(valid, `"provider":"rule"`, `"provider":"openai","api_key":"inline-secret"`, 1), strings.Replace(valid, `"owner_group":"team"`, `"owner_group":""`, 1)} {
		if _, err := ReadDeploymentConfig(strings.NewReader(bad)); err == nil {
			t.Fatal("unsafe deployment config accepted")
		}
	}
}

func TestRemoteProfilesDoNotResolveOrTransmitProviderSecrets(t *testing.T) {
	t.Setenv("AGENT_TEST_PROVIDER_KEY", "")
	config, err := ReadDeploymentConfig(strings.NewReader(`{"applications":[{"scope":{"organization_id":"o","cluster_id":"c","application_id":"a"},"owner_group":"team"}],"bindings":[],"providers":[{"id":"safe","provider":"openai","model":"gpt-4o-mini","api_key_env":"AGENT_TEST_PROVIDER_KEY","credential_version":"v1","scopes":[{"organization_id":"o","cluster_id":"c","application_id":"a"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := config.BuildRemoteProfiles()
	if err != nil || len(profiles) != 1 {
		t.Fatal("central metadata requires agent secret", err)
	}
	if profiles[0].Runner != nil || profiles[0].Metadata.APIKeyEnv != "AGENT_TEST_PROVIDER_KEY" || profiles[0].Version == "" {
		t.Fatal("remote provider governance missing")
	}
}
