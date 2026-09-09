package supportbundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestBuildSanitizesScanInputsAndIncludesOptInResources(t *testing.T) {
	const secret = "support-bundle-test-secret"
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	issue := &scanner.Issue{
		ID:            "issue-1",
		Namespace:     "ops",
		Kind:          "Pod",
		Name:          "worker",
		Severity:      scanner.SeverityHigh,
		Category:      scanner.IssueCategory(secret),
		Summary:       "worker is restarting",
		Details:       "authorization: Bearer " + secret,
		LogsSnippet:   "password: " + secret,
		Events:        []string{"token: " + secret},
		SpecSnippet:   `{"api_key":"` + secret + `"}`,
		FirstObserved: now,
		LastObserved:  now,
	}
	issue.Parent = &scanner.ResourceRef{Namespace: "ops", Kind: "Deployment", Name: "worker", UID: secret}

	historyIssue := *issue
	historyIssue.ID = "history-issue"
	history := []scanner.HistoryEntry{{
		SchemaVersion: "scan-history/v1",
		Fingerprint:   "fingerprint-1",
		Issue:         scanner.SanitizeIssue(&historyIssue),
		FirstSeen:     now,
		LastSeen:      now,
		Occurrences:   2,
		Resolved:      false,
	}}

	archive, err := Build(Input{
		GeneratedAt: now,
		Issues:      []*scanner.Issue{issue},
		Analyzers: []scanner.AnalyzerRun{{
			Info:  scanner.AnalyzerInfo{Name: "pods", Resource: "pods", Description: "pod checks"},
			Error: "provider token: " + secret,
		}},
		History: history,
		Resources: []ResourcePayload{{
			Kind:      "ConfigMap",
			Namespace: "ops",
			Name:      "worker-config",
			Data:      json.RawMessage(`{"api_key":"` + secret + `","mode":"safe"}`),
		}},
		SecretValues: []string{secret},
	}, Options{IncludeResources: true})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	files := readArchive(t, archive)
	manifestBytes := files[ManifestPath]
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		t.Fatalf("manifest schema_version = %q, want %q", manifest.SchemaVersion, SchemaVersion)
	}
	if !manifest.ResourcesIncluded || manifest.Counts.Resources != 1 {
		t.Fatalf("manifest resource metadata = %#v", manifest)
	}
	if manifest.Counts.Issues != 1 || manifest.Counts.Analyzers != 1 || manifest.Counts.History != 1 {
		t.Fatalf("manifest counts = %#v", manifest.Counts)
	}
	if manifest.Redactions.Count == 0 {
		t.Fatal("manifest does not record redactions")
	}

	for name, content := range files {
		if strings.Contains(string(content), secret) {
			t.Fatalf("archive member %q leaked configured secret", name)
		}
	}
	if _, ok := files[IssuesPath]; !ok {
		t.Fatalf("archive does not contain %q", IssuesPath)
	}
	if _, ok := files[AnalyzersPath]; !ok {
		t.Fatalf("archive does not contain %q", AnalyzersPath)
	}
	if _, ok := files[HistoryPath]; !ok {
		t.Fatalf("archive does not contain %q", HistoryPath)
	}
	if got := countPrefix(files, ResourcesPrefix); got != 1 {
		t.Fatalf("resource member count = %d, want 1", got)
	}

	for _, entry := range manifest.Files {
		payload, ok := files[entry.Path]
		if !ok {
			t.Fatalf("manifest references missing member %q", entry.Path)
		}
		if int64(len(payload)) != entry.Size {
			t.Fatalf("manifest size for %q = %d, actual %d", entry.Path, entry.Size, len(payload))
		}
		digest := sha256.Sum256(payload)
		if got := hex.EncodeToString(digest[:]); got != entry.SHA256 {
			t.Fatalf("manifest hash for %q = %q, actual %q", entry.Path, entry.SHA256, got)
		}
	}
}

func TestBuildRequiresResourceOptInAndRejectsSecrets(t *testing.T) {
	input := Input{Resources: []ResourcePayload{{Kind: "ConfigMap", Name: "config", Data: json.RawMessage(`{}`)}}}
	if _, err := Build(input, Options{}); !errors.Is(err, ErrResourcesNotOptedIn) {
		t.Fatalf("Build() error = %v, want ErrResourcesNotOptedIn", err)
	}

	secretKinds := []ResourcePayload{
		{Kind: "Secret", Name: "credentials", Data: json.RawMessage(`{"kind":"ConfigMap"}`)},
		{Kind: "ConfigMap", Name: "credentials", Data: json.RawMessage(`{"kind":"Secret","data":{"password":"value"}}`)},
		{Kind: "SecretList", Name: "credentials", Data: json.RawMessage(`{"items":[]}`)},
	}
	for _, resource := range secretKinds {
		_, err := Build(Input{Resources: []ResourcePayload{resource}}, Options{IncludeResources: true})
		if !errors.Is(err, ErrSecretResource) {
			t.Errorf("Build(%q) error = %v, want ErrSecretResource", resource.Kind, err)
		}
	}
}

func TestCreateIsAtomicAndUsesOwnerOnlyPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "support-bundle.zip")
	if err := os.WriteFile(path, []byte("previous bundle"), 0o600); err != nil {
		t.Fatalf("seed output: %v", err)
	}

	input := Input{Issues: []*scanner.Issue{{ID: "issue", Details: strings.Repeat("x", 4096)}}}
	err := Create(path, input, Options{MaxBundleBytes: 1})
	if !errors.Is(err, ErrBundleTooLarge) {
		t.Fatalf("Create() error = %v, want ErrBundleTooLarge", err)
	}
	previous, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read preserved output: %v", readErr)
	}
	if string(previous) != "previous bundle" {
		t.Fatalf("failed create replaced existing output with %q", previous)
	}
	if leftovers, globErr := filepath.Glob(filepath.Join(directory, ".support-bundle.zip.*.tmp")); globErr != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files after failed create = %v (glob error %v)", leftovers, globErr)
	}

	if err := Create(path, Input{Issues: []*scanner.Issue{{ID: "ok"}}}, Options{}); err != nil {
		t.Fatalf("successful Create() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("output permissions = %#o, want 0600", got)
	}
	if _, err := zip.NewReader(bytes.NewReader(mustReadFile(t, path)), info.Size()); err != nil {
		t.Fatalf("created output is not a ZIP archive: %v", err)
	}
}

func TestBuildEnforcesResourceAndRecordBounds(t *testing.T) {
	resource := ResourcePayload{Kind: "ConfigMap", Name: "config", Data: json.RawMessage(`{"value":"large"}`)}
	if _, err := Build(Input{Resources: []ResourcePayload{resource}}, Options{IncludeResources: true, MaxResourceBytes: 4}); !errors.Is(err, ErrResourceTooLarge) {
		t.Fatalf("resource limit error = %v, want ErrResourceTooLarge", err)
	}

	if _, err := Build(Input{Resources: []ResourcePayload{resource, resource}}, Options{IncludeResources: true, MaxResourceCount: 1}); !errors.Is(err, ErrResourceCountExceeded) {
		t.Fatalf("resource count error = %v, want ErrResourceCountExceeded", err)
	}

	if _, err := Build(Input{Issues: []*scanner.Issue{{ID: "one"}, {ID: "two"}}}, Options{MaxIssueCount: 1}); !errors.Is(err, ErrIssueCountExceeded) {
		t.Fatalf("issue count error = %v, want ErrIssueCountExceeded", err)
	}
}

func TestGeneratedResourcePathsCannotEscapeArchiveRoot(t *testing.T) {
	archive, err := Build(Input{
		Resources: []ResourcePayload{{Kind: "ConfigMap", Namespace: "../../ops", Name: "../config/../../x", Data: json.RawMessage(`{"safe":true}`)}},
	}, Options{IncludeResources: true})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	files := readArchive(t, archive)
	for name := range files {
		if filepath.IsAbs(name) || strings.Contains(name, "..") || strings.Contains(name, "\\") {
			t.Fatalf("unsafe archive path %q", name)
		}
	}
}

func TestProviderKeyHelpURLUsesExplicitAllowlist(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{provider: "openai", want: "https://platform.openai.com/api-keys"},
		{provider: "codex", want: "https://platform.openai.com/api-keys"},
		{provider: "anthropic", want: "https://console.anthropic.com/settings/keys"},
		{provider: "claude", want: "https://console.anthropic.com/settings/keys"},
		{provider: "groq", want: "https://console.groq.com/keys"},
	}
	for _, test := range tests {
		got, ok := ProviderKeyHelpURL(test.provider)
		if !ok || got != test.want {
			t.Errorf("ProviderKeyHelpURL(%q) = %q, %v; want %q, true", test.provider, got, ok, test.want)
		}
	}
	for _, provider := range []string{"", "custom", "https://evil.example/keys", "unknown"} {
		if got, ok := ProviderKeyHelpURL(provider); ok || got != "" {
			t.Errorf("ProviderKeyHelpURL(%q) = %q, %v; want empty, false", provider, got, ok)
		}
	}
}

func readArchive(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open ZIP: %v", err)
	}
	files := make(map[string][]byte, len(reader.File))
	for _, entry := range reader.File {
		if entry.Name == "" || strings.HasSuffix(entry.Name, "/") {
			t.Fatalf("unexpected ZIP directory entry %q", entry.Name)
		}
		file, err := entry.Open()
		if err != nil {
			t.Fatalf("open ZIP member %q: %v", entry.Name, err)
		}
		content, readErr := io.ReadAll(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read ZIP member %q: read=%v close=%v", entry.Name, readErr, closeErr)
		}
		files[entry.Name] = content
	}
	return files
}

func countPrefix(files map[string][]byte, prefix string) int {
	count := 0
	for name := range files {
		if strings.HasPrefix(name, prefix) {
			count++
		}
	}
	return count
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
