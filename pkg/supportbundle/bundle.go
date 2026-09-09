// Package supportbundle creates bounded, secret-safe diagnostic ZIP archives.
//
// The package deliberately has no process, browser, network, or shell
// integration. Callers provide already-collected scanner data and explicitly
// opt in to the resource payloads they want archived.
package supportbundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

const (
	SchemaVersion = "support-bundle/v1"

	ManifestPath    = "manifest.json"
	IssuesPath      = "scan/issues.json"
	AnalyzersPath   = "scan/analyzers.json"
	HistoryPath     = "scan/history.json"
	ResourcesPrefix = "resources/"

	DefaultMaxBundleBytes   int64 = 32 << 20
	DefaultMaxEntryBytes    int64 = 8 << 20
	DefaultMaxResourceBytes int64 = 1 << 20
	DefaultMaxResourceCount       = 128
	DefaultMaxIssueCount          = 10_000
	DefaultMaxAnalyzerCount       = 2_048
	DefaultMaxHistoryCount        = 10_000
)

var (
	ErrBundleTooLarge        = errors.New("support bundle exceeds size limit")
	ErrResourceTooLarge      = errors.New("support bundle resource exceeds size limit")
	ErrResourceCountExceeded = errors.New("support bundle resource count exceeds limit")
	ErrIssueCountExceeded    = errors.New("support bundle issue count exceeds limit")
	ErrAnalyzerCountExceeded = errors.New("support bundle analyzer count exceeds limit")
	ErrHistoryCountExceeded  = errors.New("support bundle history count exceeds limit")
	ErrResourcesNotOptedIn   = errors.New("resource payloads require explicit opt-in")
	ErrSecretResource        = errors.New("Secret resource payloads are not allowed")
	ErrInvalidResource       = errors.New("resource payload is invalid")
	ErrInvalidOptions        = errors.New("support bundle options are invalid")
	ErrOutputPath            = errors.New("support bundle output path is invalid")
)

// Input contains the diagnostic material to place in a bundle. Issues may be
// raw scanner issues; they are projected through scanner's sanitizer before
// serialization. History entries are sanitized again with the bundle's
// configured secret values so a caller can add a narrower policy at export
// time.
type Input struct {
	GeneratedAt time.Time

	Issues    []*scanner.Issue
	Analyzers []scanner.AnalyzerRun
	History   []scanner.HistoryEntry

	// Resources are ignored only when empty. If non-empty, IncludeResources
	// must be true; failing closed avoids silently exporting a caller's intent.
	Resources []ResourcePayload

	// SecretValues are never written to the archive. They are used only to
	// construct the redactor used for all text and structured payloads.
	SecretValues []string
}

// ResourcePayload is an explicitly selected, non-Secret Kubernetes resource.
// Data must contain valid JSON. The generated archive path does not include
// the supplied identity, preventing path traversal and accidental identity
// disclosure through ZIP member names.
type ResourcePayload struct {
	Kind      string
	Namespace string
	Name      string
	Data      json.RawMessage
}

// Options controls output and input bounds. Zero values use the documented
// defaults. Negative values are rejected.
type Options struct {
	IncludeResources bool

	MaxBundleBytes   int64
	MaxEntryBytes    int64
	MaxResourceBytes int64
	MaxResourceCount int
	MaxIssueCount    int
	MaxAnalyzerCount int
	MaxHistoryCount  int
}

// DefaultOptions returns conservative bounds suitable for local diagnostic
// exports.
func DefaultOptions() Options {
	return Options{
		MaxBundleBytes:   DefaultMaxBundleBytes,
		MaxEntryBytes:    DefaultMaxEntryBytes,
		MaxResourceBytes: DefaultMaxResourceBytes,
		MaxResourceCount: DefaultMaxResourceCount,
		MaxIssueCount:    DefaultMaxIssueCount,
		MaxAnalyzerCount: DefaultMaxAnalyzerCount,
		MaxHistoryCount:  DefaultMaxHistoryCount,
	}
}

// FileManifest describes a non-manifest ZIP member.
type FileManifest struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
}

// ResourceManifest records the sanitized identity of an included resource.
type ResourceManifest struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
}

// BundleCounts summarizes the selected material in the archive.
type BundleCounts struct {
	Issues    int `json:"issues"`
	Analyzers int `json:"analyzers"`
	History   int `json:"history"`
	Resources int `json:"resources"`
}

// RedactionSummary reports only aggregate redaction information. Removed
// values are never retained.
type RedactionSummary struct {
	Count int `json:"count"`
}

// Manifest is the versioned root document of every support bundle.
// Files intentionally excludes manifest.json because including the manifest's
// own hash would create a self-referential document.
type Manifest struct {
	SchemaVersion     string             `json:"schema_version"`
	Format            string             `json:"format"`
	CreatedAt         time.Time          `json:"created_at"`
	Files             []FileManifest     `json:"files"`
	Resources         []ResourceManifest `json:"resources,omitempty"`
	Counts            BundleCounts       `json:"counts"`
	ResourcesIncluded bool               `json:"resources_included"`
	Redactions        RedactionSummary   `json:"redactions"`
}

type bundleEntry struct {
	path      string
	mediaType string
	data      []byte
}

type preparedBundle struct {
	manifest []byte
	entries  []bundleEntry
}

type normalizedOptions struct {
	Options
}

// Build returns a complete support bundle in ZIP format.
func Build(input Input, options Options) ([]byte, error) {
	prepared, normalized, err := prepare(input, options)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := writeArchive(&output, prepared, normalized.MaxBundleBytes); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// Write writes a complete support bundle to writer. The caller owns writer;
// use Create when an atomic, owner-only filesystem output is required.
func Write(writer io.Writer, input Input, options Options) error {
	if writer == nil {
		return errors.New("support bundle writer is required")
	}
	prepared, normalized, err := prepare(input, options)
	if err != nil {
		return err
	}
	return writeArchive(writer, prepared, normalized.MaxBundleBytes)
}

// Create atomically replaces path with a support bundle. The temporary file
// lives beside the destination, is owner-only from creation, is synced before
// rename, and is removed on every pre-rename failure.
func Create(path string, input Input, options Options) error {
	if strings.TrimSpace(path) == "" || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return ErrOutputPath
	}

	prepared, normalized, err := prepare(input, options)
	if err != nil {
		return err
	}

	directory := filepath.Dir(path)
	base := filepath.Base(path)
	temporary, err := os.CreateTemp(directory, "."+base+".*.tmp")
	if err != nil {
		return fmt.Errorf("create support bundle temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = temporary.Close()
			_ = os.Remove(temporaryName)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict support bundle temporary file: %w", err)
	}
	if err := writeArchive(temporary, prepared, normalized.MaxBundleBytes); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync support bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close support bundle temporary file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace support bundle: %w", err)
	}
	removeTemporary = false
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict support bundle: %w", err)
	}

	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open support bundle directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync support bundle directory: %w", err)
	}
	return nil
}

func prepare(input Input, options Options) (preparedBundle, normalizedOptions, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return preparedBundle{}, normalizedOptions{}, err
	}
	if len(input.Resources) > 0 && !normalized.IncludeResources {
		return preparedBundle{}, normalized, ErrResourcesNotOptedIn
	}
	if len(input.Resources) > normalized.MaxResourceCount {
		return preparedBundle{}, normalized, fmt.Errorf("%w: got %d, limit %d", ErrResourceCountExceeded, len(input.Resources), normalized.MaxResourceCount)
	}
	if len(input.Issues) > normalized.MaxIssueCount {
		return preparedBundle{}, normalized, fmt.Errorf("%w: got %d, limit %d", ErrIssueCountExceeded, len(input.Issues), normalized.MaxIssueCount)
	}
	if len(input.Analyzers) > normalized.MaxAnalyzerCount {
		return preparedBundle{}, normalized, fmt.Errorf("%w: got %d, limit %d", ErrAnalyzerCountExceeded, len(input.Analyzers), normalized.MaxAnalyzerCount)
	}
	if len(input.History) > normalized.MaxHistoryCount {
		return preparedBundle{}, normalized, fmt.Errorf("%w: got %d, limit %d", ErrHistoryCountExceeded, len(input.History), normalized.MaxHistoryCount)
	}

	createdAt := input.GeneratedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	} else {
		createdAt = createdAt.UTC()
	}
	redactor := sanitizer.RedactorForSecrets(input.SecretValues...)
	var redactions RedactionSummary

	issues, issueRedactions := sanitizeIssues(input.Issues, redactor)
	redactions.Count += issueRedactions
	issuesData, err := marshalPretty(issueWires(issues))
	if err != nil {
		return preparedBundle{}, normalized, fmt.Errorf("encode support bundle issues: %w", err)
	}
	if err := checkEntrySize(IssuesPath, issuesData, normalized.MaxEntryBytes); err != nil {
		return preparedBundle{}, normalized, err
	}

	analyzers, analyzerRedactions := sanitizeAnalyzers(input.Analyzers, redactor)
	redactions.Count += analyzerRedactions
	analyzersData, err := marshalPretty(analyzers)
	if err != nil {
		return preparedBundle{}, normalized, fmt.Errorf("encode support bundle analyzers: %w", err)
	}
	if err := checkEntrySize(AnalyzersPath, analyzersData, normalized.MaxEntryBytes); err != nil {
		return preparedBundle{}, normalized, err
	}

	history, historyRedactions := sanitizeHistory(input.History, redactor)
	redactions.Count += historyRedactions
	historyData, err := marshalPretty(history)
	if err != nil {
		return preparedBundle{}, normalized, fmt.Errorf("encode support bundle history: %w", err)
	}
	if err := checkEntrySize(HistoryPath, historyData, normalized.MaxEntryBytes); err != nil {
		return preparedBundle{}, normalized, err
	}

	entries := []bundleEntry{
		{path: IssuesPath, mediaType: "application/json", data: issuesData},
		{path: AnalyzersPath, mediaType: "application/json", data: analyzersData},
		{path: HistoryPath, mediaType: "application/json", data: historyData},
	}
	resourceManifests := make([]ResourceManifest, 0, len(input.Resources))
	for index, resource := range input.Resources {
		entry, metadata, count, err := prepareResource(index, resource, redactor, normalized)
		if err != nil {
			return preparedBundle{}, normalized, err
		}
		redactions.Count += count
		entries = append(entries, entry)
		resourceManifests = append(resourceManifests, metadata)
	}
	sort.Slice(resourceManifests, func(i, j int) bool { return resourceManifests[i].Path < resourceManifests[j].Path })

	files := make([]FileManifest, 0, len(entries))
	for _, entry := range entries {
		digest := sha256.Sum256(entry.data)
		files = append(files, FileManifest{
			Path:      entry.path,
			Size:      int64(len(entry.data)),
			SHA256:    hex.EncodeToString(digest[:]),
			MediaType: entry.mediaType,
		})
	}
	manifest := Manifest{
		SchemaVersion:     SchemaVersion,
		Format:            "zip",
		CreatedAt:         createdAt,
		Files:             files,
		Resources:         resourceManifests,
		Counts:            BundleCounts{Issues: len(issues), Analyzers: len(analyzers), History: len(history), Resources: len(resourceManifests)},
		ResourcesIncluded: len(resourceManifests) > 0,
		Redactions:        redactions,
	}
	manifestData, err := marshalPretty(manifest)
	if err != nil {
		return preparedBundle{}, normalized, fmt.Errorf("encode support bundle manifest: %w", err)
	}
	if err := checkEntrySize(ManifestPath, manifestData, normalized.MaxEntryBytes); err != nil {
		return preparedBundle{}, normalized, err
	}

	totalSize := int64(len(manifestData))
	for _, entry := range entries {
		totalSize += int64(len(entry.data))
		if totalSize > normalized.MaxBundleBytes {
			return preparedBundle{}, normalized, fmt.Errorf("%w: uncompressed archive data is %d bytes, limit %d", ErrBundleTooLarge, totalSize, normalized.MaxBundleBytes)
		}
	}
	return preparedBundle{manifest: manifestData, entries: entries}, normalized, nil
}

func normalizeOptions(options Options) (normalizedOptions, error) {
	defaults := DefaultOptions()
	if options.MaxBundleBytes == 0 {
		options.MaxBundleBytes = defaults.MaxBundleBytes
	}
	if options.MaxEntryBytes == 0 {
		options.MaxEntryBytes = defaults.MaxEntryBytes
	}
	if options.MaxResourceBytes == 0 {
		options.MaxResourceBytes = defaults.MaxResourceBytes
	}
	if options.MaxResourceCount == 0 {
		options.MaxResourceCount = defaults.MaxResourceCount
	}
	if options.MaxIssueCount == 0 {
		options.MaxIssueCount = defaults.MaxIssueCount
	}
	if options.MaxAnalyzerCount == 0 {
		options.MaxAnalyzerCount = defaults.MaxAnalyzerCount
	}
	if options.MaxHistoryCount == 0 {
		options.MaxHistoryCount = defaults.MaxHistoryCount
	}
	if options.MaxBundleBytes < 0 || options.MaxEntryBytes < 0 || options.MaxResourceBytes < 0 || options.MaxResourceCount < 0 || options.MaxIssueCount < 0 || options.MaxAnalyzerCount < 0 || options.MaxHistoryCount < 0 {
		return normalizedOptions{}, ErrInvalidOptions
	}
	return normalizedOptions{Options: options}, nil
}

func sanitizeIssues(issues []*scanner.Issue, redactor *sanitizer.Redactor) ([]*scanner.SanitizedIssue, int) {
	result := make([]*scanner.SanitizedIssue, 0, len(issues))
	redactions := 0
	for _, issue := range issues {
		if issue == nil {
			continue
		}
		sanitized := scanner.SanitizeIssueWithRedactor(issue, redactor)
		sanitizeIssueEnums(sanitized, redactor, &redactions)
		result = append(result, sanitized)
	}
	return result, redactions
}

func sanitizeIssueEnums(issue *scanner.SanitizedIssue, redactor *sanitizer.Redactor, redactions *int) {
	if issue == nil {
		return
	}
	var count int
	severity, current := redactor.SanitizeTextWithReport(string(issue.Severity))
	count += current.RedactedCount
	category, current := redactor.SanitizeTextWithReport(string(issue.Category))
	count += current.RedactedCount
	issue.Severity = scanner.Severity(severity)
	issue.Category = scanner.IssueCategory(category)
	issue.Report.RedactedCount += count
	if count > 0 && redactions != nil {
		*redactions += count
	}
}

func sanitizeAnalyzers(analyzers []scanner.AnalyzerRun, redactor *sanitizer.Redactor) ([]scanner.AnalyzerRun, int) {
	result := make([]scanner.AnalyzerRun, len(analyzers))
	redactions := 0
	for index, analyzer := range analyzers {
		copy := analyzer
		copy.Info.Name, redactions = sanitizeText(copy.Info.Name, redactor, redactions)
		copy.Info.Resource, redactions = sanitizeText(copy.Info.Resource, redactor, redactions)
		copy.Info.Description, redactions = sanitizeText(copy.Info.Description, redactor, redactions)
		copy.Info.DocsURL, redactions = sanitizeURL(copy.Info.DocsURL, redactor, redactions)
		copy.Info.ParentKind, redactions = sanitizeText(copy.Info.ParentKind, redactor, redactions)
		copy.Error, redactions = sanitizeText(copy.Error, redactor, redactions)
		copy.Duration, redactions = sanitizeText(copy.Duration, redactor, redactions)
		result[index] = copy
	}
	return result, redactions
}

type historyWire struct {
	SchemaVersion string     `json:"schema_version"`
	Fingerprint   string     `json:"fingerprint"`
	Issue         *issueWire `json:"issue"`
	FirstSeen     time.Time  `json:"first_seen"`
	LastSeen      time.Time  `json:"last_seen"`
	Occurrences   int        `json:"occurrences"`
	Resolved      bool       `json:"resolved"`
}

func sanitizeHistory(history []scanner.HistoryEntry, redactor *sanitizer.Redactor) ([]historyWire, int) {
	result := make([]historyWire, len(history))
	redactions := 0
	for index, entry := range history {
		copy := historyWire{
			SchemaVersion: entry.SchemaVersion,
			Fingerprint:   entry.Fingerprint,
			FirstSeen:     entry.FirstSeen,
			LastSeen:      entry.LastSeen,
			Occurrences:   entry.Occurrences,
			Resolved:      entry.Resolved,
		}
		copy.SchemaVersion, redactions = sanitizeText(copy.SchemaVersion, redactor, redactions)
		copy.Fingerprint, redactions = sanitizeText(copy.Fingerprint, redactor, redactions)
		if entry.Issue != nil {
			sanitized := scanner.SanitizeIssueWithRedactor(entry.Issue.AsIssue(), redactor)
			sanitizeIssueEnums(sanitized, redactor, &redactions)
			copy.Issue = issueWireFrom(sanitized)
		}
		result[index] = copy
	}
	return result, redactions
}

// issueWire intentionally has no methods. scanner.SanitizedIssue has a
// defensive MarshalJSON method that uses the process default redactor; this
// local wire type ensures the bundle's explicit redactor is the final policy.
type issueWire scanner.SanitizedIssue

func issueWires(issues []*scanner.SanitizedIssue) []issueWire {
	result := make([]issueWire, 0, len(issues))
	for _, issue := range issues {
		if issue != nil {
			result = append(result, issueWire(*issue))
		}
	}
	return result
}

func issueWireFrom(issue *scanner.SanitizedIssue) *issueWire {
	if issue == nil {
		return nil
	}
	value := issueWire(*issue)
	return &value
}

func prepareResource(index int, resource ResourcePayload, redactor *sanitizer.Redactor, options normalizedOptions) (bundleEntry, ResourceManifest, int, error) {
	kind := strings.TrimSpace(resource.Kind)
	name := strings.TrimSpace(resource.Name)
	if kind == "" || name == "" || len(resource.Data) == 0 || !json.Valid(resource.Data) {
		return bundleEntry{}, ResourceManifest{}, 0, fmt.Errorf("%w: kind, name, and valid JSON data are required", ErrInvalidResource)
	}
	var value interface{}
	if err := json.Unmarshal(resource.Data, &value); err != nil {
		return bundleEntry{}, ResourceManifest{}, 0, fmt.Errorf("%w: decode data: %v", ErrInvalidResource, err)
	}
	if isSecretKind(kind) || containsSecretKind(value) {
		return bundleEntry{}, ResourceManifest{}, 0, ErrSecretResource
	}
	if int64(len(resource.Data)) > options.MaxResourceBytes {
		return bundleEntry{}, ResourceManifest{}, 0, fmt.Errorf("%w: raw payload is %d bytes, limit %d", ErrResourceTooLarge, len(resource.Data), options.MaxResourceBytes)
	}

	sanitizedText, report := redactor.SanitizeStructuredTextWithReport(string(resource.Data))
	var sanitized interface{}
	if err := json.Unmarshal([]byte(sanitizedText), &sanitized); err != nil {
		return bundleEntry{}, ResourceManifest{}, 0, fmt.Errorf("%w: sanitized data is not valid JSON", ErrInvalidResource)
	}
	sanitizedData, err := marshalPretty(sanitized)
	if err != nil {
		return bundleEntry{}, ResourceManifest{}, 0, fmt.Errorf("%w: encode data: %v", ErrInvalidResource, err)
	}
	if int64(len(sanitizedData)) > options.MaxResourceBytes {
		return bundleEntry{}, ResourceManifest{}, 0, fmt.Errorf("%w: sanitized payload is %d bytes, limit %d", ErrResourceTooLarge, len(sanitizedData), options.MaxResourceBytes)
	}

	path := resourcePath(index, resource)
	metadata := ResourceManifest{
		Path:      path,
		Kind:      kind,
		Namespace: strings.TrimSpace(resource.Namespace),
		Name:      name,
		Size:      int64(len(sanitizedData)),
	}
	metadata.Kind, report = sanitizeTextWithReport(metadata.Kind, redactor, report)
	metadata.Namespace, report = sanitizeTextWithReport(metadata.Namespace, redactor, report)
	metadata.Name, report = sanitizeTextWithReport(metadata.Name, redactor, report)
	return bundleEntry{path: path, mediaType: "application/json", data: sanitizedData}, metadata, report.RedactedCount, nil
}

func resourcePath(index int, resource ResourcePayload) string {
	identity := resource.Kind + "\x00" + resource.Namespace + "\x00" + resource.Name
	digest := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("%s%06d-%s.json", ResourcesPrefix, index, hex.EncodeToString(digest[:8]))
}

func containsSecretKind(value interface{}) bool {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, nested := range typed {
			if strings.EqualFold(strings.TrimSpace(key), "kind") {
				if kind, ok := nested.(string); ok && isSecretKind(kind) {
					return true
				}
			}
			if containsSecretKind(nested) {
				return true
			}
		}
	case []interface{}:
		for _, nested := range typed {
			if containsSecretKind(nested) {
				return true
			}
		}
	}
	return false
}

func isSecretKind(kind string) bool {
	canonical := strings.ToLower(strings.TrimSpace(kind))
	canonical = strings.TrimPrefix(canonical, "/")
	if slash := strings.LastIndexByte(canonical, '/'); slash >= 0 {
		canonical = canonical[slash+1:]
	}
	return canonical == "secret" || canonical == "secretlist"
}

func sanitizeText(value string, redactor *sanitizer.Redactor, count int) (string, int) {
	sanitized, report := redactor.SanitizeTextWithReport(value)
	return sanitized, count + report.RedactedCount
}

func sanitizeURL(value string, redactor *sanitizer.Redactor, count int) (string, int) {
	sanitized, report := redactor.SanitizeTextWithReport(value)
	return redactor.SanitizeURL(sanitized), count + report.RedactedCount
}

func sanitizeTextWithReport(value string, redactor *sanitizer.Redactor, report sanitizer.RedactionReport) (string, sanitizer.RedactionReport) {
	sanitized, current := redactor.SanitizeTextWithReport(value)
	report.RedactedCount += current.RedactedCount
	return sanitized, report
}

func marshalPretty(value interface{}) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func checkEntrySize(path string, data []byte, limit int64) error {
	if int64(len(data)) > limit {
		return fmt.Errorf("%w: %s is %d bytes, limit %d", ErrBundleTooLarge, path, len(data), limit)
	}
	return nil
}

func writeArchive(writer io.Writer, bundle preparedBundle, maxBytes int64) error {
	limited := &limitedWriter{writer: writer, limit: maxBytes}
	archive := zip.NewWriter(limited)
	manifestEntry := bundleEntry{path: ManifestPath, mediaType: "application/json", data: bundle.manifest}
	entries := make([]bundleEntry, 0, len(bundle.entries)+1)
	entries = append(entries, manifestEntry)
	entries = append(entries, bundle.entries...)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.path, Method: zip.Deflate}
		header.SetModTime(time.Unix(0, 0).UTC())
		header.SetMode(0o600)
		member, err := archive.CreateHeader(header)
		if err != nil {
			_ = archive.Close()
			return fmt.Errorf("create support bundle member %q: %w", entry.path, err)
		}
		if _, err := member.Write(entry.data); err != nil {
			_ = archive.Close()
			if errors.Is(err, ErrBundleTooLarge) {
				return err
			}
			return fmt.Errorf("write support bundle member %q: %w", entry.path, err)
		}
	}
	if err := archive.Close(); err != nil {
		if errors.Is(err, ErrBundleTooLarge) {
			return err
		}
		return fmt.Errorf("close support bundle archive: %w", err)
	}
	return nil
}

type limitedWriter struct {
	writer  io.Writer
	limit   int64
	written int64
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.limit-w.written {
		return 0, ErrBundleTooLarge
	}
	n, err := w.writer.Write(data)
	w.written += int64(n)
	if err == nil && n != len(data) {
		return n, io.ErrShortWrite
	}
	return n, err
}
