// Package plugin implements the versioned external analyzer boundary.
//
// Plugins are read-only gRPC analyzers. The client owns its connection, uses
// TLS by default, validates the endpoint before dialing, and exposes only the
// same sanitized scanner.Analyzer contract as built-in analyzers.
package plugin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	apiv1 "github.com/kubebee-com/sre/api/v1"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	SchemaVersion       = "plugin/v1"
	DefaultTimeout      = 30 * time.Second
	DefaultMaxRecvBytes = 1 << 20
	DefaultMaxSendBytes = 256 << 10
	DefaultMaxFindings  = 2048
	DefaultMaxString    = 8 << 10
	MaxTimeout          = 5 * time.Minute
	MaxFindings         = 16 << 10
	MaxMessageBytes     = 16 << 20
	MaxStringBytes      = 1 << 20
)

var (
	ErrMetadataRequired    = errors.New("plugin metadata is required")
	ErrMetadataInvalid     = errors.New("plugin metadata is invalid")
	ErrEndpointNotAllowed  = errors.New("plugin endpoint is not allowed")
	ErrTLSRequired         = errors.New("plugin TLS is required")
	ErrPluginClosed        = errors.New("plugin client is closed")
	ErrPluginUnavailable   = errors.New("plugin is unavailable")
	ErrPluginResponse      = errors.New("plugin response is invalid")
	ErrPluginResponseLimit = errors.New("plugin response exceeds limit")
	ErrPluginQuota         = errors.New("plugin concurrency quota is exhausted")
)

// Metadata is the sanitized identity advertised to the scanner catalog.
type Metadata struct {
	Name        string
	Resource    string
	Description string
	DocsURL     string
	Version     string
	ReadOnly    bool
}

// Options controls one plugin connection. Endpoint must be HTTPS unless the
// caller explicitly enables insecure loopback for a local development/test
// sidecar. DialContext is an injected transport seam for bufconn and does not
// weaken endpoint validation when a real endpoint is used.
type Options struct {
	Metadata              Metadata
	Endpoint              string
	AllowedEndpoints      []string
	TLSConfig             *tls.Config
	AllowInsecureLoopback bool
	DialContext           func(context.Context, string) (net.Conn, error)
	Timeout               time.Duration
	MaxReceiveBytes       int
	MaxSendBytes          int
	MaxFindings           int
	MaxStringBytes        int
	MaxConcurrent         int
	Token                 string
	SecretValues          []string
}

// Client is an external analyzer that implements scanner.Analyzer. It owns
// the gRPC connection and must be closed by its creator or registry.
type Client struct {
	metadata scanner.AnalyzerInfo
	endpoint string
	options  normalizedOptions
	redactor *sanitizer.Redactor
	quota    chan struct{}

	connectMu sync.Mutex
	mu        sync.Mutex
	conn      *grpc.ClientConn
	closed    bool
	closeOnce sync.Once
}

type normalizedOptions struct {
	Options
	tlsConfig *tls.Config
}

// NewClient validates plugin metadata and transport policy without contacting
// the sidecar. The first analysis or Health call establishes the connection.
func NewClient(options Options) (*Client, error) {
	if strings.TrimSpace(options.Metadata.Name) == "" || strings.TrimSpace(options.Metadata.Resource) == "" || strings.TrimSpace(options.Metadata.Description) == "" {
		return nil, ErrMetadataRequired
	}
	metadata := options.Metadata
	if !metadata.ReadOnly {
		return nil, ErrMetadataInvalid
	}
	metadata.Name = strings.TrimSpace(metadata.Name)
	metadata.Resource = strings.TrimSpace(metadata.Resource)
	metadata.Description = strings.TrimSpace(metadata.Description)
	metadata.DocsURL = strings.TrimSpace(metadata.DocsURL)
	metadata.Version = strings.TrimSpace(metadata.Version)
	if !safeIdentifier(metadata.Name) || len(metadata.Name) > 128 || len(metadata.Resource) > 128 || len(metadata.Description) > 4096 || len(metadata.Version) > 128 || strings.ContainsAny(metadata.Resource+metadata.Description+metadata.Version, "\r\n\x00") {
		return nil, ErrMetadataInvalid
	}
	if metadata.DocsURL != "" {
		parsed, err := url.Parse(metadata.DocsURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || strings.ContainsAny(metadata.DocsURL, "\r\n\x00") {
			return nil, ErrMetadataInvalid
		}
	}
	endpoint := strings.TrimSpace(options.Endpoint)
	if endpoint == "" {
		return nil, ErrEndpointNotAllowed
	}
	parsedEndpoint, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	loopback := isLoopbackHost(parsedEndpoint.Hostname())
	if parsedEndpoint.Scheme != "https" && !(loopback && options.AllowInsecureLoopback) {
		return nil, ErrTLSRequired
	}
	if len(options.AllowedEndpoints) > 0 && !matchesEndpoint(parsedEndpoint, options.AllowedEndpoints) {
		return nil, ErrEndpointNotAllowed
	}
	if options.Timeout <= 0 {
		options.Timeout = DefaultTimeout
	}
	if options.Timeout > MaxTimeout {
		return nil, ErrMetadataInvalid
	}
	if len(options.Token) > DefaultMaxString || strings.ContainsAny(options.Token, "\r\n\x00") {
		return nil, ErrMetadataInvalid
	}
	options.MaxReceiveBytes = bounded(options.MaxReceiveBytes, DefaultMaxRecvBytes, MaxMessageBytes)
	options.MaxSendBytes = bounded(options.MaxSendBytes, DefaultMaxSendBytes, MaxMessageBytes)
	options.MaxFindings = bounded(options.MaxFindings, DefaultMaxFindings, MaxFindings)
	options.MaxStringBytes = bounded(options.MaxStringBytes, DefaultMaxString, MaxStringBytes)
	if options.MaxReceiveBytes <= 0 || options.MaxSendBytes <= 0 || options.MaxFindings <= 0 || options.MaxStringBytes <= 0 || options.MaxSendBytes > MaxMessageBytes || options.MaxReceiveBytes > MaxMessageBytes {
		return nil, ErrMetadataInvalid
	}
	if options.MaxConcurrent <= 0 {
		options.MaxConcurrent = 1
	}
	if options.MaxConcurrent > MaxFindings {
		return nil, ErrMetadataInvalid
	}
	secrets := append([]string(nil), options.SecretValues...)
	if options.Token != "" {
		secrets = append(secrets, options.Token)
	}
	tlsConfig := options.TLSConfig
	if parsedEndpoint.Scheme == "https" {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsedEndpoint.Hostname()}
		} else {
			tlsConfig = tlsConfig.Clone()
			if tlsConfig.MinVersion == 0 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
			if tlsConfig.InsecureSkipVerify {
				return nil, ErrTLSRequired
			}
			if tlsConfig.ServerName == "" {
				tlsConfig.ServerName = parsedEndpoint.Hostname()
			}
		}
	}
	return &Client{
		metadata: scanner.AnalyzerInfo{Name: metadata.Name, Resource: metadata.Resource, Description: metadata.Description, DocsURL: metadata.DocsURL, Enabled: true},
		endpoint: endpoint,
		options:  normalizedOptions{Options: options, tlsConfig: tlsConfig},
		redactor: sanitizer.RedactorForSecrets(secrets...),
		quota:    make(chan struct{}, options.MaxConcurrent),
	}, nil
}

func bounded(value, fallback, maximum int) int {
	if value == 0 {
		return fallback
	}
	if value < 0 || value > maximum {
		return -1
	}
	return value
}

func (c *Client) Info() scanner.AnalyzerInfo {
	if c == nil {
		return scanner.AnalyzerInfo{}
	}
	info := c.metadata
	info.Name = c.redactor.SanitizeText(info.Name)
	info.Resource = c.redactor.SanitizeText(info.Resource)
	info.Description = c.redactor.SanitizeText(info.Description)
	info.DocsURL = c.redactor.SanitizeURL(info.DocsURL)
	return info
}

// Analyze calls the sidecar with the scan plan's read-only scope. The
// external response is validated and sanitized before becoming scanner data.
func (c *Client) Analyze(ctx context.Context, namespace string) ([]*scanner.Issue, error) {
	if c == nil {
		return nil, ErrPluginUnavailable
	}
	ctx = normalizeContext(ctx)
	requestContext, release, cancel, err := c.beginCall(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	defer cancel()
	conn, err := c.connection(requestContext)
	if err != nil {
		return nil, err
	}
	request := &apiv1.AnalyzeRequest{SchemaVersion: SchemaVersion, Namespace: sanitizeField(c.redactor, namespace, c.options.MaxStringBytes)}
	if plan, ok := scanplan.FromContext(ctx); ok {
		request.Namespace = sanitizeField(c.redactor, plan.NamespaceArgument(), c.options.MaxStringBytes)
		request.LabelSelector = sanitizeField(c.redactor, plan.LabelSelector, c.options.MaxStringBytes)
		request.Kinds = boundedFields(c.redactor, plan.Kinds, c.options.MaxStringBytes)
		request.Names = boundedFields(c.redactor, plan.Names, c.options.MaxStringBytes)
	}
	if err := validateRequest(request, c.options.MaxStringBytes); err != nil {
		return nil, err
	}
	response, err := apiv1.NewExternalAnalyzerClient(conn).Analyze(requestContext, request, grpc.MaxCallRecvMsgSize(c.options.MaxReceiveBytes), grpc.MaxCallSendMsgSize(c.options.MaxSendBytes))
	if err != nil {
		return nil, classifyError(err, requestContext)
	}
	return c.projectResponse(response)
}

func (c *Client) Health(ctx context.Context) (bool, string, error) {
	if c == nil {
		return false, "", ErrPluginUnavailable
	}
	ctx = normalizeContext(ctx)
	requestContext, release, cancel, err := c.beginCall(ctx)
	if err != nil {
		return false, "", err
	}
	defer release()
	defer cancel()
	conn, err := c.connection(requestContext)
	if err != nil {
		return false, "", err
	}
	response, err := apiv1.NewExternalAnalyzerClient(conn).Health(requestContext, &apiv1.PluginEmpty{}, grpc.MaxCallRecvMsgSize(c.options.MaxReceiveBytes), grpc.MaxCallSendMsgSize(c.options.MaxSendBytes))
	if err != nil {
		return false, "", classifyError(err, requestContext)
	}
	if response == nil || response.GetSchemaVersion() != SchemaVersion {
		return false, "", ErrPluginResponse
	}
	return response.GetReady(), c.redactor.SanitizeText(response.GetMessage()), nil
}

func (c *Client) RemoteMetadata(ctx context.Context) (Metadata, error) {
	if c == nil {
		return Metadata{}, ErrPluginUnavailable
	}
	ctx = normalizeContext(ctx)
	requestContext, release, cancel, err := c.beginCall(ctx)
	if err != nil {
		return Metadata{}, err
	}
	defer release()
	defer cancel()
	conn, err := c.connection(requestContext)
	if err != nil {
		return Metadata{}, err
	}
	response, err := apiv1.NewExternalAnalyzerClient(conn).Metadata(requestContext, &apiv1.PluginMetadataRequest{}, grpc.MaxCallRecvMsgSize(c.options.MaxReceiveBytes), grpc.MaxCallSendMsgSize(c.options.MaxSendBytes))
	if err != nil {
		return Metadata{}, classifyError(err, requestContext)
	}
	if response == nil || response.GetSchemaVersion() != SchemaVersion {
		return Metadata{}, ErrPluginResponse
	}
	result := Metadata{Name: c.redactor.SanitizeText(response.GetName()), Resource: c.redactor.SanitizeText(response.GetResource()), Description: c.redactor.SanitizeText(response.GetDescription()), DocsURL: c.redactor.SanitizeURL(response.GetDocsUrl()), Version: c.redactor.SanitizeText(response.GetVersion()), ReadOnly: response.GetReadOnly()}
	if result.Name != c.metadata.Name || !result.ReadOnly || !safeIdentifier(result.Name) || result.Resource == "" || result.Description == "" {
		return Metadata{}, ErrMetadataInvalid
	}
	if len(result.Resource) > 128 || len(result.Description) > 4096 || len(result.Version) > 128 {
		return Metadata{}, ErrMetadataInvalid
	}
	if strings.ContainsAny(result.Resource+result.Description+result.Version, "\r\n\x00") {
		return Metadata{}, ErrMetadataInvalid
	}
	if result.DocsURL != "" {
		parsed, err := url.Parse(result.DocsURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return Metadata{}, ErrMetadataInvalid
		}
	}
	return result, nil
}

// Discover performs the explicit remote metadata handshake used by registry
// callers before activation.
func (c *Client) Discover(ctx context.Context) (Metadata, error) {
	return c.RemoteMetadata(ctx)
}

func (c *Client) beginCall(ctx context.Context) (context.Context, func(), context.CancelFunc, error) {
	if c == nil {
		return nil, nil, nil, ErrPluginUnavailable
	}
	ctx = normalizeContext(ctx)
	select {
	case c.quota <- struct{}{}:
		release := func() { <-c.quota }
		requestContext, cancel := context.WithTimeout(ctx, c.options.Timeout)
		if err := requestContext.Err(); err != nil {
			release()
			cancel()
			return nil, nil, nil, err
		}
		return requestContext, release, cancel, nil
	case <-ctx.Done():
		return nil, nil, nil, ctx.Err()
	}
}

func (c *Client) connection(ctx context.Context) (*grpc.ClientConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrPluginClosed
	}
	if c.conn != nil {
		conn := c.conn
		c.mu.Unlock()
		return conn, nil
	}
	c.mu.Unlock()
	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrPluginClosed
	}
	if c.conn != nil {
		conn := c.conn
		c.mu.Unlock()
		return conn, nil
	}
	c.mu.Unlock()

	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(c.options.MaxReceiveBytes), grpc.MaxCallSendMsgSize(c.options.MaxSendBytes)),
	}
	if token := strings.TrimSpace(c.options.Token); token != "" {
		dialOptions = append(dialOptions,
			grpc.WithUnaryInterceptor(func(ctx context.Context, method string, request, reply interface{}, conn *grpc.ClientConn, invoker grpc.UnaryInvoker, options ...grpc.CallOption) error {
				ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
				return invoker(ctx, method, request, reply, conn, options...)
			}),
			grpc.WithStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, conn *grpc.ClientConn, method string, streamer grpc.Streamer, options ...grpc.CallOption) (grpc.ClientStream, error) {
				ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
				return streamer(ctx, desc, conn, method, options...)
			}),
		)
	}
	if c.options.DialContext != nil {
		dialOptions = append(dialOptions, grpc.WithContextDialer(c.options.DialContext))
	}
	if c.options.tlsConfig != nil {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(c.options.tlsConfig)))
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	dialContext, cancel := context.WithTimeout(ctx, c.options.Timeout)
	defer cancel()
	conn, err := grpc.DialContext(dialContext, c.endpoint, dialOptions...)
	if err != nil {
		return nil, classifyError(err, dialContext)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return nil, ErrPluginClosed
	}
	c.conn = conn
	c.mu.Unlock()
	return conn, nil
}

// Close releases the owned gRPC connection. It is safe to call repeatedly.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		conn := c.conn
		c.conn = nil
		c.mu.Unlock()
		if conn != nil {
			err = conn.Close()
		}
	})
	return err
}

func (c *Client) projectResponse(response *apiv1.AnalyzeResponse) ([]*scanner.Issue, error) {
	if response == nil || response.GetSchemaVersion() != SchemaVersion {
		return nil, ErrPluginResponse
	}
	if len(response.GetFindings()) > c.options.MaxFindings {
		return nil, ErrPluginResponseLimit
	}
	issues := make([]*scanner.Issue, 0, len(response.GetFindings()))
	for _, finding := range response.GetFindings() {
		if finding == nil {
			return nil, ErrPluginResponse
		}
		if err := validateFinding(finding, c.options.MaxStringBytes); err != nil {
			return nil, err
		}
		severity := scanner.Severity(strings.ToUpper(strings.TrimSpace(finding.GetSeverity())))
		if !validSeverity(severity) {
			return nil, ErrPluginResponse
		}
		issue := &scanner.Issue{
			ID:        sanitizeField(c.redactor, finding.GetId(), c.options.MaxStringBytes),
			Namespace: sanitizeField(c.redactor, finding.GetNamespace(), c.options.MaxStringBytes),
			Kind:      sanitizeField(c.redactor, finding.GetKind(), c.options.MaxStringBytes),
			Name:      sanitizeField(c.redactor, finding.GetName(), c.options.MaxStringBytes),
			Severity:  severity,
			Category:  scanner.IssueCategory(sanitizeField(c.redactor, finding.GetCategory(), c.options.MaxStringBytes)),
			Summary:   sanitizeField(c.redactor, finding.GetSummary(), c.options.MaxStringBytes),
			Details:   sanitizeField(c.redactor, finding.GetDetails(), c.options.MaxStringBytes),
			DocsURL:   c.redactor.SanitizeURL(finding.GetDocsUrl()),
		}
		if issue.ID == "" {
			issue.ID = fmt.Sprintf("plugin-%s-%s", strings.ToLower(issue.Kind), strings.ToLower(issue.Name))
		}
		for _, evidence := range finding.GetEvidence() {
			issue.Events = append(issue.Events, sanitizeField(c.redactor, evidence, c.options.MaxStringBytes))
		}
		if finding.GetParentKind() != "" || finding.GetParentName() != "" {
			issue.Parent = &scanner.ResourceRef{Namespace: sanitizeField(c.redactor, finding.GetParentNamespace(), c.options.MaxStringBytes), Kind: sanitizeField(c.redactor, finding.GetParentKind(), c.options.MaxStringBytes), Name: sanitizeField(c.redactor, finding.GetParentName(), c.options.MaxStringBytes)}
		}
		issues = append(issues, issue)
	}
	return issues, nil
}

func validateRequest(request *apiv1.AnalyzeRequest, maxString int) error {
	if request == nil || request.GetSchemaVersion() != SchemaVersion || len(request.GetKinds()) > MaxFindings || len(request.GetNames()) > MaxFindings || len(request.GetNamespace()) > maxString || len(request.GetLabelSelector()) > maxString || strings.ContainsAny(request.GetNamespace()+request.GetLabelSelector(), "\r\n\x00") {
		return ErrMetadataInvalid
	}
	for _, value := range append(append([]string(nil), request.GetKinds()...), request.GetNames()...) {
		if len(value) > maxString || strings.ContainsAny(value, "\r\n\x00") {
			return ErrMetadataInvalid
		}
	}
	return nil
}

func validateFinding(finding *apiv1.PluginFinding, maxString int) error {
	values := []string{finding.GetId(), finding.GetNamespace(), finding.GetKind(), finding.GetName(), finding.GetSeverity(), finding.GetCategory(), finding.GetSummary(), finding.GetDetails(), finding.GetDocsUrl(), finding.GetParentKind(), finding.GetParentName(), finding.GetParentNamespace()}
	for _, value := range values {
		if len(value) > maxString || strings.ContainsAny(value, "\r\n\x00") {
			return ErrPluginResponse
		}
	}
	if finding.GetKind() == "" || finding.GetName() == "" || finding.GetCategory() == "" || finding.GetSummary() == "" {
		return ErrPluginResponse
	}
	if finding.GetDocsUrl() != "" {
		parsed, err := url.Parse(finding.GetDocsUrl())
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return ErrPluginResponse
		}
	}
	if len(finding.GetEvidence()) > MaxFindings {
		return ErrPluginResponseLimit
	}
	for _, evidence := range finding.GetEvidence() {
		if len(evidence) > maxString || strings.ContainsAny(evidence, "\r\n\x00") {
			return ErrPluginResponse
		}
	}
	return nil
}

func validSeverity(value scanner.Severity) bool {
	switch value {
	case scanner.SeverityCritical, scanner.SeverityHigh, scanner.SeverityMedium, scanner.SeverityLow:
		return true
	default:
		return false
	}
}

func classifyError(err error, ctx context.Context) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("plugin request timed out: %w", context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return fmt.Errorf("plugin request canceled: %w", context.Canceled)
	}
	switch status.Code(err) {
	case codes.DeadlineExceeded:
		return fmt.Errorf("plugin request timed out: %w", context.DeadlineExceeded)
	case codes.Canceled:
		return fmt.Errorf("plugin request canceled: %w", context.Canceled)
	case codes.ResourceExhausted:
		return ErrPluginResponseLimit
	default:
		return ErrPluginUnavailable
	}
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func sanitizeField(redactor *sanitizer.Redactor, value string, max int) string {
	if len(value) > max {
		value = value[:max]
	}
	return redactor.SanitizeText(value)
}

func boundedFields(redactor *sanitizer.Redactor, values []string, max int) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, sanitizeField(redactor, value, max))
	}
	return result
}

func safeIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if index == 0 && !asciiAlphaNumeric(character) {
			return false
		}
		if !asciiAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value rune) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func parseEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, ErrEndpointNotAllowed
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, ErrEndpointNotAllowed
	}
	return parsed, nil
}

func matchesEndpoint(endpoint *url.URL, allowlist []string) bool {
	for _, raw := range allowlist {
		candidate, err := parseEndpoint(raw)
		if err != nil || candidate.Scheme != endpoint.Scheme || !strings.EqualFold(candidate.Host, endpoint.Host) {
			continue
		}
		prefix := strings.TrimRight(candidate.Path, "/")
		if prefix == "" || endpoint.Path == prefix || strings.HasPrefix(endpoint.Path, prefix+"/") {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}
