// Package grpcapi exposes the authenticated, versioned gRPC compatibility
// surface for the SRE scanner. The package deliberately owns only transport
// concerns; callers provide scanner and config implementations.
package grpcapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	apiv1 "github.com/kubebee-com/sre/api/v1"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	APISchemaVersion   = "api/v1"
	TokenMetadataKey   = "authorization"
	defaultRequestTTL  = 30 * time.Second
	defaultReceiveSize = 1 << 20
	defaultSendSize    = 4 << 20
	defaultScanSize    = 4 << 20
	defaultQuerySize   = 1 << 20
	defaultConfigSize  = 256 << 10
	defaultStringSize  = 8 << 10
	defaultItemCount   = 2048

	hardMaxReceiveSize = 16 << 20
	hardMaxSendSize    = 32 << 20
	hardMaxResponse    = 32 << 20
	hardMaxString      = 1 << 20
	hardMaxItems       = 16 << 10
)

var (
	errScannerRequired = errors.New("scanner is required")
	errInvalidOptions  = errors.New("invalid gRPC server options")
)

// Scanner is the read-only backend required by the versioned API.
type Scanner interface {
	ScanWithPlan(context.Context, scanplan.Plan) (*scanner.ScanReport, error)
	GetAnalyzers() []scanner.AnalyzerInfo
	QueryResource(context.Context, string, string, string) (interface{}, error)
}

// ConfigProvider supplies a configuration snapshot. Implementations must not
// return credentials; the transport applies a second redaction boundary.
type ConfigProvider interface {
	GetConfig(context.Context) (interface{}, error)
}

// Options configures the transport. A non-empty APIToken implicitly enables
// authentication. RequireAPIToken makes NewService fail closed when the token
// is supplied through another configuration layer; NewServer always enables it.
type Options struct {
	APIToken               string
	RequireAPIToken        bool
	RequestTimeout         time.Duration
	MaxReceiveBytes        int
	MaxSendBytes           int
	MaxScanResponseBytes   int
	MaxQueryResponseBytes  int
	MaxConfigResponseBytes int
	MaxStringBytes         int
	MaxItems               int
	SecretValues           []string
	Redactor               *sanitizer.Redactor
	Config                 ConfigProvider
	TLSConfig              *tls.Config
	EnableReflection       bool
}

type normalizedOptions struct {
	Options
	auth tokenAuthenticator
}

// Service implements all generated api/v1 services. It is exported so users
// embedding the service in an existing grpc.Server can register it directly.
type Service struct {
	apiv1.UnimplementedAnalyzerServiceServer
	apiv1.UnimplementedQueryServiceServer
	apiv1.UnimplementedConfigServiceServer

	backend  Scanner
	config   ConfigProvider
	options  normalizedOptions
	redactor *sanitizer.Redactor
}

// NewService constructs the generated-service implementation without creating
// a listener or grpc.Server. It is useful for callers that own server options.
func NewService(backend Scanner, options ...Options) (*Service, error) {
	if backend == nil {
		return nil, errScannerRequired
	}
	serverOptions := firstOptions(options)
	serverOptions.RequireAPIToken = true
	opts, err := normalizeOptions(serverOptions)
	if err != nil {
		return nil, err
	}
	redactor := opts.Redactor
	if redactor == nil {
		redactor = sanitizer.RedactorForSecrets(opts.SecretValues...)
	}
	return &Service{
		backend:  backend,
		config:   opts.Config,
		options:  opts,
		redactor: redactor,
	}, nil
}

// Register adds the versioned services to any grpc service registrar.
func (s *Service) Register(registrar grpc.ServiceRegistrar) {
	if s == nil || registrar == nil {
		return
	}
	apiv1.RegisterAnalyzerServiceServer(registrar, s)
	apiv1.RegisterQueryServiceServer(registrar, s)
	apiv1.RegisterConfigServiceServer(registrar, s)
}

// NewServer creates an authenticated grpc.Server and registers the versioned
// analyzer, query, and config services. It requires a non-empty API token.
// TLS is optional for compatibility but, when configured, is terminated by
// grpc before any RPC reaches the service.
func NewServer(backend Scanner, options ...Options) (*grpc.Server, error) {
	serverOptions := firstOptions(options)
	serverOptions.RequireAPIToken = true
	service, err := NewService(backend, serverOptions)
	if err != nil {
		return nil, err
	}
	grpcOptions := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(service.options.MaxReceiveBytes),
		grpc.MaxSendMsgSize(service.options.MaxSendBytes),
		grpc.UnaryInterceptor(service.unaryInterceptor),
		grpc.StreamInterceptor(service.streamInterceptor),
	}
	if service.options.TLSConfig != nil {
		grpcOptions = append(grpcOptions, grpc.Creds(credentials.NewTLS(service.options.TLSConfig)))
	}
	server := grpc.NewServer(grpcOptions...)
	service.Register(server)
	if service.options.EnableReflection {
		reflection.Register(server)
	}
	return server, nil
}

// NewGRPCServer is an explicit alias for callers that prefer the transport
// name in their dependency injection wiring.
func NewGRPCServer(backend Scanner, options ...Options) (*grpc.Server, error) {
	return NewServer(backend, options...)
}

func firstOptions(options []Options) Options {
	if len(options) == 0 {
		return Options{}
	}
	return options[0]
}

func normalizeOptions(options Options) (normalizedOptions, error) {
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = defaultRequestTTL
	}
	if options.RequestTimeout > scanplan.MaxScanTimeout {
		return normalizedOptions{}, fmt.Errorf("%w: request timeout exceeds maximum", errInvalidOptions)
	}
	var err error
	if options.MaxReceiveBytes, err = boundedOption(options.MaxReceiveBytes, defaultReceiveSize, hardMaxReceiveSize); err != nil {
		return normalizedOptions{}, err
	}
	if options.MaxSendBytes, err = boundedOption(options.MaxSendBytes, defaultSendSize, hardMaxSendSize); err != nil {
		return normalizedOptions{}, err
	}
	if options.MaxScanResponseBytes, err = boundedOption(options.MaxScanResponseBytes, defaultScanSize, hardMaxResponse); err != nil {
		return normalizedOptions{}, err
	}
	if options.MaxQueryResponseBytes, err = boundedOption(options.MaxQueryResponseBytes, defaultQuerySize, hardMaxResponse); err != nil {
		return normalizedOptions{}, err
	}
	if options.MaxConfigResponseBytes, err = boundedOption(options.MaxConfigResponseBytes, defaultConfigSize, hardMaxResponse); err != nil {
		return normalizedOptions{}, err
	}
	if options.MaxStringBytes, err = boundedOption(options.MaxStringBytes, defaultStringSize, hardMaxString); err != nil {
		return normalizedOptions{}, err
	}
	if options.MaxItems, err = boundedOption(options.MaxItems, defaultItemCount, hardMaxItems); err != nil {
		return normalizedOptions{}, err
	}
	if options.MaxScanResponseBytes > options.MaxSendBytes || options.MaxQueryResponseBytes > options.MaxSendBytes || options.MaxConfigResponseBytes > options.MaxSendBytes {
		return normalizedOptions{}, fmt.Errorf("%w: response limit exceeds send limit", errInvalidOptions)
	}
	if options.TLSConfig != nil {
		if len(options.TLSConfig.Certificates) == 0 {
			return normalizedOptions{}, fmt.Errorf("%w: TLS certificates are required", errInvalidOptions)
		}
		tlsConfig := options.TLSConfig.Clone()
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			return normalizedOptions{}, fmt.Errorf("%w: TLS 1.2 or newer is required", errInvalidOptions)
		}
		options.TLSConfig = tlsConfig
	}
	auth, err := newTokenAuthenticator(options.APIToken, options.RequireAPIToken)
	if err != nil {
		return normalizedOptions{}, err
	}
	options.APIToken = ""
	return normalizedOptions{Options: options, auth: auth}, nil
}

func boundedOption(value, fallback, maximum int) (int, error) {
	if value <= 0 {
		return fallback, nil
	}
	if value > maximum {
		return 0, fmt.Errorf("%w: option exceeds maximum", errInvalidOptions)
	}
	return value, nil
}

type tokenAuthenticator struct {
	digest   [sha256.Size]byte
	required bool
}

func newTokenAuthenticator(token string, required bool) (tokenAuthenticator, error) {
	token = strings.TrimSpace(token)
	if token != "" {
		required = true
	}
	if required && token == "" {
		return tokenAuthenticator{}, errors.New("API token is required")
	}
	result := tokenAuthenticator{required: required}
	if token != "" {
		result.digest = sha256.Sum256([]byte(token))
	}
	return result, nil
}

func (a tokenAuthenticator) authorize(ctx context.Context) error {
	if !a.required {
		return nil
	}
	if ctx == nil {
		return status.Error(codes.Unauthenticated, "authentication required")
	}
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "authentication required")
	}
	tokens := values.Get(TokenMetadataKey)
	if len(tokens) != 1 {
		return status.Error(codes.Unauthenticated, "authentication required")
	}
	value := strings.TrimSpace(tokens[0])
	if len(value) < len("Bearer ") || !strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return status.Error(codes.Unauthenticated, "invalid authentication token")
	}
	token := strings.TrimSpace(value[len("Bearer "):])
	provided := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(provided[:], a.digest[:]) != 1 {
		return status.Error(codes.Unauthenticated, "invalid authentication token")
	}
	return nil
}

func (s *Service) unaryInterceptor(ctx context.Context, request interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (response interface{}, err error) {
	if err := s.options.auth.authorize(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			response = nil
			err = status.Error(codes.Internal, "internal server error")
		}
	}()
	return handler(ctx, request)
}

func (s *Service) streamInterceptor(server interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	if err := s.options.auth.authorize(stream.Context()); err != nil {
		return err
	}
	defer func() {
		if recover() != nil {
			err = status.Error(codes.Internal, "internal server error")
		}
	}()
	return handler(server, stream)
}

func (s *Service) Scan(ctx context.Context, request *apiv1.ScanRequest) (*apiv1.ScanResponse, error) {
	if err := s.options.auth.authorize(ctx); err != nil {
		return nil, err
	}
	plan, err := s.scanPlan(request)
	if err != nil {
		return nil, err
	}
	requestContext, cancel := s.requestContext(ctx, plan.Timeout)
	defer cancel()
	report, err := s.backend.ScanWithPlan(requestContext, plan)
	if err != nil {
		return nil, backendError(err, "scan")
	}
	response, err := s.projectScan(report)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (s *Service) Analyze(ctx context.Context, request *apiv1.ScanRequest) (*apiv1.ScanResponse, error) {
	return s.Scan(ctx, request)
}

func (s *Service) ListAnalyzers(ctx context.Context, _ *apiv1.Empty) (*apiv1.ListAnalyzersResponse, error) {
	if err := s.options.auth.authorize(ctx); err != nil {
		return nil, err
	}
	requestContext, cancel := s.requestContext(ctx, 0)
	defer cancel()
	if err := requestContext.Err(); err != nil {
		return nil, backendError(err, "analyzer")
	}
	infos := s.backend.GetAnalyzers()
	if len(infos) > s.options.MaxItems {
		return nil, status.Error(codes.ResourceExhausted, "analyzer response exceeds item limit")
	}
	response := &apiv1.ListAnalyzersResponse{SchemaVersion: APISchemaVersion, Analyzers: make([]*apiv1.AnalyzerInfo, 0, len(infos))}
	for _, info := range infos {
		response.Analyzers = append(response.Analyzers, s.projectAnalyzerInfo(info))
	}
	return boundedMessage(response, s.options.MaxScanResponseBytes, "analyzer response exceeds size limit")
}

func (s *Service) GetResource(ctx context.Context, request *apiv1.QueryRequest) (*apiv1.QueryResponse, error) {
	return s.query(ctx, request)
}

func (s *Service) Query(ctx context.Context, request *apiv1.QueryRequest) (*apiv1.QueryResponse, error) {
	return s.query(ctx, request)
}

func (s *Service) query(ctx context.Context, request *apiv1.QueryRequest) (*apiv1.QueryResponse, error) {
	if err := s.options.auth.authorize(ctx); err != nil {
		return nil, err
	}
	if err := s.validateQueryRequest(request); err != nil {
		return nil, err
	}
	requestContext, cancel := s.requestContext(ctx, 0)
	defer cancel()
	resource, err := s.backend.QueryResource(requestContext, request.GetKind(), request.GetNamespace(), request.GetName())
	if err != nil {
		return nil, backendError(err, "query")
	}
	projected, err := scanner.SanitizeResourceForKind(request.GetKind(), resource, s.redactor)
	if err != nil {
		return nil, status.Error(codes.Internal, "resource projection failed")
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, status.Error(codes.Internal, "resource projection failed")
	}
	response := &apiv1.QueryResponse{
		SchemaVersion: APISchemaVersion,
		Kind:          s.redactor.SanitizeText(request.GetKind()),
		Namespace:     s.redactor.SanitizeText(request.GetNamespace()),
		Name:          s.redactor.SanitizeText(request.GetName()),
		ResourceJson:  string(encoded),
	}
	return boundedMessage(response, s.options.MaxQueryResponseBytes, "query response exceeds size limit")
}

func (s *Service) GetConfig(ctx context.Context, _ *apiv1.Empty) (*apiv1.ConfigResponse, error) {
	if err := s.options.auth.authorize(ctx); err != nil {
		return nil, err
	}
	if s.config == nil {
		return nil, status.Error(codes.Unimplemented, "config service unavailable")
	}
	requestContext, cancel := s.requestContext(ctx, 0)
	defer cancel()
	config, err := s.config.GetConfig(requestContext)
	if err != nil {
		return nil, backendError(err, "config")
	}
	projected, err := s.projectConfig(config)
	if err != nil {
		return nil, status.Error(codes.Internal, "config projection failed")
	}
	response := &apiv1.ConfigResponse{SchemaVersion: APISchemaVersion, ConfigJson: string(projected)}
	return boundedMessage(response, s.options.MaxConfigResponseBytes, "config response exceeds size limit")
}

func (s *Service) scanPlan(request *apiv1.ScanRequest) (scanplan.Plan, error) {
	if request == nil {
		return scanplan.Plan{}, status.Error(codes.InvalidArgument, "invalid scan request")
	}
	if err := s.validateStrings(request.GetSchemaVersion(), request.GetLabelSelector(), request.GetTimeout()); err != nil {
		return scanplan.Plan{}, err
	}
	for _, values := range [][]string{
		request.GetIncludeNamespaces(), request.GetExcludeNamespaces(), request.GetKinds(), request.GetNames(), request.GetAnalyzers(),
	} {
		if err := s.validateStringList(values); err != nil {
			return scanplan.Plan{}, err
		}
	}
	plan := scanplan.Default()
	if request.GetSchemaVersion() != "" {
		plan.SchemaVersion = request.GetSchemaVersion()
	}
	plan.IncludeNamespaces = append([]string(nil), request.GetIncludeNamespaces()...)
	plan.ExcludeNamespaces = append([]string(nil), request.GetExcludeNamespaces()...)
	plan.LabelSelector = request.GetLabelSelector()
	plan.Kinds = append([]string(nil), request.GetKinds()...)
	plan.Names = append([]string(nil), request.GetNames()...)
	plan.Analyzers = append([]string(nil), request.GetAnalyzers()...)
	if request.GetMaxConcurrency() != 0 {
		plan.MaxConcurrency = int(request.GetMaxConcurrency())
	}
	if request.GetTimeout() != "" {
		timeout, err := time.ParseDuration(request.GetTimeout())
		if err != nil {
			return scanplan.Plan{}, status.Error(codes.InvalidArgument, "invalid scan request")
		}
		plan.Timeout = timeout
	}
	known := make([]string, 0, s.options.MaxItems)
	for _, info := range s.backend.GetAnalyzers() {
		if len(known) == s.options.MaxItems {
			break
		}
		known = append(known, info.Name)
	}
	if err := plan.Validate(known); err != nil {
		return scanplan.Plan{}, status.Error(codes.InvalidArgument, "invalid scan request")
	}
	return plan, nil
}

func (s *Service) validateQueryRequest(request *apiv1.QueryRequest) error {
	if request == nil {
		return status.Error(codes.InvalidArgument, "invalid query request")
	}
	if request.GetSchemaVersion() != "" && request.GetSchemaVersion() != APISchemaVersion {
		return status.Error(codes.InvalidArgument, "invalid query request")
	}
	if err := s.validateStrings(request.GetSchemaVersion(), request.GetKind(), request.GetNamespace(), request.GetName()); err != nil {
		return status.Error(codes.InvalidArgument, "invalid query request")
	}
	if strings.TrimSpace(request.GetKind()) == "" || strings.TrimSpace(request.GetName()) == "" || strings.ContainsAny(request.GetKind()+request.GetNamespace()+request.GetName(), "\x00\r\n") {
		return status.Error(codes.InvalidArgument, "invalid query request")
	}
	if isSecretKind(request.GetKind()) {
		return status.Error(codes.InvalidArgument, "invalid query request")
	}
	if _, ok := grpcQueryableResourceKinds[canonicalGRPCResourceKind(request.GetKind())]; !ok {
		return status.Error(codes.InvalidArgument, "invalid query request")
	}
	return nil
}

var grpcQueryableResourceKinds = map[string]struct{}{
	"pod": {}, "service": {}, "configmap": {}, "persistentvolumeclaim": {},
	"deployment": {}, "statefulset": {}, "daemonset": {}, "replicaset": {},
	"job": {}, "cronjob": {}, "ingress": {}, "networkpolicy": {},
	"horizontalpodautoscaler": {}, "poddisruptionbudget": {}, "node": {},
}

func canonicalGRPCResourceKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if slash := strings.LastIndexByte(kind, '/'); slash >= 0 {
		kind = kind[slash+1:]
	}
	switch kind {
	case "pods":
		return "pod"
	case "services":
		return "service"
	case "configmaps":
		return "configmap"
	case "persistentvolumeclaims", "pvc", "pvcs":
		return "persistentvolumeclaim"
	case "deployments":
		return "deployment"
	case "statefulsets":
		return "statefulset"
	case "daemonsets":
		return "daemonset"
	case "replicasets":
		return "replicaset"
	case "jobs":
		return "job"
	case "cronjobs":
		return "cronjob"
	case "ingresses":
		return "ingress"
	case "networkpolicies", "netpol", "netpols":
		return "networkpolicy"
	case "hpa", "horizontalpodautoscalers":
		return "horizontalpodautoscaler"
	case "pdb", "poddisruptionbudgets":
		return "poddisruptionbudget"
	case "nodes":
		return "node"
	case "secret", "secrets", "secretlist":
		return "secret"
	default:
		return kind
	}
}

func isSecretKind(kind string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if slash := strings.LastIndexByte(kind, '/'); slash >= 0 {
		kind = kind[slash+1:]
	}
	return kind == "secret" || kind == "secrets" || kind == "secretlist"
}

func (s *Service) validateStrings(values ...string) error {
	for _, value := range values {
		if len(value) > s.options.MaxStringBytes || strings.IndexByte(value, 0) >= 0 {
			return status.Error(codes.InvalidArgument, "request field exceeds limit")
		}
	}
	return nil
}

func (s *Service) validateStringList(values []string) error {
	if len(values) > s.options.MaxItems {
		return status.Error(codes.InvalidArgument, "request list exceeds limit")
	}
	return s.validateStrings(values...)
}

func (s *Service) requestContext(parent context.Context, requested time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	timeout := s.options.RequestTimeout
	if requested > 0 && requested < timeout {
		timeout = requested
	}
	return context.WithTimeout(parent, timeout)
}

func (s *Service) projectScan(report *scanner.ScanReport) (*apiv1.ScanResponse, error) {
	if report == nil {
		return nil, status.Error(codes.Unavailable, "scan unavailable")
	}
	if len(report.Issues) > s.options.MaxItems || len(report.Analyzers) > s.options.MaxItems {
		return nil, status.Error(codes.ResourceExhausted, "scan response exceeds item limit")
	}
	response := &apiv1.ScanResponse{
		SchemaVersion: APISchemaVersion,
		Scope:         s.projectScope(report.Scope),
		Issues:        make([]*apiv1.Issue, 0, len(report.Issues)),
		Analyzers:     make([]*apiv1.AnalyzerRun, 0, len(report.Analyzers)),
		StartedAt:     formatTime(report.StartedAt),
		FinishedAt:    formatTime(report.FinishedAt),
		Duration:      s.redactor.SanitizeText(report.Duration),
	}
	for _, issue := range report.Issues {
		if issue == nil {
			continue
		}
		response.Issues = append(response.Issues, s.projectIssue(issue))
	}
	for _, run := range report.Analyzers {
		response.Analyzers = append(response.Analyzers, s.projectAnalyzerRun(run))
	}
	return boundedMessage(response, s.options.MaxScanResponseBytes, "scan response exceeds size limit")
}

func (s *Service) projectScope(scope scanplan.EffectiveScope) *apiv1.ScanScope {
	return &apiv1.ScanScope{
		SchemaVersion:     s.redactor.SanitizeText(scope.SchemaVersion),
		IncludeNamespaces: sanitizeStrings(s.redactor, scope.IncludeNamespaces),
		ExcludeNamespaces: sanitizeStrings(s.redactor, scope.ExcludeNamespaces),
		LabelSelector:     s.redactor.SanitizeText(scope.LabelSelector),
		Kinds:             sanitizeStrings(s.redactor, scope.Kinds),
		Names:             sanitizeStrings(s.redactor, scope.Names),
		Analyzers:         sanitizeStrings(s.redactor, scope.Analyzers),
		MaxConcurrency:    int32(scope.MaxConcurrency),
		Timeout:           s.redactor.SanitizeText(scope.Timeout),
	}
}

func (s *Service) projectIssue(issue *scanner.Issue) *apiv1.Issue {
	safe := scanner.SanitizeIssueWithRedactor(issue, s.redactor)
	result := &apiv1.Issue{
		Id:                    safe.ID,
		Namespace:             safe.Namespace,
		Kind:                  safe.Kind,
		Name:                  safe.Name,
		TargetUid:             safe.TargetUID,
		TargetResourceVersion: safe.TargetResourceVersion,
		Severity:              string(safe.Severity),
		Category:              string(safe.Category),
		Summary:               safe.Summary,
		Details:               safe.Details,
		LogsSnippet:           safe.LogsSnippet,
		Events:                append([]string(nil), safe.Events...),
		SpecSnippet:           safe.SpecSnippet,
		FirstObserved:         formatTime(safe.FirstObserved),
		LastObserved:          formatTime(safe.LastObserved),
		DocsUrl:               safe.DocsURL,
		RedactedCount:         int32(safe.Report.RedactedCount),
		RedactedFields:        append([]string(nil), safe.Report.Fields...),
	}
	if safe.Parent != nil {
		result.Parent = &apiv1.ResourceRef{
			Namespace: safe.Parent.Namespace,
			Kind:      safe.Parent.Kind,
			Name:      safe.Parent.Name,
			Uid:       safe.Parent.UID,
		}
	}
	return result
}

func (s *Service) projectAnalyzerInfo(info scanner.AnalyzerInfo) *apiv1.AnalyzerInfo {
	issueCount := info.IssueCount
	if issueCount < 0 {
		issueCount = 0
	}
	return &apiv1.AnalyzerInfo{
		Name:        s.redactor.SanitizeText(info.Name),
		Resource:    s.redactor.SanitizeText(info.Resource),
		Description: s.redactor.SanitizeText(info.Description),
		DocsUrl:     s.redactor.SanitizeURL(info.DocsURL),
		ParentKind:  s.redactor.SanitizeText(info.ParentKind),
		Enabled:     info.Enabled,
		IssueCount:  int32(issueCount),
	}
}

func (s *Service) projectAnalyzerRun(run scanner.AnalyzerRun) *apiv1.AnalyzerRun {
	result := &apiv1.AnalyzerRun{
		Info:       s.projectAnalyzerInfo(run.Info),
		IssueCount: int32(maxInt(run.IssueCount, 0)),
		Duration:   s.redactor.SanitizeText(run.Duration),
		StartedAt:  formatTime(run.StartedAt),
		FinishedAt: formatTime(run.FinishedAt),
	}
	if strings.TrimSpace(run.Error) != "" {
		result.Error = "analyzer failed"
	}
	return result
}

func (s *Service) projectConfig(config interface{}) ([]byte, error) {
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var value interface{}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, err
	}
	value = sanitizeConfigValue(value, s.redactor)
	return json.Marshal(value)
}

func sanitizeConfigValue(value interface{}, redactor *sanitizer.Redactor) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(typed))
		for key, nested := range typed {
			safeKey := redactor.SanitizeText(key)
			if sensitiveConfigKey(key) {
				result[safeKey] = "[REDACTED]"
				continue
			}
			result[safeKey] = sanitizeConfigValue(nested, redactor)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(typed))
		for index, nested := range typed {
			result[index] = sanitizeConfigValue(nested, redactor)
		}
		return result
	default:
		return redactor.SanitizeValue(value)
	}
}

func sensitiveConfigKey(key string) bool {
	var normalized strings.Builder
	for _, character := range strings.ToLower(key) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			normalized.WriteRune(character)
		}
	}
	value := normalized.String()
	if value == "key" || value == "token" || value == "secret" || value == "password" || value == "credential" || value == "authorization" || value == "privatekey" {
		return true
	}
	for _, marker := range []string{"apikey", "authtoken", "accesstoken", "refreshtoken", "clientsecret", "password", "credential", "privatekey"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return strings.HasSuffix(value, "token") || strings.HasSuffix(value, "secret")
}

func boundedMessage[T proto.Message](message T, limit int, description string) (T, error) {
	if proto.Size(message) > limit {
		var zero T
		return zero, status.Error(codes.ResourceExhausted, description)
	}
	return message, nil
}

func backendError(err error, operation string) error {
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, "request canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request deadline exceeded")
	}
	if operation == "query" {
		return status.Error(codes.Unavailable, "resource unavailable")
	}
	return status.Error(codes.Unavailable, operation+" unavailable")
}

func sanitizeStrings(redactor *sanitizer.Redactor, values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = redactor.SanitizeText(value)
	}
	return result
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func maxInt(value, minimum int) int {
	if value < minimum {
		return minimum
	}
	return value
}
