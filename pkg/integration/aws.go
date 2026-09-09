package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	eksDocsURL        = "https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html"
	maxEKSListPages   = 100
	maxEKSMessageSize = 512
)

var ErrEKSClusterNotDetected = errors.New("AWS EKS cluster was not detected")

// EKSClient is the small AWS SDK surface required by the analyzer. Keeping
// the interfaces at the integration boundary makes health checks testable
// without credentials or a live AWS account.
type EKSClient interface {
	eks.ListClustersAPIClient
	eks.DescribeClusterAPIClient
}

// AWSOptions configures the read-only EKS integration. ClusterName is useful
// for in-cluster deployments where no local kubeconfig is mounted.
type AWSOptions struct {
	Client         EKSClient
	Region         string
	ClusterName    string
	KubeconfigPath string
	ContextName    string
	SecretValues   []string
}

// AWSFactory creates the EKS analyzer only when an operator explicitly
// activates the integration registry entry.
type AWSFactory struct {
	client   EKSClient
	options  AWSOptions
	redactor *sanitizer.Redactor
}

var _ SingleAnalyzerFactory = (*AWSFactory)(nil)

// NewAWSFactory loads the AWS SDK default credential chain when no client is
// injected. Loading configuration performs no EKS API call; Analyze remains
// the only operation that contacts AWS.
func NewAWSFactory(ctx context.Context, options AWSOptions) (*AWSFactory, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Client == nil {
		loadOptions := make([]func(*awsconfig.LoadOptions) error, 0, 1)
		if region := strings.TrimSpace(options.Region); region != "" {
			loadOptions = append(loadOptions, awsconfig.WithRegion(region))
		}
		config, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
		if err != nil {
			return nil, errors.New("AWS configuration could not be loaded")
		}
		options.Client = eks.NewFromConfig(config)
	}
	options.Region = strings.TrimSpace(options.Region)
	options.ClusterName = strings.TrimSpace(options.ClusterName)
	options.KubeconfigPath = strings.TrimSpace(options.KubeconfigPath)
	options.ContextName = strings.TrimSpace(options.ContextName)
	return &AWSFactory{
		client:   options.Client,
		options:  options,
		redactor: sanitizer.RedactorForSecrets(options.SecretValues...),
	}, nil
}

func (f *AWSFactory) Metadata() Metadata {
	return Metadata{
		Name:        "aws-eks",
		DisplayName: "AWS/EKS",
		Version:     "v1",
		Description: "Read-only Amazon EKS control-plane health analysis",
		DocsURL:     eksDocsURL,
		Owner:       "kubebee-sre",
		ReadOnly:    true,
	}
}

func (f *AWSFactory) New(ctx context.Context) (scanner.Analyzer, error) {
	if f == nil || f.client == nil {
		return nil, errors.New("AWS EKS client is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &EKSAnalyzer{
		client:   f.client,
		options:  f.options,
		redactor: f.redactorOrDefault(),
	}, nil
}

// EKSAnalyzer reports only health and lifecycle state returned by the EKS
// control plane. It never mutates AWS or Kubernetes resources.
type EKSAnalyzer struct {
	client   EKSClient
	options  AWSOptions
	redactor *sanitizer.Redactor
}

var _ scanner.Analyzer = (*EKSAnalyzer)(nil)

func (a *EKSAnalyzer) Info() scanner.AnalyzerInfo {
	return scanner.AnalyzerInfo{
		Name:        "EKSAnalyzer",
		Resource:    "EKS",
		Description: "Checks Amazon EKS control-plane health and lifecycle state",
		DocsURL:     eksDocsURL,
		Enabled:     true,
	}
}

func (f *AWSFactory) redactorOrDefault() *sanitizer.Redactor {
	if f != nil && f.redactor != nil {
		return f.redactor
	}
	return sanitizer.DefaultRedactor()
}

func (a *EKSAnalyzer) Analyze(ctx context.Context, _ string) ([]*scanner.Issue, error) {
	if a == nil || a.client == nil {
		return nil, errors.New("AWS EKS client is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clusterName, err := a.resolveClusterName(ctx)
	if err != nil {
		return nil, err
	}
	output, err := a.client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(clusterName)})
	if err != nil {
		return nil, fmt.Errorf("describe EKS cluster: %s", a.safeMessage(err.Error()))
	}
	if output == nil || output.Cluster == nil {
		return nil, errors.New("describe EKS cluster returned no cluster")
	}

	cluster := output.Cluster
	issues := make([]*scanner.Issue, 0)
	if cluster.Status != "" && cluster.Status != ekstypes.ClusterStatusActive {
		issues = append(issues, a.issue(clusterName, "status-"+string(cluster.Status), severityForClusterStatus(cluster.Status), scanner.CategoryEKSClusterHealth,
			fmt.Sprintf("EKS cluster %s is %s", clusterName, cluster.Status),
			"The EKS control plane is not ACTIVE; check the cluster operation and AWS control-plane events."))
	}
	if cluster.Health != nil {
		for index, healthIssue := range cluster.Health.Issues {
			code := strings.TrimSpace(string(healthIssue.Code))
			if code == "" {
				code = "Unknown"
			}
			message := "The EKS control plane reported a health issue."
			if healthIssue.Message != nil && strings.TrimSpace(*healthIssue.Message) != "" {
				message = a.safeMessage(*healthIssue.Message)
			}
			issues = append(issues, a.issue(clusterName, fmt.Sprintf("health-%d-%s", index, code), severityForClusterIssue(healthIssue.Code), scanner.CategoryEKSClusterHealth,
				fmt.Sprintf("EKS cluster %s reports %s", clusterName, code), message))
		}
	}
	return issues, nil
}

func (a *EKSAnalyzer) resolveClusterName(ctx context.Context) (string, error) {
	if name := strings.TrimSpace(a.options.ClusterName); name != "" {
		if !validEKSClusterName(name) {
			return "", ErrEKSClusterNotDetected
		}
		return name, nil
	}
	contextName, clusterRef, err := currentKubeContext(a.options.KubeconfigPath, a.options.ContextName)
	if err != nil {
		return "", fmt.Errorf("resolve EKS kube context: %s", a.safeMessage(err.Error()))
	}

	paginator := eks.NewListClustersPaginator(a.client, &eks.ListClustersInput{MaxResults: aws.Int32(100)}, func(options *eks.ListClustersPaginatorOptions) {
		options.Limit = 100
		options.StopOnDuplicateToken = true
	})
	for page := 0; paginator.HasMorePages(); page++ {
		if page >= maxEKSListPages {
			return "", errors.New("EKS cluster discovery exceeded its page limit")
		}
		result, err := paginator.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("list EKS clusters: %s", a.safeMessage(err.Error()))
		}
		if result == nil {
			continue
		}
		for _, candidate := range result.Clusters {
			if clusterNameMatches(candidate, contextName, clusterRef) {
				return candidate, nil
			}
		}
	}
	return "", ErrEKSClusterNotDetected
}

func currentKubeContext(path, contextName string) (string, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if strings.TrimSpace(path) != "" {
		rules.ExplicitPath = path
	} else if home, err := os.UserHomeDir(); err == nil {
		rules.ExplicitPath = filepath.Join(home, ".kube", "config")
	}
	raw, err := rules.Load()
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(contextName) == "" {
		contextName = raw.CurrentContext
	}
	contextName = strings.TrimSpace(contextName)
	if contextName == "" {
		return "", "", errors.New("current Kubernetes context is empty")
	}
	selected, ok := raw.Contexts[contextName]
	if !ok || selected == nil {
		return "", "", errors.New("current Kubernetes context is not configured")
	}
	return contextName, strings.TrimSpace(selected.Cluster), nil
}

func clusterNameMatches(candidate, contextName, clusterRef string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || !validEKSClusterName(candidate) {
		return false
	}
	for _, value := range []string{contextName, clusterRef} {
		value = strings.TrimSpace(value)
		if value == candidate || strings.HasSuffix(value, "/"+candidate) {
			return true
		}
	}
	return false
}

func validEKSClusterName(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}
	for index, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || (character == '-' && index > 0) {
			continue
		}
		return false
	}
	return true
}

func severityForClusterIssue(code ekstypes.ClusterIssueCode) scanner.Severity {
	switch code {
	case ekstypes.ClusterIssueCodeAccessDenied, ekstypes.ClusterIssueCodeClusterUnreachable, ekstypes.ClusterIssueCodeInternalFailure:
		return scanner.SeverityCritical
	default:
		return scanner.SeverityHigh
	}
}

func severityForClusterStatus(status ekstypes.ClusterStatus) scanner.Severity {
	if status == ekstypes.ClusterStatusFailed || status == ekstypes.ClusterStatusDeleting {
		return scanner.SeverityCritical
	}
	return scanner.SeverityHigh
}

func (a *EKSAnalyzer) issue(clusterName, reason string, severity scanner.Severity, category scanner.IssueCategory, summary, details string) *scanner.Issue {
	digest := sha256.Sum256([]byte(clusterName + "\x00" + reason))
	return &scanner.Issue{
		ID:            fmt.Sprintf("eks-%x", digest[:12]),
		Kind:          "EKS",
		Name:          a.redactorOrDefault().SanitizeText(clusterName),
		Severity:      severity,
		Category:      category,
		Summary:       a.redactorOrDefault().SanitizeText(summary),
		Details:       a.redactorOrDefault().SanitizeText(details),
		FirstObserved: time.Now().UTC(),
		LastObserved:  time.Now().UTC(),
		DocsURL:       eksDocsURL,
	}
}

func (a *EKSAnalyzer) safeMessage(message string) string {
	message = a.redactorOrDefault().SafeLogValue(message)
	if len(message) > maxEKSMessageSize {
		return message[:maxEKSMessageSize]
	}
	return message
}

func (a *EKSAnalyzer) redactorOrDefault() *sanitizer.Redactor {
	if a != nil && a.redactor != nil {
		return a.redactor
	}
	return sanitizer.DefaultRedactor()
}
