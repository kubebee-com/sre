package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/kubebee-com/sre/pkg/scanner"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type fakeEKSClient struct {
	pages          [][]string
	listCalls      int
	describeCalls  int
	describeName   string
	describeOutput *eks.DescribeClusterOutput
	describeError  error
}

func (f *fakeEKSClient) ListClusters(_ context.Context, input *eks.ListClustersInput, _ ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	f.listCalls++
	page := f.listCalls - 1
	if page >= len(f.pages) {
		return &eks.ListClustersOutput{}, nil
	}
	output := &eks.ListClustersOutput{Clusters: append([]string(nil), f.pages[page]...)}
	if page+1 < len(f.pages) {
		token := "page-2"
		if input != nil && input.NextToken != nil {
			token = "page-more"
		}
		output.NextToken = aws.String(token)
	}
	return output, nil
}

func (f *fakeEKSClient) DescribeCluster(_ context.Context, input *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	f.describeCalls++
	if input != nil && input.Name != nil {
		f.describeName = *input.Name
	}
	if f.describeError != nil {
		return nil, f.describeError
	}
	return f.describeOutput, nil
}

func writeEKSContext(t *testing.T, contextName, clusterRef string) string {
	t.Helper()
	path := t.TempDir() + "/config"
	config := &clientcmdapi.Config{
		CurrentContext: contextName,
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {Cluster: clusterRef},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			clusterRef: {Server: "https://kubernetes.example.test"},
		},
	}
	if err := clientcmd.WriteToFile(*config, path); err != nil {
		t.Fatalf("clientcmd.WriteToFile() error = %v", err)
	}
	return path
}

func TestAWSFactoryMetadataAndExplicitActivation(t *testing.T) {
	client := &fakeEKSClient{describeOutput: &eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{Name: aws.String("production")}}}
	factory, err := NewAWSFactory(context.Background(), AWSOptions{Client: client, ClusterName: "production"})
	if err != nil {
		t.Fatalf("NewAWSFactory() error = %v", err)
	}
	if metadata := factory.Metadata(); metadata.Name != "aws-eks" || !metadata.ReadOnly {
		t.Fatalf("Metadata() = %#v, want read-only aws-eks metadata", metadata)
	}
	registry := NewRegistry()
	if err := registry.Register(factory); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registrar := scanner.NewClusterScanner(nil)
	if err := registry.Activate(context.Background(), "AWS-EKS", registrar); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	status, found := registry.Get("aws-eks")
	if !found || status.State != StateActive || len(registrar.CustomAnalyzers()) != 1 {
		t.Fatalf("active registry = %#v (found=%v), analyzers = %d", status, found, len(registrar.CustomAnalyzers()))
	}
	if got := registrar.CustomAnalyzers()[0].Info().Name; got != "EKSAnalyzer" {
		t.Fatalf("activated analyzer name = %q, want EKSAnalyzer", got)
	}
}

func TestEKSAnalyzerUsesPaginatedContextMatchingAndRedactsHealth(t *testing.T) {
	const secret = "eks-health-secret"
	contextName := "arn:aws:eks:us-east-1:123456789012:cluster/production"
	path := writeEKSContext(t, contextName, contextName)
	client := &fakeEKSClient{
		pages: [][]string{{"staging"}, {"production"}},
		describeOutput: &eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{
			Name:   aws.String("production"),
			Status: ekstypes.ClusterStatusActive,
			Health: &ekstypes.ClusterHealth{Issues: []ekstypes.ClusterIssue{{
				Code:    ekstypes.ClusterIssueCodeClusterUnreachable,
				Message: aws.String("control plane token=" + secret),
			}}},
		}},
	}
	factory, err := NewAWSFactory(context.Background(), AWSOptions{Client: client, KubeconfigPath: path, SecretValues: []string{secret}})
	if err != nil {
		t.Fatalf("NewAWSFactory() error = %v", err)
	}
	analyzer, err := factory.New(context.Background())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	issues, err := analyzer.Analyze(context.Background(), "")
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(issues) != 1 || issues[0].Severity != scanner.SeverityCritical || issues[0].Category != scanner.CategoryEKSClusterHealth {
		t.Fatalf("Analyze() issues = %#v, want one critical EKS health issue", issues)
	}
	if client.listCalls != 2 || client.describeCalls != 1 || client.describeName != "production" {
		t.Fatalf("AWS calls = list %d/describe %d name %q, want paginated list and production describe", client.listCalls, client.describeCalls, client.describeName)
	}
	if strings.Contains(issues[0].Details, secret) {
		t.Fatalf("health issue leaked secret: %#v", issues[0])
	}
}

func TestEKSAnalyzerDoesNotUseSubstringContextMatches(t *testing.T) {
	path := writeEKSContext(t, "production", "production")
	client := &fakeEKSClient{pages: [][]string{{"prod"}}}
	factory, err := NewAWSFactory(context.Background(), AWSOptions{Client: client, KubeconfigPath: path})
	if err != nil {
		t.Fatalf("NewAWSFactory() error = %v", err)
	}
	analyzer, err := factory.New(context.Background())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = analyzer.Analyze(context.Background(), "")
	if !errors.Is(err, ErrEKSClusterNotDetected) {
		t.Fatalf("Analyze() error = %v, want ErrEKSClusterNotDetected", err)
	}
	if client.describeCalls != 0 {
		t.Fatal("Analyze() described a cluster after an unsafe substring match")
	}
}

func TestClusterNameMatchesRequiresExactOrARNPathMatch(t *testing.T) {
	if !clusterNameMatches("production", "arn:aws:eks:region:account:cluster/production", "") {
		t.Fatal("ARN context did not match exact cluster name")
	}
	if clusterNameMatches("prod", "production", "production") {
		t.Fatal("clusterNameMatches accepted a substring")
	}
}
