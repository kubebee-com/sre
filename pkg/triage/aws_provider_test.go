package triage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sagemakerruntime"
	"github.com/kubebee-com/sre/pkg/scanner"
)

type fakeBedrockRuntimeClient struct {
	input  *bedrockruntime.InvokeModelInput
	output *bedrockruntime.InvokeModelOutput
	err    error
	call   func(context.Context, *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error)
}

func (f *fakeBedrockRuntimeClient) InvokeModel(ctx context.Context, input *bedrockruntime.InvokeModelInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
	f.input = input
	if f.call != nil {
		return f.call(ctx, input)
	}
	return f.output, f.err
}

type fakeSageMakerRuntimeClient struct {
	input  *sagemakerruntime.InvokeEndpointInput
	output *sagemakerruntime.InvokeEndpointOutput
	err    error
	call   func(context.Context, *sagemakerruntime.InvokeEndpointInput) (*sagemakerruntime.InvokeEndpointOutput, error)
}

func (f *fakeSageMakerRuntimeClient) InvokeEndpoint(ctx context.Context, input *sagemakerruntime.InvokeEndpointInput, _ ...func(*sagemakerruntime.Options)) (*sagemakerruntime.InvokeEndpointOutput, error) {
	f.input = input
	if f.call != nil {
		return f.call(ctx, input)
	}
	return f.output, f.err
}

func TestBedrockProviderUsesInjectedClientAndClaudeWireShape(t *testing.T) {
	const secret = "bedrock-secret"
	client := &fakeBedrockRuntimeClient{
		output: &bedrockruntime.InvokeModelOutput{Body: []byte(`{"content":[{"type":"text","text":"safe response"}]}`)},
	}
	provider, err := NewBedrockProvider(ProviderProfile{
		Provider:     "bedrock",
		Model:        "anthropic.claude-3-5-sonnet-20241022-v2:0",
		AWSRegion:    "us-east-1",
		SecretValues: []string{secret},
	}, AWSProviderOptions{BedrockClient: client})
	if err != nil {
		t.Fatalf("NewBedrockProvider() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "inspect "+secret, nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if reply != "safe response" || strings.Contains(reply, secret) {
		t.Fatalf("Explain() = %q", reply)
	}
	if client.input == nil || aws.ToString(client.input.ModelId) != "anthropic.claude-3-5-sonnet-20241022-v2:0" {
		t.Fatalf("InvokeModel input = %#v", client.input)
	}
	if got := aws.ToString(client.input.ContentType); got != "application/json" {
		t.Fatalf("ContentType = %q", got)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(client.input.Body, &payload); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	if payload["anthropic_version"] != "bedrock-2023-05-31" {
		t.Fatalf("request payload = %#v", payload)
	}
	if strings.Contains(string(client.input.Body), secret) {
		t.Fatalf("request body leaked secret: %s", client.input.Body)
	}
}

func TestBedrockProviderDiagnoseParsesAndRedactsModelOutput(t *testing.T) {
	const secret = "bedrock-diagnosis-secret"
	client := &fakeBedrockRuntimeClient{output: &bedrockruntime.InvokeModelOutput{Body: []byte(`{"content":[{"text":"{\"issue_id\":\"issue-bedrock\",\"summary\":\"bad\",\"root_cause\":\"password=bedrock-diagnosis-secret\",\"severity\":\"HIGH\",\"remediation_plan\":\"inspect workload\",\"action_type\":\"Manual\",\"proposed_command\":\"kubectl get pods -n default\",\"confidence_score\":0.8}"}]}`)}}
	provider, err := NewBedrockProvider(ProviderProfile{
		Provider:     "bedrock",
		Model:        "anthropic.claude-3-sonnet-20240229-v1:0",
		SecretValues: []string{secret},
	}, AWSProviderOptions{BedrockClient: client})
	if err != nil {
		t.Fatalf("NewBedrockProvider() error = %v", err)
	}
	diagnosis, err := provider.Diagnose(context.Background(), &scanner.Issue{ID: "issue-bedrock", Kind: "Pod", Name: "worker"})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if diagnosis.IssueID != "issue-bedrock" || strings.Contains(diagnosis.RootCause, secret) {
		t.Fatalf("Diagnose() = %#v", diagnosis)
	}
}

func TestSageMakerProviderUsesInjectedClientAndBoundsOutput(t *testing.T) {
	const secret = "sagemaker-secret"
	client := &fakeSageMakerRuntimeClient{
		output: &sagemakerruntime.InvokeEndpointOutput{Body: []byte(`{"generated_text":"safe response"}`)},
	}
	provider, err := NewSageMakerProvider(ProviderProfile{
		Provider:     "sagemaker",
		Endpoint:     "sre-endpoint",
		AWSRegion:    "us-west-2",
		SecretValues: []string{secret},
	}, AWSProviderOptions{SageMakerClient: client})
	if err != nil {
		t.Fatalf("NewSageMakerProvider() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "inspect "+secret, nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if reply != "safe response" || strings.Contains(reply, secret) {
		t.Fatalf("Explain() = %q", reply)
	}
	if client.input == nil || aws.ToString(client.input.EndpointName) != "sre-endpoint" {
		t.Fatalf("InvokeEndpoint input = %#v", client.input)
	}
	if got := aws.ToString(client.input.ContentType); got != "application/json" {
		t.Fatalf("ContentType = %q", got)
	}
	if strings.Contains(string(client.input.Body), secret) {
		t.Fatalf("request body leaked secret: %s", client.input.Body)
	}
}

func TestAWSProvidersClassifyBoundsAndSDKErrorsWithoutLeakingDetails(t *testing.T) {
	const secret = "sdk-credential-secret"
	largeBody := []byte(strings.Repeat("x", 33))
	client := &fakeBedrockRuntimeClient{output: &bedrockruntime.InvokeModelOutput{Body: largeBody}}
	provider, err := NewBedrockProvider(ProviderProfile{
		Provider:         "bedrock",
		Model:            "amazon.titan-text-express-v1",
		MaxResponseBytes: 32,
		SecretValues:     []string{secret},
	}, AWSProviderOptions{BedrockClient: client})
	if err != nil {
		t.Fatalf("NewBedrockProvider() error = %v", err)
	}
	_, err = provider.Explain(context.Background(), "hello", nil)
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorLimit {
		t.Fatalf("oversized response error = %v, want bounded provider error", err)
	}

	client.err = errors.New("access key=" + secret)
	_, err = provider.Explain(context.Background(), "hello", nil)
	if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorTransport || strings.Contains(err.Error(), secret) {
		t.Fatalf("SDK error = %v, want safe transport error", err)
	}
}

func TestAWSProviderHonorsCallerDeadline(t *testing.T) {
	started := make(chan struct{})
	client := &fakeBedrockRuntimeClient{call: func(ctx context.Context, _ *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	provider, err := NewBedrockProvider(ProviderProfile{
		Provider: "bedrock",
		Model:    "amazon.titan-text-express-v1",
		Timeout:  time.Second,
	}, AWSProviderOptions{BedrockClient: client})
	if err != nil {
		t.Fatalf("NewBedrockProvider() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = provider.Explain(ctx, "hello", nil)
	<-started
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != ProviderErrorTimeout {
		t.Fatalf("deadline error = %v, want timeout provider error", err)
	}
}

func TestAWSProviderFactoryKeepsHTTPCompatibilityAndSupportsNativeMode(t *testing.T) {
	legacy, err := NewProviderFromProfile(ProviderProfile{
		Provider:          "bedrock",
		Endpoint:          "https://bedrock.example.test",
		EndpointAllowlist: []string{"https://bedrock.example.test"},
		Model:             "model",
	})
	if err != nil {
		t.Fatalf("legacy provider construction error = %v", err)
	}
	if _, ok := legacy.(*CloudProvider); !ok {
		t.Fatalf("legacy provider type = %T, want *CloudProvider", legacy)
	}

	client := &fakeSageMakerRuntimeClient{output: &sagemakerruntime.InvokeEndpointOutput{Body: []byte(`{"generated_text":"native"}`)}}
	native, err := NewProviderFromProfileWithAWS(ProviderProfile{
		Provider: "sagemaker",
		Mode:     ProviderModeAWS,
		Endpoint: "native-endpoint",
		Model:    "model",
	}, AWSProviderOptions{SageMakerClient: client})
	if err != nil {
		t.Fatalf("native provider construction error = %v", err)
	}
	if _, ok := native.(*SageMakerProvider); !ok {
		t.Fatalf("native provider type = %T, want *SageMakerProvider", native)
	}
	if _, ok := native.(StructuredTaskRunner); !ok {
		t.Fatalf("native provider type = %T, want StructuredTaskRunner", native)
	}

	bedrockNative, err := NewProviderFromProfileWithAWS(ProviderProfile{
		Provider: "bedrock",
		Mode:     ProviderModeAWS,
		Model:    "amazon.titan-text-express-v1",
	}, AWSProviderOptions{BedrockClient: &fakeBedrockRuntimeClient{}})
	if err != nil {
		t.Fatalf("bedrock native provider construction error = %v", err)
	}
	if _, ok := bedrockNative.(StructuredTaskRunner); !ok {
		t.Fatalf("bedrock native provider type = %T, want StructuredTaskRunner", bedrockNative)
	}
}

func TestNativeAWSProvidersRunStructuredFailClosed(t *testing.T) {
	bedrockClient := &fakeBedrockRuntimeClient{output: &bedrockruntime.InvokeModelOutput{Body: []byte(`{"content":[{"text":"{\"ok\":true}"}]}`)}}
	bedrock, err := NewBedrockProvider(ProviderProfile{
		Provider: "bedrock",
		Model:    "amazon.titan-text-express-v1",
	}, AWSProviderOptions{BedrockClient: bedrockClient})
	if err != nil {
		t.Fatalf("NewBedrockProvider() error = %v", err)
	}
	_, err = bedrock.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.digest",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if !errors.Is(err, ErrStructuredTaskUnsupported) {
		t.Fatalf("Bedrock RunStructured() error = %v, want ErrStructuredTaskUnsupported", err)
	}
	if bedrockClient.input != nil {
		t.Fatalf("Bedrock RunStructured() invoked native client: %#v", bedrockClient.input)
	}

	sageMakerClient := &fakeSageMakerRuntimeClient{output: &sagemakerruntime.InvokeEndpointOutput{Body: []byte(`{"generated_text":"{\"ok\":true}"}`)}}
	sageMaker, err := NewSageMakerProvider(ProviderProfile{
		Provider: "sagemaker",
		Endpoint: "native-endpoint",
		Model:    "model",
	}, AWSProviderOptions{SageMakerClient: sageMakerClient})
	if err != nil {
		t.Fatalf("NewSageMakerProvider() error = %v", err)
	}
	_, err = sageMaker.RunStructured(context.Background(), StructuredTask{
		Operation:    "playbook.digest",
		SystemPrompt: "system",
		UserPrompt:   "user",
	})
	if !errors.Is(err, ErrStructuredTaskUnsupported) {
		t.Fatalf("SageMaker RunStructured() error = %v, want ErrStructuredTaskUnsupported", err)
	}
	if sageMakerClient.input != nil {
		t.Fatalf("SageMaker RunStructured() invoked native client: %#v", sageMakerClient.input)
	}
}

func TestAWSProviderUsesInjectedTransportForSDKClient(t *testing.T) {
	called := false
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		if request.URL.Host == "" {
			t.Fatal("SDK request has no host")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"generation":"transport response"}`)),
			Request:    request,
		}, nil
	})
	config := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("test-access-key", "test-signing-secret", ""),
		HTTPClient:  &http.Client{Transport: transport},
	}
	provider, err := NewBedrockProvider(ProviderProfile{
		Provider: "bedrock",
		Model:    "meta.llama3-8b-instruct-v1:0",
	}, AWSProviderOptions{AWSConfig: &config})
	if err != nil {
		t.Fatalf("NewBedrockProvider() error = %v", err)
	}
	reply, err := provider.Explain(context.Background(), "hello", nil)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if reply != "transport response" || !called {
		t.Fatalf("Explain() = %q, transport called = %t", reply, called)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
