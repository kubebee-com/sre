package legacyserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCleanupPostCreatesPendingProposalWithoutDeleting(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "default", UID: types.UID("cleanup-uid"), ResourceVersion: "4"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed},
	})
	engine := remediation.NewEngine(client)
	defer engine.Close()
	s := NewServer(0, scanner.NewClusterScanner(client), triage.NewRuleBasedProvider(), engine, nil)
	rr := serveCleanupRequest(testHandler(t, s), http.MethodPost, `{"namespace":"default","pod_names":["failed"]}`, "")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("cleanup POST status = %d, want %d: %s", rr.Code, http.StatusAccepted, rr.Body.String())
	}
	var response struct {
		CandidatePods []string `json:"candidate_pods"`
		Proposals     []struct {
			ID     string                     `json:"id"`
			Status remediation.ProposalStatus `json:"status"`
		} `json:"proposals"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode cleanup response: %v", err)
	}
	if len(response.CandidatePods) != 1 || response.CandidatePods[0] != "failed" || len(response.Proposals) != 1 || response.Proposals[0].Status != remediation.StatusPending {
		t.Fatalf("cleanup response = %#v", response)
	}
	if _, err := client.CoreV1().Pods("default").Get(context.Background(), "failed", metav1.GetOptions{}); err != nil {
		t.Fatalf("cleanup POST deleted pod before approval: %v", err)
	}
	proposal, ok := engine.GetProposal(response.Proposals[0].ID)
	if !ok || proposal.CreatedBy == "" || proposal.TargetUID != "cleanup-uid" || proposal.TargetResourceVersion != "4" {
		t.Fatalf("cleanup proposal = %#v, found = %v", proposal, ok)
	}
}

func TestCleanupPostRejectsCurrentlyIneligiblePods(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "running", Namespace: "default", UID: types.UID("running-uid"), ResourceVersion: "1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	engine := remediation.NewEngine(client)
	defer engine.Close()
	s := NewServer(0, scanner.NewClusterScanner(client), triage.NewRuleBasedProvider(), engine, nil)
	rr := serveCleanupRequest(testHandler(t, s), http.MethodPost, `{"namespace":"default","pod_names":["running"]}`, "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("ineligible cleanup status = %d, want %d: %s", rr.Code, http.StatusConflict, rr.Body.String())
	}
	if len(engine.ListProposals()) != 0 {
		t.Fatalf("ineligible cleanup created proposals: %#v", engine.ListProposals())
	}
}

func TestCleanupApprovalRechecksEligibilityAndPreconditions(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "default", UID: types.UID("cleanup-uid"), ResourceVersion: "4"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed},
	})
	engine := remediation.NewEngine(client)
	defer engine.Close()
	s := NewServer(0, scanner.NewClusterScanner(client), triage.NewRuleBasedProvider(), engine, nil)
	created := serveCleanupRequest(testHandler(t, s), http.MethodPost, `{"namespace":"default","pod_names":["failed"]}`, "")
	var response struct {
		Proposals []struct {
			ID string `json:"id"`
		} `json:"proposals"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil || len(response.Proposals) != 1 {
		t.Fatalf("cleanup response = %s, decode error = %v", created.Body.String(), err)
	}
	if _, err := client.CoreV1().Pods("default").Update(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "default", UID: types.UID("replacement-uid"), ResourceVersion: "5"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("replace pod: %v", err)
	}
	_, err := engine.Approve(context.Background(), response.Proposals[0].ID, "operator")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "stale") {
		t.Fatalf("stale cleanup approval error = %v, want stale error", err)
	}
	proposal, _ := engine.GetProposal(response.Proposals[0].ID)
	if proposal.Status != remediation.StatusStale {
		t.Fatalf("stale cleanup proposal status = %s, want %s", proposal.Status, remediation.StatusStale)
	}
}

func TestAuditEndpointReturnsSanitizedProposalHistory(t *testing.T) {
	engine := remediation.NewEngine(fake.NewSimpleClientset())
	defer engine.Close()
	issue := &scanner.Issue{ID: "issue-audit-api", Kind: "Pod", Name: "payments"}
	proposal := engine.CreateProposal(issue, &triage.Diagnosis{
		IssueID: issue.ID, Summary: "summary", RootCause: "root", Severity: scanner.SeverityMedium,
		RemediationPlan: "plan", ActionType: triage.ActionManual, ProposedCommand: "kubectl get pods -n default", ConfidenceScore: 0.5,
	})
	if proposal == nil {
		t.Fatal("CreateProposal() returned nil")
	}
	s := NewServer(0, nil, triage.NewRuleBasedProvider(), engine, nil)
	rr := serveTestRequest(testHandler(t, s), http.MethodGet, "/api/audit?proposal_id="+proposal.ID, "", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "create") {
		t.Fatalf("audit response status/body = %d/%s", rr.Code, rr.Body.String())
	}
}

func serveCleanupRequest(handler http.Handler, method, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/clean/pods", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

var _ = time.Second
