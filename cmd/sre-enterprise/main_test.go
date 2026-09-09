package main

import (
	"strings"
	"testing"
)

func TestApprovalRequiresExactAcknowledgmentAndNoGenericMutation(t *testing.T) {
	o := options{id: "action", hash: strings.Repeat("a", 64)}
	if _, _, _, err := route("approve", o); err == nil {
		t.Fatal("approval lacked acknowledgment")
	}
	o.acknowledge = true
	method, path, _, err := route("approve", o)
	if err != nil || method != "POST" || path != "/api/actions/action/approve" {
		t.Fatal("exact approval route")
	}
	for _, cmd := range []string{"exec", "delete", "patch", "kubectl", "post"} {
		if _, _, _, err := route(cmd, o); err == nil {
			t.Fatal("generic mutation exposed")
		}
	}
}

func TestReconcileRequiresExactAcknowledgment(t *testing.T) {
	o := options{id: "action", hash: strings.Repeat("a", 64)}
	if _, _, _, err := route("reconcile-action", o); err == nil {
		t.Fatal("missing acknowledgement accepted")
	}
	o.acknowledge = true
	method, path, body, err := route("reconcile-action", o)
	if err != nil || method != "POST" || path != "/api/actions/action/reconcile" || body.(map[string]string)["hash"] != o.hash {
		t.Fatal("invalid exact reconciliation route", err)
	}
}
