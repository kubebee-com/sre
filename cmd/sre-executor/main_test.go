package main

import "testing"

func TestCLIRejectsMissingExplicitAuthority(t *testing.T) {
	for _, args := range [][]string{nil, {"--in-cluster"}, {"--kubeconfig", "x", "--in-cluster"}, {"--namespaces", "work", "--identity-key-file", "/missing"}, {"--bogus"}} {
		if run(args) == nil {
			t.Fatal("accepted incomplete authority")
		}
	}
}
