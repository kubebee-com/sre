package main

import "testing"

func TestCommandRequiresExplicitConfiguration(t *testing.T) {
	if err := run([]string{}); err == nil {
		t.Fatal("missing configuration accepted")
	}
	if err := run([]string{"--control-plane=http://localhost", "--namespaces=default"}); err == nil {
		t.Fatal("unsafe configuration accepted")
	}
}
