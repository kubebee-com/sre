package main

import "testing"

func TestManagedMarkerIsOnlyAnEntrypointMarker(t *testing.T) {
	if got := managedArgs([]string{"--managed", "run", "--in-cluster"}); len(got) != 2 || got[0] != "run" || got[1] != "--in-cluster" {
		t.Fatalf("managed arguments = %#v", got)
	}
	if got := managedArgs([]string{"run"}); len(got) != 1 || got[0] != "run" {
		t.Fatalf("ordinary arguments changed: %#v", got)
	}
}
