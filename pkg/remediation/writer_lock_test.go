package remediation

import (
	"os"
	"os/exec"
	"testing"
)

func TestProposalStoreRejectsSecondWriter(t *testing.T) {
	dir := t.TempDir()
	first, err := NewFileProposalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewFileProposalStore(dir)
	if err == nil {
		second.Close()
		t.Fatal("second file writer was accepted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := NewFileProposalStore(dir)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	defer third.Close()
}

func TestProposalStoreLockAcrossProcesses(t *testing.T) {
	if dir := os.Getenv("SRE_WRITER_LOCK_TEST_DIRECTORY"); dir != "" {
		store, err := NewFileProposalStore(dir)
		if err == nil {
			store.Close()
			t.Fatal("child acquired parent's writer lock")
		}
		return
	}
	dir := t.TempDir()
	store, err := NewFileProposalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestProposalStoreLockAcrossProcesses$")
	child.Env = append(os.Environ(), "SRE_WRITER_LOCK_TEST_DIRECTORY="+dir)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("cross-process lock: %v %s", err, output)
	}
}
