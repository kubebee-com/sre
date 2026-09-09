package executor

import (
	"bytes"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"io"
	"os"
	"syscall"
)

type attempt struct {
	ReceiptToken string `json:"receipt_token"`
	Outcome      string `json:"outcome"`
	Acknowledged bool   `json:"acknowledged"`
}

func (r *Runtime) openJournal() error {
	path := r.config.CredentialFile + ".lock"
	fd, e := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrRuntime
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		f.Close()
		return ErrRuntime
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return ErrRuntime
	}
	r.lock = f
	r.journal = map[string]attempt{}
	fail := func() error { syscall.Flock(fd, syscall.LOCK_UN); f.Close(); r.lock = nil; return ErrRuntime }
	path = r.config.CredentialFile + ".attempts"
	if _, e = os.Lstat(path); os.IsNotExist(e) {
		if r.persistJournal() != nil {
			return fail()
		}
		return nil
	} else if e != nil {
		return fail()
	}
	b, e := readPrivate(path, maxWireBytes)
	if e != nil {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r.journal) != nil || d.Decode(new(any)) != io.EOF || r.journal == nil || len(r.journal) > 256 {
		return fail()
	}
	for id, a := range r.journal {
		if !identity.ValidID(id) || len(a.ReceiptToken) != 64 {
			return fail()
		}
		switch a.Outcome {
		case "APPLIED", "AMBIGUOUS", "DENIED", "PRECONDITION_FAILED":
		default:
			return fail()
		}
	}
	return nil
}
func (r *Runtime) persistJournal() error {
	return savePrivate(r.config.CredentialFile+".attempts", r.journal)
}

// Confirmed receipts can be compacted: the control plane never reclaims a
// submitted action, and restore changes its authority epoch. Unacknowledged
// attempts are never pruned, because they still require outcome reconciliation.
func (r *Runtime) compactJournal() error {
	if len(r.journal) < 192 {
		return nil
	}
	next := make(map[string]attempt, len(r.journal))
	for id, a := range r.journal {
		next[id] = a
	}
	for id, a := range next {
		if len(next) <= 128 {
			break
		}
		if a.Acknowledged {
			delete(next, id)
		}
	}
	if len(next) == len(r.journal) {
		return nil
	}
	old := r.journal
	r.journal = next
	if err := r.persistJournal(); err != nil {
		r.journal = old
		return err
	}
	return nil
}
