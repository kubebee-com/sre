package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

var ErrRuntime = errors.New("executor operation unavailable")
var ErrReenrollment = errors.New("executor authorization rejected; administrator re-enrollment required")

const maxWireBytes = 64 << 10

type controlClient struct {
	origin string
	scope  identity.Scope
	http   *http.Client
}

func newControlClient(origin string, scope identity.Scope, client *http.Client) (*controlClient, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || scope.Validate() != nil {
		return nil, ErrRuntime
	}
	if client == nil {
		client = &http.Client{}
	}
	bounded := *client
	bounded.Timeout = 15 * time.Second
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRuntime }
	return &controlClient{origin: "https://" + u.Host, scope: scope, http: &bounded}, nil
}
func (c *controlClient) post(ctx context.Context, path, token string, in, out any) error {
	return c.request(ctx, http.MethodPost, path, token, in, out)
}
func (c *controlClient) request(ctx context.Context, method, path, token string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil || len(b) > maxWireBytes {
		return ErrRuntime
	}
	q := url.Values{"organization_id": {c.scope.OrganizationID}, "cluster_id": {c.scope.ClusterID}, "application_id": {c.scope.ApplicationID}}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path+"?"+q.Encode(), bytes.NewReader(b))
	if err != nil {
		return ErrRuntime
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ErrRuntime
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return ErrReenrollment
	}
	b, err = io.ReadAll(io.LimitReader(resp.Body, maxWireBytes+1))
	if err != nil || len(b) > maxWireBytes || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrRuntime
	}
	if out != nil {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
			return ErrRuntime
		}
	}
	return nil
}
func (c *controlClient) enroll(ctx context.Context, token, uid string) (fleet.Credential, error) {
	var out fleet.Credential
	err := c.post(ctx, "/agent/enroll", "", map[string]string{"token": token, "cluster_uid": uid, "role": fleet.Executor}, &out)
	return out, err
}
func (c *controlClient) renew(ctx context.Context, old fleet.Credential) (fleet.Credential, error) {
	var out fleet.Credential
	err := c.post(ctx, "/agent/renew", old.Token, map[string]string{"role": fleet.Executor}, &out)
	return out, err
}
func readPrivate(path string, limit int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > limit {
		return nil, ErrRuntime
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrRuntime
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, ErrRuntime
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrRuntime
	}
	return b, nil
}
func loadCredential(path string) (fleet.Credential, error) {
	var c fleet.Credential
	b, err := readPrivate(path, maxWireBytes)
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, ErrRuntime
	}
	return c, nil
}
func saveCredential(path string, c fleet.Credential) error { return savePrivate(path, c) }
func savePrivate(path string, c any) error {
	dir := filepath.Dir(path)
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return ErrRuntime
	}
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
		return ErrRuntime
	} else if err != nil && !os.IsNotExist(err) {
		return ErrRuntime
	}
	b, err := json.Marshal(c)
	if err != nil || len(b) > maxWireBytes {
		return ErrRuntime
	}
	f, err := os.CreateTemp(dir, ".credential-*")
	if err != nil {
		return ErrRuntime
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if f.Chmod(0600) != nil {
		return ErrRuntime
	}
	if _, err = f.Write(b); err != nil {
		return ErrRuntime
	}
	if f.Sync() != nil || f.Close() != nil {
		return ErrRuntime
	}
	if os.Rename(f.Name(), path) != nil {
		return ErrRuntime
	}
	d, err := os.Open(dir)
	if err != nil {
		return ErrRuntime
	}
	defer d.Close()
	if d.Sync() != nil {
		return ErrRuntime
	}
	return nil
}
