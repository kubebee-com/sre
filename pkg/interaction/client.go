package interaction

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ClientConfig struct {
	BaseURL      string
	HumanToken   string
	Scope        identity.Scope
	IncidentID   string
	Input        io.Reader
	Output       io.Writer
	HTTPClient   *http.Client
	PollInterval time.Duration
}
type terminal struct {
	cfg           ClientConfig
	client        *http.Client
	query         string
	requests      map[string]Request
	actions       map[string]incident.Action
	notifications map[string]incident.Notification
	seen          map[string]string
}

// Run attaches a human channel to central state. It never reads input unless
// called explicitly; EOF detaches without answering or approving pending work.
func Run(ctx context.Context, cfg ClientConfig) error {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.TrimSpace(cfg.HumanToken) == "" || cfg.Scope.Validate() != nil || cfg.Input == nil || cfg.Output == nil || (cfg.IncidentID != "" && !identity.ValidID(cfg.IncidentID)) {
		return ErrInvalid
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }
	q := url.Values{"organization_id": {cfg.Scope.OrganizationID}, "cluster_id": {cfg.Scope.ClusterID}, "application_id": {cfg.Scope.ApplicationID}}
	t := terminal{cfg: cfg, client: &copyClient, query: q.Encode(), seen: map[string]string{}}
	if err := t.refresh(ctx); err != nil {
		return err
	}
	fmt.Fprintln(cfg.Output, "Commands: investigate INCIDENT PROFILE | answer REQUEST CODE | approve ACTION HASH | reject ACTION | ack NOTIFICATION | quit. EOF leaves requests pending.")
	lines := make(chan string)
	readErrors := make(chan error, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		scanner := bufio.NewScanner(cfg.Input)
		scanner.Buffer(make([]byte, 1024), 4096)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-done:
				return
			}
		}
		readErrors <- scanner.Err()
	}()
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErrors:
			return err
		case line := <-lines:
			if strings.TrimSpace(line) == "quit" {
				return nil
			}
			if err := t.command(ctx, line); err != nil {
				fmt.Fprintln(cfg.Output, "Response not accepted:", err)
			}
		case <-ticker.C:
			if err := t.refresh(ctx); err != nil {
				return err
			}
		}
	}
}
func (t *terminal) request(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.cfg.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.cfg.HumanToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := t.client.Do(req)
	if err != nil {
		return errors.New("orchestrator unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("orchestrator returned HTTP %d; refresh before retrying", res.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(out)
}
func page[T any](ctx context.Context, t *terminal, path string, id func(T) string) ([]T, error) {
	var result []T
	after := ""
	for n := 0; n < 100; n++ {
		var values []T
		if err := t.request(ctx, "GET", path+"?"+t.query+"&after="+url.QueryEscape(after), nil, &values); err != nil {
			return nil, err
		}
		result = append(result, values...)
		if len(values) < 50 {
			return result, nil
		}
		next := id(values[len(values)-1])
		if next <= after {
			return nil, errors.New("invalid pagination")
		}
		after = next
	}
	return nil, errors.New("too many records; narrow scope")
}
func (t *terminal) show(key string, value any) {
	raw, _ := json.Marshal(value)
	if t.seen[key] != string(raw) {
		fmt.Fprintln(t.cfg.Output, string(raw))
		t.seen[key] = string(raw)
	}
}
func (t *terminal) refresh(ctx context.Context) error {
	requests, err := page(ctx, t, "/api/interactions", func(r Request) string { return r.ID })
	if err != nil {
		return err
	}
	t.requests = map[string]Request{}
	for _, r := range requests {
		if t.cfg.IncidentID != "" && r.IncidentID != t.cfg.IncidentID {
			continue
		}
		t.requests[r.ID] = r
		if r.Status == "PENDING" && r.ExpiresAt.After(time.Now()) {
			t.show("question/"+r.ID, r)
			t.show("prompt/"+r.ID, map[string]any{"request": r.ID, "prompt": Prompt(r.Question), "options": Options(r.Question)})
		}
	}
	actions, err := page(ctx, t, "/api/actions", func(a incident.Action) string { return a.Plan.ID })
	if err != nil {
		return err
	}
	t.actions = map[string]incident.Action{}
	for _, a := range actions {
		if t.cfg.IncidentID != "" && a.Plan.IncidentID != t.cfg.IncidentID {
			continue
		}
		t.actions[a.Plan.ID] = a
		t.show("action/"+a.Plan.ID, a)
	}
	notifications, err := page(ctx, t, "/api/notifications", func(n incident.Notification) string { return n.ID })
	if err != nil {
		return err
	}
	t.notifications = map[string]incident.Notification{}
	for _, n := range notifications {
		if t.cfg.IncidentID != "" && n.IncidentID != t.cfg.IncidentID {
			continue
		}
		t.notifications[n.ID] = n
		if n.AcknowledgedBy == "" {
			t.show("notification/"+n.ID, n)
		}
	}
	ids := []string{t.cfg.IncidentID}
	if t.cfg.IncidentID == "" {
		incidents, err := page(ctx, t, "/api/incidents", func(i incident.Incident) string { return i.ID })
		if err != nil {
			return err
		}
		ids = nil
		for _, i := range incidents {
			t.show("incident/"+i.ID, i)
			ids = append(ids, i.ID)
		}
	}
	for _, id := range ids {
		var jobs []incident.DiagnosticJob
		if err := t.request(ctx, "GET", "/api/incidents/"+url.PathEscape(id)+"/jobs?"+t.query, nil, &jobs); err != nil {
			return err
		}
		for _, j := range jobs {
			t.show("job/"+j.ID, j)
		}
	}
	return nil
}
func (t *terminal) command(ctx context.Context, line string) error {
	parts := strings.Fields(line)
	if len(parts) < 2 || !identity.ValidID(parts[1]) {
		return ErrInvalid
	}
	id := parts[1]
	var path string
	var body any = map[string]string{}
	switch parts[0] {
	case "investigate":
		if len(parts) != 3 || !identity.ValidID(parts[2]) {
			return ErrInvalid
		}
		path = "/api/incidents/" + id + "/investigate"
		body = map[string]string{"profile_id": parts[2]}
	case "answer":
		r, ok := t.requests[id]
		if len(parts) != 3 || !ok || r.Status != "PENDING" || !r.ExpiresAt.After(time.Now()) || !r.Accepts(parts[2]) {
			return ErrInvalid
		}
		path = "/api/interactions/" + id + "/answer"
		body = map[string]any{"version": r.Version, "answer": parts[2]}
	case "approve":
		a, ok := t.actions[id]
		if len(parts) != 3 || !ok || a.State != "PROPOSED" || a.Hash != parts[2] || !a.Plan.ExpiresAt.After(time.Now()) {
			return ErrInvalid
		}
		path = "/api/actions/" + id + "/approve"
		body = map[string]string{"hash": parts[2]}
	case "reject":
		a, ok := t.actions[id]
		if len(parts) != 2 || !ok || a.State != "PROPOSED" {
			return ErrInvalid
		}
		path = "/api/actions/" + id + "/cancel"
	case "ack":
		if _, ok := t.notifications[id]; len(parts) != 2 || !ok {
			return ErrInvalid
		}
		path = "/api/notifications/" + id + "/acknowledge"
	default:
		return ErrInvalid
	}
	if err := t.request(ctx, "POST", path+"?"+t.query, body, nil); err != nil {
		return err
	}
	fmt.Fprintln(t.cfg.Output, "Response recorded by orchestrator.")
	return nil
}
