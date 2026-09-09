// sre-orchestrator is a scoped engineer client. It never reads kubeconfig or runs
// cluster tools; all commands use the orchestrator authorization services.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/kubebee-com/sre/pkg/identity"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type options struct {
	server, tokenFile, organization, cluster, application, incident, id, hash, profile, dataFile, after string
	acknowledge                                                                                         bool
}

func route(command string, o options) (string, string, any, error) {
	id := url.PathEscape(o.id)
	incident := url.PathEscape(o.incident)
	switch command {
	case "incidents":
		return "GET", "/api/incidents", nil, nil
	case "items", "jobs":
		if !identity.ValidID(o.incident) {
			break
		}
		return "GET", "/api/incidents/" + incident + "/" + command, nil, nil
	case "actions", "agents", "notifications", "quality", "environment", "golden-cases", "operations":
		return "GET", "/api/" + command, nil, nil
	case "investigate":
		if !identity.ValidID(o.incident) || !identity.ValidID(o.profile) {
			break
		}
		return "POST", "/api/incidents/" + incident + "/investigate", map[string]string{"profile_id": o.profile}, nil
	case "approve", "reconcile-action":
		if !o.acknowledge || !identity.ValidID(o.id) || len(o.hash) != 64 {
			break
		}
		operation := "approve"
		if command == "reconcile-action" {
			operation = "reconcile"
		}
		return "POST", "/api/actions/" + id + "/" + operation, map[string]string{"hash": o.hash}, nil
	case "cancel-action", "cancel-job", "acknowledge", "revoke":
		if !identity.ValidID(o.id) {
			break
		}
		paths := map[string]string{"cancel-action": "/api/actions/" + id + "/cancel", "cancel-job": "/api/jobs/" + id + "/cancel", "acknowledge": "/api/notifications/" + id + "/acknowledge", "revoke": "/api/agents/" + id + "/revoke"}
		return "POST", paths[command], struct{}{}, nil
	case "recovery":
		if !identity.ValidID(o.incident) {
			break
		}
		return "POST", "/api/incidents/" + incident + "/recovery", struct{}{}, nil
	case "feedback", "propose", "bootstrap", "set-environment", "set-recovery", "adjudicate", "corroborate", "create-golden", "review-golden":
		paths := map[string]string{"feedback": "/api/incidents/" + incident + "/feedback", "propose": "/api/actions", "bootstrap": "/api/agents/bootstrap", "set-environment": "/api/environment", "set-recovery": "/api/recovery-profile", "adjudicate": "/api/adjudications", "corroborate": "/api/corroborations", "create-golden": "/api/golden-cases", "review-golden": "/api/golden-cases/" + id + "/review"}
		if (command == "feedback" && !identity.ValidID(o.incident)) || (command == "review-golden" && !identity.ValidID(o.id)) {
			break
		}
		raw, err := readBounded(o.dataFile, 65536, false)
		if err != nil || !json.Valid(raw) {
			break
		}
		return "POST", paths[command], json.RawMessage(raw), nil
	}
	return "", "", nil, errors.New("command requires explicit scope, identifiers and input; approval and reconciliation also require --acknowledge and --hash")
}
func readBounded(path string, limit int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || (private && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("input file unavailable or unsafe")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input file unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("input unavailable")
	}
	return raw, nil
}
func run(args []string, out io.Writer) error {
	var o options
	flags := flag.NewFlagSet("sre-orchestrator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&o.server, "server", "", "HTTPS orchestrator URL")
	flags.StringVar(&o.tokenFile, "token-file", "", "private OIDC bearer token file")
	flags.StringVar(&o.organization, "organization-id", "", "organization")
	flags.StringVar(&o.cluster, "cluster-id", "", "cluster")
	flags.StringVar(&o.application, "application-id", "", "application")
	flags.StringVar(&o.incident, "incident", "", "incident ID")
	flags.StringVar(&o.id, "id", "", "record ID")
	flags.StringVar(&o.after, "after", "", "last record ID from the preceding page")
	flags.StringVar(&o.hash, "hash", "", "exact approval hash")
	flags.StringVar(&o.profile, "profile", "", "approved AI profile")
	flags.StringVar(&o.dataFile, "data-file", "", "JSON request file")
	flags.BoolVar(&o.acknowledge, "acknowledge", false, "explicitly authorize the exact described action")
	if flags.Parse(args) != nil || flags.NArg() != 1 {
		return errors.New("provide connection flags followed by one orchestrator command")
	}
	scope := identity.Scope{OrganizationID: o.organization, ClusterID: o.cluster, ApplicationID: o.application}
	u, err := url.Parse(o.server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || scope.Validate() != nil {
		return errors.New("explicit HTTPS endpoint and complete scope required")
	}
	method, path, body, err := route(flags.Arg(0), o)
	if err != nil {
		return err
	}
	token, err := readBounded(o.tokenFile, 32768, true)
	if err != nil {
		return err
	}
	bearer := strings.TrimSpace(string(token))
	if bearer == "" || strings.ContainsAny(bearer, "\r\n") {
		return errors.New("OIDC credential invalid")
	}
	raw, _ := json.Marshal(body)
	q := url.Values{"organization_id": {scope.OrganizationID}, "cluster_id": {scope.ClusterID}, "application_id": {scope.ApplicationID}}
	if o.after != "" {
		if method != "GET" || !identity.ValidID(o.after) {
			return errors.New("valid pagination ID required")
		}
		q.Set("after", o.after)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(o.server, "/")+path+"?"+q.Encode(), bytes.NewReader(raw))
	if err != nil {
		return errors.New("request unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("orchestrator request unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("orchestrator request rejected (%d)", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 || !json.Valid(data) {
		return errors.New("orchestrator response invalid")
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, data, "", "  ") != nil {
		return errors.New("orchestrator response invalid")
	}
	_, err = fmt.Fprintln(out, pretty.String())
	return err
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
