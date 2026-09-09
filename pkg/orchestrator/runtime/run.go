// sre-control-plane never constructs a Kubernetes client or remediation executor.
package runtime

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/kubebee-com/sre/pkg/delivery"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/knowledge"
	"github.com/kubebee-com/sre/pkg/operations"
	"github.com/kubebee-com/sre/pkg/orchestrator"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func Run(ctx context.Context) error {
	file, err := os.Open(setting("SRE_CONFIG", "SRE_ENTERPRISE_CONFIG"))
	if err != nil {
		return errors.New("orchestrator configuration unavailable")
	}
	config, err := orchestrator.ReadDeploymentConfig(file)
	file.Close()
	if err != nil {
		return err
	}
	db, err := postgres.OpenSecure(ctx, setting("SRE_DATABASE_URL", "SRE_ENTERPRISE_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()
	policy, err := config.Policy()
	if err != nil {
		return err
	}
	grantKey, err := base64.StdEncoding.DecodeString(os.Getenv("SRE_AUTHORITY_KEY"))
	if err != nil || len(grantKey) != 32 {
		return errors.New("SRE_AUTHORITY_KEY must contain a base64-encoded 32-byte shared key")
	}
	if err := policy.SetGrantKey(grantKey, os.Getenv("SRE_AUTHORITY_GENERATION")); err != nil {
		return err
	}
	clear(grantKey)
	profiles, err := config.BuildRemoteProfiles()
	if err != nil {
		return err
	}
	publicURL := strings.TrimRight(setting("SRE_PUBLIC_URL", "SRE_ENTERPRISE_PUBLIC_URL"), "/")
	clientID := os.Getenv("SRE_OIDC_CLIENT_ID")
	verifier, err := identity.NewOIDCVerifier(ctx, os.Getenv("SRE_OIDC_ISSUER"), clientID)
	if err != nil {
		return err
	}
	investigations, err := investigation.NewService(db, policy, profiles)
	if err != nil {
		return err
	}
	agents, err := fleet.NewService(db, policy, os.Getenv("SRE_AUTHORITY_GENERATION"))
	if err != nil {
		return err
	}
	investigations.AuthorityEpoch = agents.Epoch
	learning := &knowledge.Service{DB: db, Policy: policy}
	investigations.Guidance = learning.Retrieve
	investigations.ValidateGuidance = knowledge.PublishedEligibleTx
	queue := &investigation.Queue{Service: investigations}
	for _, app := range config.Applications {
		queue.Scopes = append(queue.Scopes, app.Scope)
	}
	notifications, err := delivery.NewService(db, policy, config.Notifications, delivery.NewHTTPSender(publicURL))
	if err != nil {
		return err
	}
	if err := notifications.RegisterRoutes(ctx); err != nil {
		return err
	}
	handler, err := orchestrator.New(orchestrator.Config{Messaging: config.Messaging, Queue: queue, Notifications: notifications, Execution: &execution.Service{Fleet: agents, Enabled: os.Getenv("SRE_EXECUTOR_ENABLED") == "true"}, Fleet: agents, DB: db, Policy: policy, Verifier: verifier, Investigations: investigations, PublicURL: publicURL, OAuth: &oauth2.Config{ClientID: clientID, ClientSecret: os.Getenv("SRE_OIDC_CLIENT_SECRET"), Endpoint: verifier.OAuthEndpoint(), RedirectURL: publicURL + "/auth/callback", Scopes: []string{"openid", "profile", "groups"}}})
	if err != nil {
		return err
	}
	address := setting("SRE_LISTEN", "SRE_ENTERPRISE_LISTEN")
	if address == "" {
		address = ":8080"
	}
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	workers, stopWorkers := context.WithCancel(ctx)
	var workerGroup sync.WaitGroup
	maintenance := &operations.Service{DB: db, Scopes: queue.Scopes, RetentionDays: config.RetentionDays}
	workerGroup.Add(2)
	go func() { defer workerGroup.Done(); maintenance.Run(workers) }()
	defer func() { stopWorkers(); workerGroup.Wait() }()
	go func() { defer workerGroup.Done(); notifications.Run(workers) }()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("orchestrator listener failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
func setting(primary, legacy string) string {
	if v, ok := os.LookupEnv(primary); ok {
		return v
	}
	return os.Getenv(legacy)
}
