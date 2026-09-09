// Package fleet manages role-bound source identities independently of engineers.
package fleet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"time"
)

const (
	Collector = "COLLECTOR"
	Executor  = "EXECUTOR"
)

var ErrAgentUnauthorized = errors.New("current scoped agent credential required")

type Credential struct {
	Token string         `json:"token"`
	Agent incident.Agent `json:"agent"`
}
type Service struct {
	DB     *postgres.Store
	Policy *authorization.Policy
	Epoch  string
}

func NewService(db *postgres.Store, policy *authorization.Policy, externalGeneration string) (*Service, error) {
	if db == nil || policy == nil || !identity.ValidID(externalGeneration) {
		return nil, postgres.ErrInvalid
	}
	// Replicas share authority until the operator explicitly rotates the external
	// generation (including after a database restore).
	digest := sha256.Sum256([]byte(externalGeneration))
	epoch := hex.EncodeToString(digest[:])
	if err := db.SetAuthorityEpoch(epoch); err != nil {
		return nil, err
	}
	return &Service{DB: db, Policy: policy, Epoch: epoch}, nil
}
func audience(role string) string {
	switch role {
	case Collector:
		return "sre-evidence"
	case Executor:
		return "sre-execution"
	}
	return ""
}
func TokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
func newToken() string {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic("secure token generation unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(data[:])
}
func (s *Service) Bootstrap(ctx context.Context, principal identity.Principal, scope identity.Scope, id, uid, role string) (Credential, error) {
	if err := s.Policy.Authorize(principal, scope, authorization.Setup); err != nil {
		return Credential{}, err
	}
	if !identity.ValidID(id) || !identity.ValidID(uid) || audience(role) == "" {
		return Credential{}, postgres.ErrInvalid
	}
	result := Credential{Token: newToken(), Agent: incident.Agent{Scope: scope, ID: id, Role: role, Audience: audience(role), Epoch: s.Epoch, ClusterUID: uid, ExpiresAt: time.Now().Add(10 * time.Minute)}}
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		return tx.CreateBootstrap(incident.AgentBootstrap{Agent: result.Agent, TokenHash: TokenHash(result.Token), ExpiresAt: result.Agent.ExpiresAt})
	})
	if err != nil {
		return Credential{}, err
	}
	return result, nil
}
func (s *Service) Enroll(ctx context.Context, scope identity.Scope, bootstrap, uid, role string) (Credential, error) {
	if len(bootstrap) != 43 || !identity.ValidID(uid) || audience(role) == "" {
		return Credential{}, ErrAgentUnauthorized
	}
	result := Credential{Token: newToken()}
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		a, err := tx.ConsumeBootstrap(TokenHash(bootstrap), uid, role, audience(role), s.Epoch, TokenHash(result.Token), time.Now().Add(30*time.Minute))
		result.Agent = a
		return err
	})
	if err != nil {
		return Credential{}, ErrAgentUnauthorized
	}
	return result, nil
}
func (s *Service) AuthenticateTx(tx *postgres.Tx, token, role string) (incident.Agent, error) {
	if len(token) != 43 || audience(role) == "" {
		return incident.Agent{}, ErrAgentUnauthorized
	}
	agent, err := tx.AgentByToken(TokenHash(token))
	if err != nil {
		return incident.Agent{}, ErrAgentUnauthorized
	}
	if agent.Revoked || !agent.ExpiresAt.After(time.Now()) || agent.Epoch != s.Epoch || agent.Role != role || agent.Audience != audience(role) {
		return incident.Agent{}, ErrAgentUnauthorized
	}
	return agent, nil
}
func (s *Service) Authenticate(ctx context.Context, scope identity.Scope, token, role string) (incident.Agent, error) {
	var a incident.Agent
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error { var err error; a, err = s.AuthenticateTx(tx, token, role); return err })
	return a, err
}
func (s *Service) Renew(ctx context.Context, scope identity.Scope, token, role string) (Credential, error) {
	result := Credential{Token: newToken()}
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		agent, err := s.AuthenticateTx(tx, token, role)
		if err != nil {
			return err
		}
		result.Agent, err = tx.RotateAgent(agent.ID, agent.Generation, TokenHash(result.Token), time.Now().Add(30*time.Minute))
		return err
	})
	if err != nil {
		return Credential{}, err
	}
	return result, nil
}
func (s *Service) Revoke(ctx context.Context, principal identity.Principal, scope identity.Scope, id string) error {
	if err := s.Policy.Authorize(principal, scope, authorization.Setup); err != nil {
		return err
	}
	return s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.RevokeAgent(id) })
}
