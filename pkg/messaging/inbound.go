// Package messaging authenticates inbound platform commands before invoking the
// existing governed service. It never accepts platform roles as authorization.
package messaging

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/identity"
)

type User struct {
	ExternalID  string   `json:"external_id"`
	PrincipalID string   `json:"principal_id"`
	Groups      []string `json:"groups"`
}

// AccountID is the Slack team, Discord guild, or Telegram bot identity. Telegram
// authenticates the bot through a unique webhook secret, since updates omit it.
type Config struct {
	ID             string         `json:"id"`
	Provider       string         `json:"provider"`
	SecretEnv      string         `json:"secret_env"`
	PublicKey      string         `json:"public_key"`
	AccountID      string         `json:"account_id"`
	ConversationID string         `json:"conversation_id"`
	Scope          identity.Scope `json:"scope"`
	Users          []User         `json:"users"`
}
type Command struct {
	Verb, ID, Value string
	Version         int64
}
type endpoint struct {
	config Config
	secret []byte
	key    ed25519.PublicKey
	users  map[string]User
}
type handler struct {
	endpoints map[string]endpoint
	execute   func(context.Context, identity.Principal, identity.Scope, Command) error
}

// ErrRetryable identifies a transient service failure that should not be acknowledged.
// Callbacks must honor their context deadline and preserve governed idempotency.
var ErrRetryable = errors.New("messaging command temporarily unavailable")

var errInvalid = errors.New("invalid messaging configuration or command")

func New(configs []Config, execute func(context.Context, identity.Principal, identity.Scope, Command) error) (http.Handler, error) {
	if execute == nil || len(configs) > 128 {
		return nil, errInvalid
	}
	h := &handler{endpoints: map[string]endpoint{}, execute: execute}
	telegramSecrets := map[string]bool{}
	for _, c := range configs {
		if !identity.ValidID(c.ID) || c.Scope.Validate() != nil || !safe(c.AccountID) || !safe(c.ConversationID) || len(c.Users) == 0 || len(c.Users) > 1024 {
			return nil, errInvalid
		}
		if _, ok := h.endpoints[c.ID]; ok {
			return nil, errInvalid
		}
		e := endpoint{config: c, users: map[string]User{}}
		switch c.Provider {
		case "slack", "telegram":
			e.secret = []byte(os.Getenv(c.SecretEnv))
			if len(e.secret) == 0 {
				return nil, errInvalid
			}
			if c.Provider == "telegram" {
				if !validTelegramSecret(e.secret) || telegramSecrets[string(e.secret)] {
					return nil, errInvalid
				}
				telegramSecrets[string(e.secret)] = true
			}
		case "discord":
			key, err := hex.DecodeString(c.PublicKey)
			if err != nil || len(key) != ed25519.PublicKeySize {
				return nil, errInvalid
			}
			e.key = key
		default:
			return nil, errInvalid
		}
		for _, u := range c.Users {
			if !safe(u.ExternalID) || !identity.ValidID(u.PrincipalID) || len(u.Groups) > 128 {
				return nil, errInvalid
			}
			if _, ok := e.users[u.ExternalID]; ok {
				return nil, errInvalid
			}
			for _, g := range u.Groups {
				if !safe(g) {
					return nil, errInvalid
				}
			}
			u.Groups = append([]string(nil), u.Groups...)
			e.users[u.ExternalID] = u
		}
		h.endpoints[c.ID] = e
	}
	return h, nil
}
func validTelegramSecret(secret []byte) bool {
	if len(secret) == 0 || len(secret) > 256 {
		return false
	}
	for _, b := range secret {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}
func safe(s string) bool { return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\r\n\x00") }
func parseCommand(text string) (Command, error) {
	p := strings.Fields(text)
	if len(p) < 2 || !identity.ValidID(p[1]) {
		return Command{}, errInvalid
	}
	c := Command{Verb: p[0], ID: p[1]}
	switch c.Verb {
	case "ack", "reject":
		if len(p) != 2 {
			return Command{}, errInvalid
		}
	case "approve":
		if len(p) != 3 || len(p[2]) != 64 || strings.ToLower(p[2]) != p[2] {
			return Command{}, errInvalid
		}
		if _, err := hex.DecodeString(p[2]); err != nil {
			return Command{}, errInvalid
		}
		c.Value = p[2]
	case "answer":
		if len(p) != 4 || !identity.ValidID(p[3]) {
			return Command{}, errInvalid
		}
		v, err := strconv.ParseInt(p[2], 10, 64)
		if err != nil || v < 1 || strconv.FormatInt(v, 10) != p[2] {
			return Command{}, errInvalid
		}
		c.Version = v
		c.Value = p[3]
	default:
		return Command{}, errInvalid
	}
	return c, nil
}
func fresh(raw string) bool {
	n, err := strconv.ParseInt(raw, 10, 64)
	now := time.Now().Unix()
	return err == nil && n >= now-300 && n <= now+30
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 4 || parts[1] != "channels" || parts[3] != "events" {
		http.NotFound(w, r)
		return
	}
	e, ok := h.endpoints[parts[2]]
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		http.Error(w, "invalid request", http.StatusRequestEntityTooLarge)
		return
	}
	user, text, ignored, ping, err := e.decode(r, body)
	if err != nil {
		http.Error(w, "request rejected", http.StatusUnauthorized)
		return
	}
	if ping {
		respond(w, map[string]any{"type": 1})
		return
	}
	if ignored {
		w.WriteHeader(http.StatusOK)
		return
	}
	u, ok := e.users[user]
	if !ok {
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	command, err := parseCommand(text)
	if err != nil {
		http.Error(w, "unsupported command", http.StatusBadRequest)
		return
	}
	now := time.Now()
	p := identity.Principal{ID: u.PrincipalID, Issuer: "https://sre.internal/messaging/" + e.config.Provider + "/" + url.PathEscape(e.config.AccountID), Groups: append([]string(nil), u.Groups...), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	message := "Command accepted."
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err = h.execute(ctx, p, e.config.Scope, command); errors.Is(err, ErrRetryable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		http.Error(w, "command temporarily unavailable", http.StatusServiceUnavailable)
		return
	} else if err != nil {
		message = "Command rejected by policy or current state."
	}
	switch e.config.Provider {
	case "slack":
		respond(w, map[string]any{"response_type": "ephemeral", "text": message})
	case "discord":
		respond(w, map[string]any{"type": 4, "data": map[string]any{"content": message, "flags": 64, "allowed_mentions": map[string]any{"parse": []string{}}}})
	default:
		respond(w, map[string]any{"ok": true})
	}
}
func respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (e endpoint) decode(r *http.Request, body []byte) (user, text string, ignored, ping bool, err error) {
	fail := func() (string, string, bool, bool, error) { return "", "", false, false, errInvalid }
	switch e.config.Provider {
	case "slack":
		ts := r.Header.Get("X-Slack-Request-Timestamp")
		if !fresh(ts) {
			return fail()
		}
		mac := hmac.New(sha256.New, e.secret)
		_, _ = mac.Write([]byte("v0:" + ts + ":"))
		_, _ = mac.Write(body)
		if !hmac.Equal([]byte("v0="+hex.EncodeToString(mac.Sum(nil))), []byte(r.Header.Get("X-Slack-Signature"))) {
			return fail()
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return fail()
		}
		for _, values := range form {
			if len(values) != 1 {
				return fail()
			}
		}
		if form.Get("team_id") != e.config.AccountID || form.Get("channel_id") != e.config.ConversationID || form.Get("command") != "/sre" {
			return fail()
		}
		return form.Get("user_id"), form.Get("text"), form.Get("bot_id") != "" || form.Get("user_id") == "USLACKBOT", false, nil
	case "discord":
		ts := r.Header.Get("X-Signature-Timestamp")
		sig, err := hex.DecodeString(r.Header.Get("X-Signature-Ed25519"))
		if err != nil || !fresh(ts) || !ed25519.Verify(e.key, append([]byte(ts), body...), sig) {
			return fail()
		}
		var v struct {
			Type      int    `json:"type"`
			GuildID   string `json:"guild_id"`
			ChannelID string `json:"channel_id"`
			Member    struct {
				User struct {
					ID  string `json:"id"`
					Bot bool   `json:"bot"`
				} `json:"user"`
			} `json:"member"`
			Data struct {
				Name    string `json:"name"`
				Options []struct {
					Name  string `json:"name"`
					Type  int    `json:"type"`
					Value string `json:"value"`
				} `json:"options"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &v) != nil {
			return fail()
		}
		if v.Type == 1 {
			return "", "", false, true, nil
		}
		if v.Type != 2 || v.GuildID != e.config.AccountID || v.ChannelID != e.config.ConversationID || v.Data.Name != "sre" || len(v.Data.Options) != 1 || v.Data.Options[0].Name != "command" || v.Data.Options[0].Type != 3 {
			return fail()
		}
		return v.Member.User.ID, v.Data.Options[0].Value, v.Member.User.Bot, false, nil
	case "telegram":
		if !hmac.Equal(e.secret, []byte(r.Header.Get("X-Telegram-Bot-Api-Secret-Token"))) {
			return fail()
		}
		var v struct {
			Message *struct {
				Date int64  `json:"date"`
				Text string `json:"text"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
				From *struct {
					ID  int64 `json:"id"`
					Bot bool  `json:"is_bot"`
				} `json:"from"`
				SenderChat json.RawMessage `json:"sender_chat"`
			} `json:"message"`
		}
		if json.Unmarshal(body, &v) != nil || v.Message == nil || v.Message.From == nil {
			return fail()
		}
		m := v.Message
		if !fresh(strconv.FormatInt(m.Date, 10)) || strconv.FormatInt(m.Chat.ID, 10) != e.config.ConversationID {
			return fail()
		}
		parts := strings.SplitN(m.Text, " ", 2)
		if len(parts) != 2 || (parts[0] != "/sre" && parts[0] != "/sre@"+e.config.AccountID) {
			return fail()
		}
		return strconv.FormatInt(m.From.ID, 10), parts[1], m.From.Bot || len(m.SenderChat) > 0, false, nil
	}
	return fail()
}
