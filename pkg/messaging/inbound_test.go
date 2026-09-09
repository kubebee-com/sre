package messaging

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func config(provider string) Config {
	return Config{ID: "ops", Provider: provider, SecretEnv: "IM_TEST_SECRET", AccountID: "account", ConversationID: "room", Scope: identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}, Users: []User{{ExternalID: "123", PrincipalID: "engineer", Groups: []string{"operators"}}}}
}
func TestCommands(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, tc := range []struct {
		text string
		good bool
		want Command
	}{{"approve action " + hash, true, Command{Verb: "approve", ID: "action", Value: hash}}, {"reject action", true, Command{Verb: "reject", ID: "action"}}, {"answer question 2 yes", true, Command{Verb: "answer", ID: "question", Version: 2, Value: "yes"}}, {"ack incident", true, Command{Verb: "ack", ID: "incident"}}, {"investigate incident", false, Command{}}, {"approve action " + strings.Repeat("A", 64), false, Command{}}, {"approve action bad", false, Command{}}, {"answer q 0 yes", false, Command{}}, {"answer q -1 yes", false, Command{}}, {"answer q 9223372036854775808 yes", false, Command{}}, {"answer q 1 ../yes", false, Command{}}, {"reject ../action", false, Command{}}, {"ack a extra", false, Command{}}, {"", false, Command{}}} {
		t.Run(tc.text, func(t *testing.T) {
			got, err := parseCommand(tc.text)
			if (err == nil) != tc.good || tc.good && got != tc.want {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
}
func TestInbound(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, provider := range []string{"slack", "discord", "telegram"} {
		t.Run(provider, func(t *testing.T) {
			t.Setenv("IM_TEST_SECRET", "test_secret_1234567890")
			cfg := config(provider)
			cfg.PublicKey = hex.EncodeToString(pub)
			if provider == "telegram" {
				cfg.ConversationID = "-42"
			}
			for _, kind := range []string{"valid", "signature", "old", "future", "room", "account", "user", "bot", "command", "malformed", "oversized", "execute", "retryable", "deadline", "canceled", "parent-deadline", "method", "path", "ping"} {
				t.Run(kind, func(t *testing.T) {
					if provider == "telegram" && kind == "account" || provider != "discord" && kind == "ping" {
						t.Skip("not present in protocol")
					}
					called := 0
					h, err := New([]Config{cfg}, func(ctx context.Context, p identity.Principal, s identity.Scope, c Command) error {
						called++
						deadline, ok := ctx.Deadline()
						if !ok || time.Until(deadline) > 2*time.Second || time.Until(deadline) <= 0 {
							t.Errorf("missing or invalid callback deadline: %v %v", deadline, ok)
						}
						if kind == "parent-deadline" && time.Until(deadline) > 500*time.Millisecond {
							t.Error("parent deadline extended")
						}
						switch kind {
						case "retryable":
							return errors.Join(errors.New("private detail"), ErrRetryable)
						case "deadline":
							return errors.Join(errors.New("private detail"), context.DeadlineExceeded)
						case "canceled":
							return errors.Join(errors.New("private detail"), context.Canceled)
						}
						if p.ID != "engineer" || !p.Valid(time.Now()) || len(p.Groups) != 1 || p.Groups[0] != "operators" || s != cfg.Scope || c.Verb != "ack" || c.ID != "incident" {
							t.Errorf("wrong authority or command: %+v %+v %+v", p, s, c)
						}
						if kind == "execute" {
							return errors.New("private detail")
						}
						return nil
					})
					if err != nil {
						t.Fatal(err)
					}
					now := time.Now().Unix()
					if kind == "old" {
						now -= 600
					}
					if kind == "future" {
						now += 600
					}
					ts := strconv.FormatInt(now, 10)
					account, room, user, command := cfg.AccountID, cfg.ConversationID, "123", "ack incident"
					if kind == "account" {
						account = "other"
					}
					if kind == "room" {
						room = "999"
					}
					if kind == "user" {
						user = "999"
					}
					if kind == "command" {
						command = "investigate incident"
					}
					var body string
					switch provider {
					case "slack":
						v := url.Values{"team_id": {account}, "channel_id": {room}, "user_id": {user}, "command": {"/sre"}, "text": {command}}
						if kind == "bot" {
							v.Set("bot_id", "B1")
						}
						body = v.Encode()
					case "discord":
						typ := 2
						if kind == "ping" {
							typ = 1
						}
						b, _ := json.Marshal(map[string]any{"type": typ, "guild_id": account, "channel_id": room, "member": map[string]any{"user": map[string]any{"id": user, "bot": kind == "bot"}}, "data": map[string]any{"name": "sre", "options": []any{map[string]any{"name": "command", "type": 3, "value": command}}}})
						body = string(b)
					case "telegram":
						chat, _ := strconv.ParseInt(room, 10, 64)
						uid, _ := strconv.ParseInt(user, 10, 64)
						b, _ := json.Marshal(map[string]any{"update_id": 1, "message": map[string]any{"date": now, "chat": map[string]any{"id": chat}, "from": map[string]any{"id": uid, "is_bot": kind == "bot"}, "text": "/sre " + command}})
						body = string(b)
					}
					if kind == "malformed" {
						body = "%{"
					}
					if kind == "oversized" {
						body = strings.Repeat("x", 65537)
					}
					r := httptest.NewRequest("POST", "/channels/ops/events", strings.NewReader(body))
					switch provider {
					case "slack":
						r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						r.Header.Set("X-Slack-Request-Timestamp", ts)
						mac := hmac.New(sha256.New, []byte("test_secret_1234567890"))
						mac.Write([]byte("v0:" + ts + ":" + body))
						r.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
					case "discord":
						r.Header.Set("X-Signature-Timestamp", ts)
						r.Header.Set("X-Signature-Ed25519", hex.EncodeToString(ed25519.Sign(priv, []byte(ts+body))))
					case "telegram":
						r.Header.Set("X-Telegram-Bot-Api-Secret-Token", "test_secret_1234567890")
					}
					if kind == "signature" {
						r.Header = make(http.Header)
					}
					if kind == "method" {
						r.Method = "GET"
					}
					if kind == "path" {
						r.URL.Path = "/channels/missing/events"
					}
					if kind == "parent-deadline" {
						ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
						defer cancel()
						r = r.WithContext(ctx)
					}
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					wantRetry := kind == "retryable" || kind == "deadline" || kind == "canceled"
					wantCall := kind == "valid" || kind == "execute" || kind == "parent-deadline" || wantRetry
					if wantRetry && w.Code != 503 {
						t.Fatalf("transient error acknowledged: %d %s", w.Code, w.Body.String())
					}
					if kind == "execute" && w.Code != 200 {
						t.Fatalf("permanent error retried: %d", w.Code)
					}
					if (called == 1) != wantCall {
						t.Fatalf("calls=%d status=%d body=%s", called, w.Code, w.Body.String())
					}
					if kind == "valid" && w.Code != 200 {
						t.Fatal(w.Code)
					}
					if strings.Contains(w.Body.String(), "private detail") {
						t.Fatal("error leaked")
					}
					if kind == "valid" && provider == "discord" && !strings.Contains(w.Body.String(), `"flags":64`) {
						t.Fatal("not ephemeral")
					}
					if kind == "ping" && !strings.Contains(w.Body.String(), `"type":1`) {
						t.Fatal("missing pong")
					}
				})
			}
		})
	}
}
func TestConfigValidation(t *testing.T) {
	t.Setenv("IM_TEST_SECRET", "secret")
	for _, kind := range []string{"valid", "provider", "id", "scope", "account", "room", "users", "principal", "duplicate-user", "duplicate-channel", "secret", "key", "group", "duplicate-telegram-secret"} {
		t.Run(kind, func(t *testing.T) {
			c := config("slack")
			cs := []Config{c}
			switch kind {
			case "provider":
				cs[0].Provider = "matrix"
			case "id":
				cs[0].ID = "../ops"
			case "scope":
				cs[0].Scope = identity.Scope{}
			case "account":
				cs[0].AccountID = ""
			case "room":
				cs[0].ConversationID = ""
			case "users":
				cs[0].Users = nil
			case "principal":
				cs[0].Users[0].PrincipalID = ""
			case "duplicate-user":
				cs[0].Users = append(cs[0].Users, cs[0].Users[0])
			case "duplicate-channel":
				cs = append(cs, c)
			case "secret":
				cs[0].SecretEnv = "MISSING_IM_SECRET"
			case "key":
				cs[0].Provider = "discord"
			case "group":
				cs[0].Users[0].Groups = []string{"\n"}
			case "duplicate-telegram-secret":
				cs[0].Provider = "telegram"
				c.Provider = "telegram"
				c.ID = "other"
				cs = append(cs, c)
			}
			_, err := New(cs, func(context.Context, identity.Principal, identity.Scope, Command) error { return nil })
			if (err == nil) != (kind == "valid") {
				t.Fatalf("error %v", err)
			}
		})
	}
	if _, err := New(nil, nil); err == nil {
		t.Fatal("nil executor accepted")
	}
}

func TestTelegramSecretFormat(t *testing.T) {
	execute := func(context.Context, identity.Principal, identity.Scope, Command) error { return nil }
	for _, tc := range []struct {
		name, secret string
		valid        bool
	}{{"single", "a", true}, {"allowed", "aAZ09_-", true}, {"maximum", strings.Repeat("s", 256), true}, {"empty", "", false}, {"too-long", strings.Repeat("s", 257), false}, {"space", "a b", false}, {"newline", "ab\n", false}, {"punctuation", "abc!", false}, {"unicode", "café", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("IM_TEST_SECRET", tc.secret)
			_, err := New([]Config{config("telegram")}, execute)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
func TestConfigurationListLimits(t *testing.T) {
	t.Setenv("IM_TEST_SECRET", "secret")
	execute := func(context.Context, identity.Principal, identity.Scope, Command) error { return nil }
	for _, count := range []int{128, 129} {
		configs := make([]Config, count)
		for i := range configs {
			configs[i] = config("slack")
			configs[i].ID = "ops" + strconv.Itoa(i)
		}
		_, err := New(configs, execute)
		if (err == nil) != (count == 128) {
			t.Fatalf("endpoints=%d error=%v", count, err)
		}
	}
	for _, count := range []int{1024, 1025} {
		c := config("slack")
		c.Users = make([]User, count)
		for i := range c.Users {
			c.Users[i] = User{ExternalID: strconv.Itoa(i), PrincipalID: "engineer"}
		}
		_, err := New([]Config{c}, execute)
		if (err == nil) != (count == 1024) {
			t.Fatalf("users=%d error=%v", count, err)
		}
	}
}
