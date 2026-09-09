package incident

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"strings"
	"testing"
	"time"
)

func validItem() Item {
	return Item{Scope: identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}, IncidentID: "incident", ID: "evidence", Version: 1, Kind: Evidence, Body: json.RawMessage(`{"code":"POD_FAILED","count":9007199254740993}`), ObservedAt: time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)}
}
func TestItemSealCanonicalAndPrecise(t *testing.T) {
	a, b := validItem(), validItem()
	b.Body = json.RawMessage(`{"count":9007199254740993,"code":"POD_FAILED"}`)
	if err := a.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash || !strings.Contains(string(a.Body), "9007199254740993") {
		t.Fatal("canonicalization changed evidence or hash")
	}
	b.Body = json.RawMessage(`{"count":9007199254740992,"code":"POD_FAILED"}`)
	b.Seal()
	if a.Hash == b.Hash {
		t.Fatal("distinct integer observations collide")
	}
}
func TestItemSealRejectsUnsafeEnvelope(t *testing.T) {
	cases := []func(*Item){func(i *Item) { i.Scope.ApplicationID = "" }, func(i *Item) { i.ID = "../x" }, func(i *Item) { i.Body = json.RawMessage(`[]`) }, func(i *Item) { i.Body = json.RawMessage(`{"a":1,"a":2}`) }, func(i *Item) { i.Body = json.RawMessage(`{"code":"` + strings.Repeat("x", 65536) + `"}`) }, func(i *Item) { i.ObservedAt = time.Time{} }, func(i *Item) { i.ValidUntil = i.ObservedAt }, func(i *Item) { i.Version = 0 }, func(i *Item) { i.Kind = "UNKNOWN" }, func(i *Item) { i.Parents = []ItemRef{{ID: "p", Version: 1}, {ID: "p", Version: 1}} }, func(i *Item) { i.Parents = []ItemRef{{ID: i.ID, Version: i.Version}} }}
	for n, mutate := range cases {
		item := validItem()
		mutate(&item)
		if item.Seal() == nil {
			t.Errorf("case %d accepted", n)
		}
	}
}

func TestCanonicalOutputLimitAndHashEnvelope(t *testing.T) {
	item := validItem()
	item.Body = json.RawMessage(`{"x":"` + strings.Repeat("<", 11000) + `"}`)
	if item.Seal() == nil {
		t.Fatal("canonical output exceeds storage bound")
	}
	item = validItem()
	if err := item.Seal(); err != nil {
		t.Fatal(err)
	}
	first := item.Hash
	if err := item.Seal(); err != nil || first != item.Hash {
		t.Fatal("sealing is not idempotent")
	}
	item.Hash = ""
	encoded, _ := json.Marshal(item)
	if strings.Contains(string(encoded), `"hash"`) {
		t.Fatal("empty Hash must be excluded from hash envelope")
	}
}
