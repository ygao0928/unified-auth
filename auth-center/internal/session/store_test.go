package session

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb), mr
}

func TestGlobalAppAndRefreshRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, mr := newStore(t)
	gs := GlobalSession{
		SID: "bj1.8f2c4a9e", Sub: "E10023", IDP: "corp-oidc",
		CreatedAt: 100, LastActive: 110, AbsExp: 500, IP: "10.1.2.3", UA: "test",
	}
	if err := store.PutGlobal(ctx, gs); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetGlobal(ctx, gs.SID)
	if err != nil {
		t.Fatal(err)
	}
	if got != gs {
		t.Fatalf("global: %+v", got)
	}

	as := AppSession{ASID: "as.31d07c", SID: gs.SID, ClientID: "meeting", ClientType: "web", CreatedAt: 100, LastActive: 110}
	if err := store.PutApp(ctx, as); err != nil {
		t.Fatal(err)
	}
	gotAS, err := store.GetApp(ctx, as.ASID)
	if err != nil {
		t.Fatal(err)
	}
	if gotAS != as {
		t.Fatalf("app: %+v", gotAS)
	}
	ids, err := store.ListAppIDs(ctx, gs.SID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != as.ASID {
		t.Fatalf("apps: %v", ids)
	}
	if err := store.PutUserSession(ctx, gs.Sub, as.ASID, as.CreatedAt); err != nil {
		t.Fatal(err)
	}
	refs, err := store.UserSessions(ctx, gs.Sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].ASID != as.ASID || refs[0].CreatedAt != 100 {
		t.Fatalf("user sessions: %+v", refs)
	}
	if mr.Exists(UserSessionsKey(gs.Sub)) == false {
		t.Fatal("missing user session key")
	}

	// TTL 由调用方传入，等于该客户端的 refresh_token_ttl，而不是写死 600。
	ttl := 42 * time.Second
	rt := Refresh{Hash: "abc", ASID: as.ASID, FamilyID: "fam-1", Used: true}
	if err := store.PutRefresh(ctx, rt, ttl); err != nil {
		t.Fatal(err)
	}
	gotRT, err := store.GetRefresh(ctx, rt.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if gotRT != rt {
		t.Fatalf("refresh: %+v", gotRT)
	}
	if mr.TTL(RefreshKey(rt.Hash)) != ttl {
		t.Fatalf("ttl %s", mr.TTL(RefreshKey(rt.Hash)))
	}

	if err := store.RememberRevokedSID(ctx, gs.SID, 1860*time.Second); err != nil {
		t.Fatal(err)
	}
	revoked, err := store.IsSIDRevoked(ctx, gs.SID)
	if err != nil || !revoked {
		t.Fatalf("revoked %v %v", revoked, err)
	}
	if mr.TTL(RevokedSIDKey()) != 1860*time.Second {
		t.Fatalf("revoked ttl %s", mr.TTL(RevokedSIDKey()))
	}

	if _, err := store.GetGlobal(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("missing global: %v", err)
	}
}

func TestRejectsEmptyIDsAndNonPositiveTTL(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	if err := store.PutGlobal(ctx, GlobalSession{}); err == nil {
		t.Fatal("empty global")
	}
	if err := store.PutRefresh(ctx, Refresh{Hash: "h", ASID: "a", FamilyID: "f"}, 0); err == nil {
		t.Fatal("zero ttl")
	}
}
