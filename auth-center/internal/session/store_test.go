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

func TestRefreshConsumeKeepsTTLAndRevokeChain(t *testing.T) {
	ctx := context.Background()
	store, mr := newStore(t)
	gs := GlobalSession{SID: "bj1.abc", Sub: "E1", IDP: "corp", CreatedAt: 10, LastActive: 10, AbsExp: 500}
	if err := store.PutGlobal(ctx, gs); err != nil {
		t.Fatal(err)
	}
	as := AppSession{ASID: "as.1", SID: gs.SID, ClientID: "meeting", ClientType: "web", CreatedAt: 10, LastActive: 10}
	if err := store.PutApp(ctx, as); err != nil {
		t.Fatal(err)
	}
	if err := store.PutUserSession(ctx, gs.Sub, as.ASID, 10); err != nil {
		t.Fatal(err)
	}
	if err := store.PutLoginMeta(ctx, gs.SID, LoginMeta{AuthTime: 10, AMR: []string{"pwd"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAuthMeta(ctx, as.ASID, AuthMeta{AuthTime: 10, AMR: []string{"pwd"}, Scope: "openid"}); err != nil {
		t.Fatal(err)
	}
	ttl := 50 * time.Second
	rt := Refresh{Hash: "h1", ASID: as.ASID, FamilyID: "fam"}
	if err := store.PutRefresh(ctx, rt, ttl); err != nil {
		t.Fatal(err)
	}
	if err := store.PutRefresh(ctx, Refresh{Hash: "h2", ASID: as.ASID, FamilyID: "fam"}, ttl); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(5 * time.Second)
	got, consumed, err := store.ConsumeRefresh(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if got != ConsumeOK || consumed.ASID != as.ASID || consumed.FamilyID != "fam" {
		t.Fatalf("consume %d %+v", got, consumed)
	}
	if mr.TTL(RefreshKey("h1")) != 45*time.Second {
		t.Fatalf("ttl extended: %s", mr.TTL(RefreshKey("h1")))
	}
	again, _, err := store.ConsumeRefresh(ctx, "h1")
	if err != nil || again != ConsumeReused {
		t.Fatalf("reuse %d %v", again, err)
	}
	missing, _, err := store.ConsumeRefresh(ctx, "missing")
	if err != nil || missing != ConsumeMissing {
		t.Fatalf("missing %d %v", missing, err)
	}
	if err := store.Touch(ctx, gs.SID, as.ASID, 99); err != nil {
		t.Fatal(err)
	}
	touched, err := store.GetApp(ctx, as.ASID)
	if err != nil || touched.LastActive != 99 {
		t.Fatalf("touch %+v %v", touched, err)
	}
	txn := AuthTxn{ID: "tx1", ClientID: "meeting", RedirectURI: "https://app.example/cb", State: "state-state-state", CodeChallenge: "c", Scope: "openid", IDPID: "corp"}
	if err := store.PutTxn(ctx, txn, time.Minute); err != nil {
		t.Fatal(err)
	}
	taken, err := store.TakeTxn(ctx, "tx1")
	if err != nil || taken.State != txn.State || taken.IDPID != "corp" {
		t.Fatalf("%+v %v", taken, err)
	}
	if _, err := store.TakeTxn(ctx, "tx1"); err != ErrNotFound {
		t.Fatalf("txn replay %v", err)
	}
	if err := store.RevokeChain(ctx, gs.SID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetGlobal(ctx, gs.SID); err != ErrNotFound {
		t.Fatal(err)
	}
	if _, err := store.GetRefresh(ctx, "h2"); err != ErrNotFound {
		t.Fatal("family refresh survived")
	}
	if mr.Exists(AuthMetaKey(as.ASID)) || mr.Exists(LoginMetaKey(gs.SID)) || mr.Exists(AppKey(as.ASID)) {
		t.Fatal("session keys survived revoke")
	}
	revoked, err := store.IsSIDRevoked(ctx, gs.SID)
	if err != nil || !revoked {
		t.Fatal(revoked, err)
	}
}

func TestRevokeAppLeavesGlobalSession(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	gs := GlobalSession{SID: "bj1.keep", Sub: "E1", IDP: "corp", CreatedAt: 1, LastActive: 1, AbsExp: 100}
	if err := store.PutGlobal(ctx, gs); err != nil {
		t.Fatal(err)
	}
	keep := AppSession{ASID: "as.keep", SID: gs.SID, ClientID: "web", ClientType: "web", CreatedAt: 1, LastActive: 1}
	drop := AppSession{ASID: "as.drop", SID: gs.SID, ClientID: "app", ClientType: "app", CreatedAt: 1, LastActive: 1}
	if err := store.PutApp(ctx, keep); err != nil {
		t.Fatal(err)
	}
	if err := store.PutApp(ctx, drop); err != nil {
		t.Fatal(err)
	}
	if err := store.PutUserSession(ctx, gs.Sub, drop.ASID, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.PutRefresh(ctx, Refresh{Hash: "rh", ASID: drop.ASID, FamilyID: "rf.1"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := store.RevokeApp(ctx, drop.ASID)
	if err != nil || got.ASID != drop.ASID {
		t.Fatal(err, got.ASID)
	}
	if _, err := store.GetGlobal(ctx, gs.SID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetApp(ctx, keep.ASID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetApp(ctx, drop.ASID); err != ErrNotFound {
		t.Fatal(err)
	}
	ids, err := store.ListAppIDs(ctx, gs.SID)
	if err != nil || len(ids) != 1 || ids[0] != keep.ASID {
		t.Fatalf("%v %v", ids, err)
	}
	if _, err := store.GetRefresh(ctx, "rh"); err != ErrNotFound {
		t.Fatal(err)
	}
	revoked, err := store.IsSIDRevoked(ctx, gs.SID)
	if err != nil || revoked {
		t.Fatal(revoked, err)
	}
}
