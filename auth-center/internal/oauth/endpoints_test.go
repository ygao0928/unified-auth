package oauth

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/eventbus/redisstream"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func TestLogoutUserinfoRevokeAndIntrospect(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	bus := redisstream.New(rdb)

	var logoutTokens atomic.Int32
	var lastLogout atomic.Value
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("backchannel form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lastLogout.Store(r.PostFormValue("logout_token"))
		logoutTokens.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(back.Close)

	pemBytes, _, err := keys.GenerateRSA("endpoint-key", 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/active.pem"
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := keys.LoadFiles([]keys.Input{{Alg: keys.AlgRS256, PEMFile: path, Role: keys.RoleActive}})
	if err != nil {
		t.Fatal(err)
	}
	defaults := config.BuiltinLifetimeDefaults()
	store := pgstore.New(pool, config.DefaultAccessTokenTTLCap, defaults)
	sessions := session.New(rdb)
	var now atomic.Int64
	now.Store(1_700_000_000)
	handler, err := New(Deps{
		Issuer: "http://auth.example", DC: "local", Cap: 1800, ClockSkew: 60, Defaults: defaults,
		Keys: mgr, Store: store, Sessions: sessions, Bus: bus,
		Now:    func() time.Time { return time.Unix(now.Load(), 0).UTC() },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	handler.Mount(router)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	name := "王五"
	emp := "E" + randomSuffix(t)
	if err := store.UpsertUserFromLogin(ctx, pgstore.User{EmpNo: emp, Name: &name}); err != nil {
		t.Fatal(err)
	}
	hash, err := pgstore.HashClientSecret("conf-secret", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	sfx := randomSuffix(t)
	redirect := "https://app.example/cb"
	web := pgstore.Client{
		ClientID: "web-" + sfx, Name: "web", ClientType: config.ClientWeb, SecretHash: hash,
		RedirectURIs: []string{redirect}, Enabled: true, BackchannelLogoutURI: back.URL + "/logout",
	}
	appClient := pgstore.Client{
		ClientID: "app-" + sfx, Name: "app", ClientType: config.ClientApp, SecretHash: hash,
		RedirectURIs: []string{redirect}, Enabled: true, BackchannelLogoutURI: back.URL + "/logout",
	}
	spa := pgstore.Client{
		ClientID: "spa-" + sfx, Name: "spa", ClientType: config.ClientWeb,
		RedirectURIs: []string{redirect}, Enabled: true,
	}
	for _, c := range []pgstore.Client{web, appClient, spa} {
		if err := store.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	sid := "local." + randomSuffix(t)
	if err := sessions.PutGlobal(ctx, session.GlobalSession{
		SID: sid, Sub: emp, IDP: "corp", CreatedAt: now.Load(), LastActive: now.Load(), AbsExp: now.Load() + 40000,
	}); err != nil {
		t.Fatal(err)
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	postAuth := func(path, clientID, secret string, form url.Values) (int, map[string]any) {
		t.Helper()
		if clientID != "" && secret == "" {
			form.Set("client_id", clientID)
		}
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if secret != "" {
			req.SetBasicAuth(clientID, secret)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("status %d body %q", res.StatusCode, raw)
			}
		}
		return res.StatusCode, body
	}

	issue := func(client pgstore.Client) (string, string, string) {
		t.Helper()
		asid := "as." + randomSuffix(t)
		as := session.AppSession{
			ASID: asid, SID: sid, ClientID: client.ClientID, ClientType: client.ClientType,
			CreatedAt: now.Load(), LastActive: now.Load(),
		}
		if err := sessions.PutApp(ctx, as); err != nil {
			t.Fatal(err)
		}
		if err := sessions.PutAuthMeta(ctx, asid, session.AuthMeta{Scope: "openid", AuthTime: now.Load()}); err != nil {
			t.Fatal(err)
		}
		resp, err := handler.issueTokens(ctx, client, session.GlobalSession{
			SID: sid, Sub: emp, AbsExp: now.Load() + 40000,
		}, as, "nonce-nonce-nonce", true, "")
		if err != nil {
			t.Fatal(err)
		}
		return resp.AccessToken, resp.RefreshToken, resp.IDToken
	}
	userinfo := func(token string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/userinfo", nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, body
	}

	webAccess, webRefresh, webID := issue(web)
	appAccess, _, _ := issue(appClient)
	_, spaRefresh, _ := issue(spa)

	status, body := userinfo("")
	if status != http.StatusUnauthorized || body["code"] != "AUTH_TOKEN_MISSING" {
		t.Fatalf("missing token %d %#v", status, body)
	}
	status, body = userinfo(webAccess)
	if status != http.StatusOK || body["sub"] != emp || body["name"] != name {
		t.Fatalf("userinfo %d %#v", status, body)
	}
	if _, ok := body["dept_id"]; ok || body["email"] != nil {
		t.Fatalf("empty claims returned %#v", body)
	}

	status, body = postAuth("/oauth2/introspect", web.ClientID, "conf-secret", url.Values{"token": {webAccess}})
	if status != http.StatusOK || body["active"] != true || body["sub"] != emp || body["aud"] != web.ClientID || body["perm_ver"] != float64(0) {
		t.Fatalf("introspect %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/introspect", appClient.ClientID, "conf-secret", url.Values{"token": {webAccess}})
	if status != http.StatusOK || body["active"] != false || body["sub"] != nil {
		t.Fatalf("cross introspect %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/introspect", spa.ClientID, "", url.Values{"token": {webAccess}})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" || body["code"] != "INVALID_CLIENT" {
		t.Fatalf("public introspect %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/introspect", web.ClientID, "conf-secret", url.Values{})
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("introspect missing token %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/introspect", web.ClientID, "conf-secret", url.Values{"token": {webRefresh}})
	if status != http.StatusOK || body["active"] != true || body["token_type"] != "refresh_token" || body["sub"] != emp {
		t.Fatalf("introspect refresh %d %#v", status, body)
	}

	status, body = postAuth("/oauth2/revoke", spa.ClientID, "", url.Values{"token": {webRefresh}, "token_type_hint": {"refresh_token"}})
	if status != http.StatusOK {
		t.Fatalf("cross revoke %d %#v", status, body)
	}
	status, body = userinfo(webAccess)
	if status != http.StatusOK {
		t.Fatalf("cross revoke killed the token %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/revoke", web.ClientID, "conf-secret", url.Values{"token": {"not-a-token"}})
	if status != http.StatusOK {
		t.Fatalf("unknown revoke %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/revoke", web.ClientID, "conf-secret", url.Values{"token": {webRefresh}, "token_type_hint": {"nope"}})
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("bad hint %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/revoke", web.ClientID, "", url.Values{"token": {webRefresh}})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" || body["code"] != "INVALID_CLIENT" {
		t.Fatalf("confidential revoke without secret %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/revoke", web.ClientID, "conf-secret", url.Values{"token": {webRefresh}, "token_type_hint": {"refresh_token"}})
	if status != http.StatusOK {
		t.Fatalf("revoke refresh %d %#v", status, body)
	}
	status, body = userinfo(webAccess)
	if status != http.StatusUnauthorized || body["code"] != "AUTH_SESSION_REVOKED" {
		t.Fatalf("revoked userinfo %d %#v", status, body)
	}
	status, body = userinfo(appAccess)
	if status != http.StatusOK {
		t.Fatalf("other app userinfo %d %#v", status, body)
	}
	if _, err := sessions.GetGlobal(ctx, sid); err != nil {
		t.Fatal(err)
	}
	events := readRevoked(t, ctx, bus)
	if !hasEvent(events, "app_session", "logout", web.ClientID) {
		t.Fatalf("missing app revoke event %#v", events)
	}

	status, body = postAuth("/oauth2/revoke", spa.ClientID, "", url.Values{"token": {spaRefresh}})
	if status != http.StatusOK {
		t.Fatalf("public revoke %d %#v", status, body)
	}

	logoutBefore := logoutTokens.Load()
	bad, err := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/logout?"+url.Values{
		"client_id": {web.ClientID}, "post_logout_redirect_uri": {"https://evil.example/out"},
	}.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	bad.AddCookie(&http.Cookie{Name: "auth_sid", Value: sid})
	badRes, err := noRedirect.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	badRes.Body.Close()
	if badRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad redirect %d", badRes.StatusCode)
	}
	if _, err := sessions.GetGlobal(ctx, sid); err != nil {
		t.Fatal("bad redirect revoked the session", err)
	}

	loc := srv.URL + "/oauth2/logout?" + url.Values{
		"id_token_hint": {webID}, "client_id": {web.ClientID},
		"post_logout_redirect_uri": {redirect}, "state": {"logout-state-1"},
	}.Encode()
	req, err := http.NewRequest(http.MethodGet, loc, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("logout %d", res.StatusCode)
	}
	dest, err := url.Parse(res.Header.Get("Location"))
	if err != nil || dest.Query().Get("state") != "logout-state-1" || dest.Scheme+"://"+dest.Host+dest.Path != redirect {
		t.Fatalf("location %s", res.Header.Get("Location"))
	}
	if logoutTokens.Load() != logoutBefore+1 {
		t.Fatalf("backchannel calls %d", logoutTokens.Load())
	}
	hintTok, _ := lastLogout.Load().(string)
	hdr, claims, err := mgr.Verify(hintTok)
	typ, _ := hdr.ExtraHeaders["typ"].(string)
	if err != nil || typ != "logout+jwt" || claims["sid"] != sid || claims["aud"] != appClient.ClientID {
		t.Fatalf("logout token %v %#v %v", typ, claims, err)
	}
	eventsMap, _ := claims["events"].(map[string]any)
	if _, ok := eventsMap["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("events %#v", claims["events"])
	}
	if _, err := sessions.GetGlobal(ctx, sid); err != session.ErrNotFound {
		t.Fatal(err)
	}
	status, body = userinfo(appAccess)
	if status != http.StatusUnauthorized || body["code"] != "AUTH_SESSION_REVOKED" {
		t.Fatalf("after logout %d %#v", status, body)
	}
	events = readRevoked(t, ctx, bus)
	if !hasEvent(events, "session", "logout", "") {
		t.Fatalf("missing logout event %#v", events)
	}

	bareReq, err := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	bareReq.AddCookie(&http.Cookie{Name: "auth_sid", Value: sid})
	bareRes, err := noRedirect.Do(bareReq)
	if err != nil {
		t.Fatal(err)
	}
	bareRes.Body.Close()
	if bareRes.StatusCode != http.StatusNoContent {
		t.Fatalf("empty logout %d", bareRes.StatusCode)
	}
	cleared := false
	for _, c := range bareRes.Cookies() {
		if c.Name == "auth_sid" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("cookie was not cleared")
	}

	reuseSID := "local." + randomSuffix(t)
	if err := sessions.PutGlobal(ctx, session.GlobalSession{
		SID: reuseSID, Sub: emp, IDP: "corp", CreatedAt: now.Load(), LastActive: now.Load(), AbsExp: now.Load() + 40000,
	}); err != nil {
		t.Fatal(err)
	}
	asid := "as." + randomSuffix(t)
	if err := sessions.PutApp(ctx, session.AppSession{
		ASID: asid, SID: reuseSID, ClientID: web.ClientID, ClientType: web.ClientType,
		CreatedAt: now.Load(), LastActive: now.Load(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.PutAuthMeta(ctx, asid, session.AuthMeta{Scope: "openid"}); err != nil {
		t.Fatal(err)
	}
	minted, err := handler.issueTokens(ctx, web, session.GlobalSession{SID: reuseSID, Sub: emp, AbsExp: now.Load() + 40000}, session.AppSession{
		ASID: asid, SID: reuseSID, ClientID: web.ClientID, ClientType: web.ClientType, LastActive: now.Load(),
	}, "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	status, body = postAuth("/oauth2/token", web.ClientID, "conf-secret", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {minted.RefreshToken},
	})
	if status != http.StatusOK {
		t.Fatalf("rotate %d %#v", status, body)
	}
	status, body = postAuth("/oauth2/token", web.ClientID, "conf-secret", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {minted.RefreshToken},
	})
	if status != http.StatusUnauthorized || body["code"] != "AUTH_REFRESH_REUSED" {
		t.Fatalf("reuse %d %#v", status, body)
	}
	events = readRevoked(t, ctx, bus)
	if !hasEvent(events, "session", "refresh_reused", "") {
		t.Fatalf("missing reuse event %#v", events)
	}

	now.Store(now.Load() + 800)
	status, body = userinfo(appAccess)
	if status != http.StatusUnauthorized || body["code"] != "AUTH_TOKEN_EXPIRED" {
		t.Fatalf("expired %d %#v", status, body)
	}

	discRes, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer discRes.Body.Close()
	var disc map[string]any
	if err := json.NewDecoder(discRes.Body).Decode(&disc); err != nil {
		t.Fatal(err)
	}
	if disc["end_session_endpoint"] != "http://auth.example/oauth2/logout" || disc["backchannel_logout_supported"] != true {
		t.Fatalf("discovery %#v", disc)
	}
}

func readRevoked(t *testing.T, ctx context.Context, bus *redisstream.Bus) []map[string]any {
	t.Helper()
	delivered, err := bus.ReadAfter(ctx, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, item := range delivered {
		if item.Event.Name != "auth.revoked" {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(item.Event.Data, &body); err != nil {
			t.Fatal(err)
		}
		out = append(out, body)
	}
	return out
}

func hasEvent(events []map[string]any, typ, reason, clientID string) bool {
	for _, event := range events {
		if event["event"] != "auth.revoked" || event["type"] != typ || event["reason"] != reason {
			continue
		}
		if clientID != "" && event["client_id"] != clientID {
			continue
		}
		if event["id"] == "" || event["ts"] == nil {
			continue
		}
		return true
	}
	return false
}
