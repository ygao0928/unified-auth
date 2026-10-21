package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-jose/go-jose/v4"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp/oidc"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func TestOIDCAuthorizeTokenAndRefresh(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	op := newMockOP(t)
	op.emp = "E" + randomSuffix(t)
	op.name = "张三"
	op.email = "a@example.com"
	op.authTime = 1_690_000_000

	var now atomic.Int64
	now.Store(1_700_000_000)
	defaults := config.BuiltinLifetimeDefaults()
	defaults.UserAccessTokenTTL = 90

	pemBytes, _, err := keys.GenerateRSA("flow-key", 2048)
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
	store := pgstore.New(pool, 1800, defaults)
	sessions := session.New(rdb)

	authSrv := httptest.NewUnstartedServer(nil)
	issuer := "http://" + authSrv.Listener.Addr().String()
	adapter, err := oidc.New(oidc.Config{
		ID: "corp", Issuer: op.issuer, ClientID: op.clientID, ClientSecret: op.secret,
		RedirectURL: issuer + "/idp/corp/callback",
		Mapping:     oidc.Mapping{EmpNo: "employeeNumber", Name: "name", Email: "email"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	handler, err := New(Deps{
		Issuer: issuer, DC: "local", Cap: 1800, ClockSkew: 60, Defaults: defaults,
		AuthCodeTTL: time.Minute, TxnTTL: 10 * time.Minute,
		Keys: mgr, Store: store, Sessions: sessions,
		IDPs:   map[string]idp.IdentityProvider{"corp": adapter},
		Now:    func() time.Time { return time.Unix(now.Load(), 0).UTC() },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	authSrv.Config.Handler = httpserver.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mgr, nil, handler.Mount)
	authSrv.Start()
	t.Cleanup(authSrv.Close)

	capture := newCapture()
	clientSrv := httptest.NewServer(capture)
	t.Cleanup(clientSrv.Close)

	secret := "client-secret-value"
	hash, err := pgstore.HashClientSecret(secret, bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	sfx := randomSuffix(t)
	alias := map[string]string{}
	newClient := func(short, clientType string, policy config.SessionPolicy) {
		t.Helper()
		id := short + "-" + sfx
		alias[short] = id
		if err := store.CreateClient(ctx, pgstore.Client{
			ClientID: id, Name: id, ClientType: clientType, SecretHash: hash,
			RedirectURIs: []string{clientSrv.URL + "/cb/" + id}, SessionPolicy: policy, Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	newClient("web-default", config.ClientWeb, config.SessionPolicy{})
	access30 := 30
	newClient("web-30", config.ClientWeb, config.SessionPolicy{AccessTokenTTL: &access30})
	tooLong := 99999
	newClient("web-cap", config.ClientWeb, config.SessionPolicy{AccessTokenTTL: &tooLong})
	newClient("web-long-rt", config.ClientWeb, config.SessionPolicy{RefreshTokenTTL: &tooLong})
	idle, absolute, refreshTTL := 10, 100000, 600
	newClient("web-idle", config.ClientWeb, config.SessionPolicy{IdleTimeout: &idle, AbsoluteSessionTTL: &absolute, RefreshTokenTTL: &refreshTTL})
	abs, idleLong := 30, 100000
	newClient("web-abs", config.ClientWeb, config.SessionPolicy{AbsoluteSessionTTL: &abs, IdleTimeout: &idleLong, RefreshTokenTTL: &refreshTTL})
	shortRefresh := 5
	newClient("web-short-rt", config.ClientWeb, config.SessionPolicy{RefreshTokenTTL: &shortRefresh, IdleTimeout: &idleLong, AbsoluteSessionTTL: &absolute})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	login := func(short, prompt string) string {
		t.Helper()
		clientID := alias[short]
		state := "state-state-state"
		req, err := http.NewRequest(http.MethodGet, authorizeURL(issuer, clientID, clientSrv.URL+"/cb/"+clientID, state, verifier, prompt), nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("login %s ended at %d", clientID, res.StatusCode)
		}
		got := capture.take("/cb/" + clientID)
		if got.Query().Get("state") != state {
			t.Fatalf("state %s", got.RawQuery)
		}
		if errCode := got.Query().Get("error"); errCode != "" {
			t.Fatalf("authorize error %s", got.RawQuery)
		}
		return got.Query().Get("code")
	}
	postToken := func(short string, form url.Values, basic bool) (int, map[string]any) {
		t.Helper()
		clientID := alias[short]
		if form.Get("redirect_uri") != "" {
			form.Set("redirect_uri", clientSrv.URL+"/cb/"+clientID)
		}
		req, err := http.NewRequest(http.MethodPost, issuer+"/oauth2/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			req.SetBasicAuth(clientID, secret)
		} else {
			form.Set("client_id", clientID)
			form.Set("client_secret", secret)
			req, err = http.NewRequest(http.MethodPost, issuer+"/oauth2/token", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		if res.StatusCode == http.StatusOK && res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal(res.Header.Get("Cache-Control"))
		}
		return res.StatusCode, body
	}

	code := login("web-default", "")
	if op.hits.Load() != 1 {
		t.Fatalf("upstream hits %d", op.hits.Load())
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET perm_ver = 7 WHERE emp_no = $1`, op.emp); err != nil {
		t.Fatal(err)
	}
	status, body := postToken("web-default", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {clientSrv.URL + "/cb/web-default"}, "code_verifier": {verifier},
	}, true)
	if status != http.StatusOK {
		t.Fatalf("token %d %#v", status, body)
	}
	access, _ := body["access_token"].(string)
	refresh, _ := body["refresh_token"].(string)
	idToken, _ := body["id_token"].(string)
	if access == "" || refresh == "" || idToken == "" || body["token_type"] != "Bearer" || body["expires_in"] != float64(90) {
		t.Fatalf("token body %#v", body)
	}
	jwks, err := mgr.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	user := verifyReference(t, issuer, alias["web-default"], 60, jwks, access, now.Load())
	if user["emp_no"] != op.emp || user["client_id"] != alias["web-default"] || user["perm_ver"] != float64(7) || user["name"] != "张三" {
		t.Fatalf("user %#v", user)
	}
	if user["auth_time"] != float64(op.authTime) || user["sid"] == "" || user["asid"] == "" {
		t.Fatalf("session claims %#v", user)
	}
	if code := referenceCode(t, issuer, alias["web-default"], 60, jwks, idToken, now.Load()); code != "AUTH_TOKEN_INVALID" {
		t.Fatalf("id token accepted as access token: %s", code)
	}
	gs, err := sessions.GetGlobal(ctx, user["sid"].(string))
	if err != nil || gs.Sub != op.emp || gs.IDP != "corp" || gs.AbsExp != now.Load()+int64(config.DefaultWebAbsoluteSessionTTL) {
		t.Fatalf("global %+v %v", gs, err)
	}
	authURL, _ := url.Parse(issuer)
	var sawCookie bool
	for _, c := range jar.Cookies(authURL) {
		if c.Name == cookieName && c.Value == gs.SID {
			sawCookie = true
		}
	}
	if !sawCookie {
		t.Fatal("auth_sid cookie missing")
	}
	stored, err := store.GetUser(ctx, op.emp)
	if err != nil || stored.Name == nil || *stored.Name != "张三" || stored.PermVer != 7 {
		t.Fatalf("user row %+v %v", stored, err)
	}

	before := op.hits.Load()
	silent := login("web-default", "")
	if op.hits.Load() != before {
		t.Fatal("silent authorize contacted upstream")
	}
	status, body = postToken("web-default", url.Values{
		"grant_type": {"authorization_code"}, "code": {silent},
		"redirect_uri": {clientSrv.URL + "/cb/web-default"}, "code_verifier": {"wrong-verifier-wrong-verifier-wrong-verifi"},
	}, true)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("bad pkce %d %#v", status, body)
	}
	status, body = postToken("web-default", url.Values{
		"grant_type": {"authorization_code"}, "code": {silent},
		"redirect_uri": {clientSrv.URL + "/cb/web-default"}, "code_verifier": {verifier},
	}, true)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("replayed code %d %#v", status, body)
	}

	op.setProfile("", "b@example.com")
	login("web-default", "login")
	if op.hits.Load() != before+1 {
		t.Fatalf("prompt=login hits %d", op.hits.Load())
	}
	stored, err = store.GetUser(ctx, op.emp)
	if err != nil || stored.Name == nil || *stored.Name != "张三" || stored.Email == nil || *stored.Email != "b@example.com" {
		t.Fatalf("empty attribute overwrote user %+v", stored)
	}

	oldHash := tokenHash(refresh)
	now.Add(5)
	mr.FastForward(5 * time.Second)
	status, body = postToken("web-default", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, true)
	if status != http.StatusOK {
		t.Fatalf("refresh %d %#v", status, body)
	}
	if mr.TTL(session.RefreshKey(oldHash)) != 595*time.Second {
		t.Fatalf("old refresh ttl %s", mr.TTL(session.RefreshKey(oldHash)))
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == refresh || body["id_token"] != nil || body["expires_in"] != float64(90) {
		t.Fatalf("rotated %#v", body)
	}
	if mr.TTL(session.RefreshKey(tokenHash(rotated))) != 600*time.Second {
		t.Fatalf("new refresh ttl %s", mr.TTL(session.RefreshKey(tokenHash(rotated))))
	}
	rotatedAccess, _ := body["access_token"].(string)
	verifyReference(t, issuer, alias["web-default"], 60, jwks, rotatedAccess, now.Load())
	used, err := sessions.GetRefresh(ctx, oldHash)
	if err != nil || !used.Used {
		t.Fatalf("old refresh %+v %v", used, err)
	}

	status, body = postToken("web-default", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, true)
	if status != http.StatusUnauthorized || body["code"] != "AUTH_REFRESH_REUSED" || body["error"] != "invalid_grant" {
		t.Fatalf("reuse %d %#v", status, body)
	}
	if _, err := sessions.GetGlobal(ctx, gs.SID); err != session.ErrNotFound {
		t.Fatal("global session survived reuse")
	}
	revoked, err := sessions.IsSIDRevoked(ctx, gs.SID)
	if err != nil || !revoked {
		t.Fatal(revoked, err)
	}
	status, body = postToken("web-default", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rotated}}, true)
	if status != http.StatusUnauthorized || body["code"] != "AUTH_LOGIN_REQUIRED" {
		t.Fatalf("rotated token after revoke %d %#v", status, body)
	}

	assertExpires := func(clientID string, want int, basic bool) {
		t.Helper()
		code := login(clientID, "login")
		status, body := postToken(clientID, url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {clientSrv.URL + "/cb/" + clientID}, "code_verifier": {verifier},
		}, basic)
		if status != http.StatusOK || body["expires_in"] != float64(want) {
			t.Fatalf("%s expires %d %#v", clientID, status, body)
		}
	}
	assertExpires("web-30", 30, true)
	assertExpires("web-cap", 1800, false)

	longCode := login("web-long-rt", "login")
	status, body = postToken("web-long-rt", url.Values{
		"grant_type": {"authorization_code"}, "code": {longCode},
		"redirect_uri": {clientSrv.URL + "/cb/web-long-rt"}, "code_verifier": {verifier},
	}, true)
	if status != http.StatusOK {
		t.Fatalf("long refresh %d %#v", status, body)
	}
	longRaw, _ := body["refresh_token"].(string)
	if mr.TTL(session.RefreshKey(tokenHash(longRaw))) != 99999*time.Second {
		t.Fatalf("refresh cap applied: %s", mr.TTL(session.RefreshKey(tokenHash(longRaw))))
	}

	idleCode := login("web-idle", "login")
	status, body = postToken("web-idle", url.Values{
		"grant_type": {"authorization_code"}, "code": {idleCode},
		"redirect_uri": {clientSrv.URL + "/cb/web-idle"}, "code_verifier": {verifier},
	}, true)
	if status != http.StatusOK {
		t.Fatal(body)
	}
	idleRefresh, _ := body["refresh_token"].(string)
	idleHash := tokenHash(idleRefresh)
	now.Add(10)
	mr.FastForward(10 * time.Second)
	status, body = postToken("web-idle", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {idleRefresh}}, true)
	if status != http.StatusUnauthorized || body["code"] != "AUTH_LOGIN_REQUIRED" {
		t.Fatalf("idle %d %#v", status, body)
	}
	if _, err := sessions.GetRefresh(ctx, idleHash); err != nil {
		t.Fatal("idle check consumed the refresh token")
	}

	absCode := login("web-abs", "login")
	status, body = postToken("web-abs", url.Values{
		"grant_type": {"authorization_code"}, "code": {absCode},
		"redirect_uri": {clientSrv.URL + "/cb/web-abs"}, "code_verifier": {verifier},
	}, true)
	if status != http.StatusOK {
		t.Fatal(body)
	}
	absRefresh, _ := body["refresh_token"].(string)
	now.Add(30)
	mr.FastForward(30 * time.Second)
	status, body = postToken("web-abs", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {absRefresh}}, true)
	if status != http.StatusUnauthorized || body["code"] != "AUTH_LOGIN_REQUIRED" {
		t.Fatalf("absolute %d %#v", status, body)
	}
	if _, err := sessions.GetRefresh(ctx, tokenHash(absRefresh)); err != nil {
		t.Fatal("absolute check consumed the refresh token")
	}

	shortCode := login("web-short-rt", "login")
	status, body = postToken("web-short-rt", url.Values{
		"grant_type": {"authorization_code"}, "code": {shortCode},
		"redirect_uri": {clientSrv.URL + "/cb/web-short-rt"}, "code_verifier": {verifier},
	}, true)
	if status != http.StatusOK {
		t.Fatal(body)
	}
	shortRaw, _ := body["refresh_token"].(string)
	now.Add(6)
	mr.FastForward(6 * time.Second)
	status, body = postToken("web-short-rt", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {shortRaw}}, true)
	if status != http.StatusUnauthorized || body["code"] != "AUTH_LOGIN_REQUIRED" {
		t.Fatalf("refresh ttl %d %#v", status, body)
	}

	status, body = postToken("web-default", url.Values{"grant_type": {"client_credentials"}}, true)
	if status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Fatalf("client credentials %d %#v", status, body)
	}
	badReq, err := http.NewRequest(http.MethodPost, issuer+"/oauth2/token", strings.NewReader("grant_type=refresh_token"))
	if err != nil {
		t.Fatal(err)
	}
	badReq.SetBasicAuth("web-default", "nope")
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRes, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	defer badRes.Body.Close()
	if badRes.StatusCode != http.StatusUnauthorized || badRes.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("bad client %d", badRes.StatusCode)
	}

	discRes, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer discRes.Body.Close()
	var disc map[string]any
	if err := json.NewDecoder(discRes.Body).Decode(&disc); err != nil {
		t.Fatal(err)
	}
	if disc["issuer"] != issuer || disc["jwks_uri"] != issuer+"/oauth2/jwks" {
		t.Fatalf("discovery %#v", disc)
	}
	if disc["userinfo_endpoint"] != issuer+"/oauth2/userinfo" || disc["revocation_endpoint"] != issuer+"/oauth2/revoke" || disc["introspection_endpoint"] != issuer+"/oauth2/introspect" || disc["end_session_endpoint"] != issuer+"/oauth2/logout" || disc["backchannel_logout_supported"] != true {
		t.Fatalf("discovery endpoints %#v", disc)
	}
	methods, _ := disc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("pkce %#v", disc["code_challenge_methods_supported"])
	}
	jwksRes, err := http.Get(issuer + "/oauth2/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer jwksRes.Body.Close()
	if jwksRes.Header.Get("Cache-Control") != "max-age=600" {
		t.Fatal(jwksRes.Header.Get("Cache-Control"))
	}
}

func TestAuthorizeRequiresHintWhenSeveralIDPs(t *testing.T) {
	pool := pgtest.Pool(t)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	pemBytes, _, err := keys.GenerateRSA("hint-key", 2048)
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
	store := pgstore.New(pool, 1800, config.BuiltinLifetimeDefaults())
	var landed atomic.Value
	clientSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landed.Store(r.URL.String())
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(clientSrv.Close)
	redirect := clientSrv.URL + "/cb"
	hash, err := pgstore.HashClientSecret("secret", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	id := "hint-" + randomSuffix(t)
	if err := store.CreateClient(context.Background(), pgstore.Client{
		ClientID: id, Name: id, ClientType: config.ClientWeb, SecretHash: hash,
		RedirectURIs: []string{redirect}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	authSrv := httptest.NewUnstartedServer(nil)
	handler, err := New(Deps{
		Issuer: "http://" + authSrv.Listener.Addr().String(), DC: "local", Cap: 1800, ClockSkew: 60,
		Defaults: config.BuiltinLifetimeDefaults(),
		Keys:     mgr, Store: store, Sessions: session.New(rdb),
		IDPs: map[string]idp.IdentityProvider{
			"one": stubIDP{id: "one"},
			"two": stubIDP{id: "two"},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	authSrv.Config.Handler = httpserver.New(nil, mgr, nil, handler.Mount)
	authSrv.Start()
	t.Cleanup(authSrv.Close)
	res, err := http.Get(authorizeURL(authSrv.URL, id, redirect, "state-state-state", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", ""))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	got, _ := landed.Load().(string)
	u, err := url.Parse(got)
	if err != nil || u.Query().Get("error") != "invalid_request" || u.Query().Get("error_description") == "" {
		t.Fatalf("landed %s", got)
	}

	empty := httptest.NewUnstartedServer(nil)
	noIDP, err := New(Deps{
		Issuer: "http://" + empty.Listener.Addr().String(), DC: "local", Cap: 1800, ClockSkew: 60,
		Defaults: config.BuiltinLifetimeDefaults(),
		Keys:     mgr, Store: store, Sessions: session.New(rdb),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	empty.Config.Handler = httpserver.New(nil, mgr, nil, noIDP.Mount)
	empty.Start()
	t.Cleanup(empty.Close)
	landed.Store("")
	res, err = http.Get(authorizeURL(empty.URL, id, redirect, "state-state-state", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", ""))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	got, _ = landed.Load().(string)
	u, err = url.Parse(got)
	if err != nil || u.Query().Get("error") != "temporarily_unavailable" {
		t.Fatalf("no idp landed %s", got)
	}
}

type stubIDP struct{ id string }

func (s stubIDP) ID() string             { return s.id }
func (s stubIDP) Protocol() idp.Protocol { return idp.ProtocolOIDC }
func (s stubIDP) BuildLoginRedirect(context.Context, string) (string, error) {
	return "http://idp.example/login", nil
}
func (s stubIDP) HandleCallback(context.Context, *http.Request) (*idp.Identity, error) {
	return nil, errNoIDP
}
func (s stubIDP) BuildLogoutRedirect(context.Context, idp.LogoutHint) (string, bool) {
	return "", false
}

type capture struct {
	mu   sync.Mutex
	urls map[string]*url.URL
}

func newCapture() *capture { return &capture{urls: map[string]*url.URL{}} }

func (c *capture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.urls[r.URL.Path] = r.URL
	c.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (c *capture) take(path string) *url.URL {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.urls[path]
}

func authorizeURL(issuer, clientID, redirect, state, verifier, prompt string) string {
	sum := sha256Sum(verifier)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", "openid profile")
	q.Set("state", state)
	q.Set("nonce", "nonce-nonce-nonce")
	q.Set("code_challenge", sum)
	q.Set("code_challenge_method", "S256")
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	return issuer + "/oauth2/authorize?" + q.Encode()
}

type mockOP struct {
	issuer   string
	clientID string
	secret   string
	key      *rsa.PrivateKey
	kid      string
	hits     atomic.Int32
	deny     atomic.Bool
	emp      string
	authTime int64

	mu    sync.Mutex
	name  string
	email string
}

func newMockOP(t *testing.T) *mockOP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	op := &mockOP{key: key, kid: "mock-1", clientID: "auth-center", secret: "upstream-secret", authTime: 1_690_000_000}
	srv := httptest.NewUnstartedServer(nil)
	op.issuer = "http://" + srv.Listener.Addr().String()
	srv.Config.Handler = op
	srv.Start()
	t.Cleanup(srv.Close)
	return op
}

func (m *mockOP) setProfile(name, email string) {
	m.mu.Lock()
	m.name = name
	m.email = email
	m.mu.Unlock()
}

func (m *mockOP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                m.issuer,
			"authorization_endpoint":                m.issuer + "/authorize",
			"token_endpoint":                        m.issuer + "/token",
			"jwks_uri":                              m.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/jwks":
		jwk := jose.JSONWebKey{Key: &m.key.PublicKey, KeyID: m.kid, Algorithm: "RS256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	case "/authorize":
		m.hits.Add(1)
		u, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		q := u.Query()
		if m.deny.Load() {
			q.Set("error", "access_denied")
		} else {
			q.Set("code", "upstream-code")
		}
		q.Set("state", r.URL.Query().Get("state"))
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	case "/token":
		w.Header().Set("Content-Type", "application/json")
		m.mu.Lock()
		name, email := m.name, m.email
		m.mu.Unlock()
		claims := map[string]any{
			"iss": m.issuer, "sub": "upstream-subject", "aud": m.clientID,
			"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
			"employeeNumber": m.emp, "amr": []string{"pwd"}, "auth_time": m.authTime,
		}
		if name != "" {
			claims["name"] = name
		}
		if email != "" {
			claims["email"] = email
		}
		jwk := jose.JSONWebKey{Key: m.key, KeyID: m.kid, Algorithm: string(jose.RS256), Use: "sig"}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		payload, _ := json.Marshal(claims)
		signed, err := signer.Sign(payload)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		raw, _ := signed.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-access", "token_type": "Bearer", "id_token": raw,
		})
	default:
		http.NotFound(w, r)
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf[:])
}

func sha256Sum(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
