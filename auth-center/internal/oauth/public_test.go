package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func TestPublicClientTokenAndRefresh(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	pemBytes, _, err := keys.GenerateRSA("public-key", 2048)
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
	now := time.Unix(1_700_000_000, 0).UTC()
	handler, err := New(Deps{
		Issuer: "http://auth.example", DC: "local", Cap: 1800, ClockSkew: 60, Defaults: defaults,
		Keys: mgr, Store: store, Sessions: sessions,
		Now:    func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	handler.Mount(router)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	name := "李四"
	emp := "E" + randomSuffix(t)
	if err := store.UpsertUserFromLogin(ctx, pgstore.User{EmpNo: emp, Name: &name}); err != nil {
		t.Fatal(err)
	}
	hash, err := pgstore.HashClientSecret("conf-secret", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	sfx := randomSuffix(t)
	publicWeb := "spa-" + sfx
	publicApp := "app-" + sfx
	publicMini := "mini-" + sfx
	confidential := "bff-" + sfx
	ssr := "ssr-" + sfx
	redirect := "https://app.example/cb"
	clients := []pgstore.Client{
		{ClientID: publicWeb, Name: publicWeb, ClientType: config.ClientWeb, RedirectURIs: []string{redirect}, Enabled: true},
		{ClientID: publicApp, Name: publicApp, ClientType: config.ClientApp, RedirectURIs: []string{redirect}, Enabled: true},
		{ClientID: publicMini, Name: publicMini, ClientType: config.ClientMiniApp, RedirectURIs: []string{redirect}, Enabled: true},
		{ClientID: confidential, Name: confidential, ClientType: config.ClientWeb, SecretHash: hash, RedirectURIs: []string{redirect}, Enabled: true},
		{ClientID: ssr, Name: ssr, ClientType: config.ClientSSR, RedirectURIs: []string{redirect}, Enabled: true},
	}
	for _, c := range clients {
		if err := store.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	post := func(form url.Values) (int, map[string]any, http.Header) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, body, res.Header
	}
	seed := func(clientID, clientType string) string {
		t.Helper()
		return seedAuthCode(t, ctx, sessions, clientID, clientType, emp, redirect, verifier, now.Unix())
	}

	code := seed(publicWeb, config.ClientWeb)
	status, body, _ := post(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {publicWeb}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("public code %d %#v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" || body["access_token"] == "" {
		t.Fatalf("public token %#v", body)
	}

	status, body, _ = post(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {publicWeb},
	})
	if status != http.StatusOK {
		t.Fatalf("public refresh %d %#v", status, body)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == refresh {
		t.Fatalf("refresh did not rotate: %#v", body)
	}
	status, body, hdr := post(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {publicWeb},
	})
	if status != http.StatusUnauthorized || body["code"] != "AUTH_REFRESH_REUSED" || body["error"] != "invalid_grant" {
		t.Fatalf("reuse %d %#v", status, body)
	}
	if hdr.Get("WWW-Authenticate") != "" {
		t.Fatal("reuse is not a client auth failure")
	}
	status, body, _ = post(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rotated}, "client_id": {publicWeb},
	})
	if status != http.StatusUnauthorized || body["code"] != "AUTH_LOGIN_REQUIRED" {
		t.Fatalf("rotated after reuse %d %#v", status, body)
	}

	for _, id := range []string{publicApp, publicMini} {
		code = seed(id, map[string]string{publicApp: config.ClientApp, publicMini: config.ClientMiniApp}[id])
		status, body, _ = post(url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
			"client_id": {id}, "code_verifier": {verifier},
		})
		if status != http.StatusOK {
			t.Fatalf("%s %d %#v", id, status, body)
		}
	}

	code = seed(publicWeb, config.ClientWeb)
	status, body, hdr = post(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {publicWeb}, "client_secret": {"nope"}, "code_verifier": {verifier},
	})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" || body["code"] != "INVALID_REQUEST" {
		t.Fatalf("bogus secret %d %#v", status, body)
	}
	if hdr.Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}

	code = seed(confidential, config.ClientWeb)
	status, body, _ = post(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {confidential}, "code_verifier": {verifier},
	})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("confidential without secret %d %#v", status, body)
	}
	code = seed(confidential, config.ClientWeb)
	status, body, _ = post(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {confidential}, "client_secret": {"conf-secret"}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("confidential with secret %d %#v", status, body)
	}

	code = seed(ssr, config.ClientSSR)
	status, body, _ = post(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {ssr}, "code_verifier": {verifier},
	})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("ssr without secret %d %#v", status, body)
	}

	status, body, _ = post(url.Values{
		"grant_type": {"client_credentials"}, "client_id": {publicWeb},
	})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("public client_credentials %d %#v", status, body)
	}
}

func seedAuthCode(t *testing.T, ctx context.Context, sessions *session.Store, clientID, clientType, emp, redirect, verifier string, now int64) string {
	t.Helper()
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	raw := hex.EncodeToString(buf[:])
	sid := "local." + hex.EncodeToString(buf[:8])
	asid := "as." + hex.EncodeToString(buf[8:])
	if err := sessions.PutGlobal(ctx, session.GlobalSession{
		SID: sid, Sub: emp, IDP: "corp", CreatedAt: now, LastActive: now, AbsExp: now + 3600,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.PutApp(ctx, session.AppSession{
		ASID: asid, SID: sid, ClientID: clientID, ClientType: clientType, CreatedAt: now, LastActive: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.PutAuthMeta(ctx, asid, session.AuthMeta{Scope: "openid", AuthTime: now}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := sessions.PutCode(ctx, tokenHash(raw), session.AuthCode{
		ClientID: clientID, RedirectURI: redirect, CodeChallenge: challenge,
		Scope: "openid", SID: sid, ASID: asid, Sub: emp, AuthTime: now,
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	return raw
}
