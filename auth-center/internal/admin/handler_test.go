package admin

import (
	"bytes"
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
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/audit"
	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/oauth"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func TestRegisterClientCompletesCodeExchange(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	pemBytes, _, err := keys.GenerateRSA("admin-key", 2048)
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
	authSrv := httptest.NewUnstartedServer(nil)
	issuer := "http://" + authSrv.Listener.Addr().String()
	oauthHandler, err := oauth.New(oauth.Deps{
		Issuer: issuer, DC: "local", Cap: config.DefaultAccessTokenTTLCap, ClockSkew: 60, Defaults: defaults,
		Keys: mgr, Store: store, Sessions: sessions,
		Now:    func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	adminHandler, err := New(Deps{
		Issuer: issuer, DC: "local", ClockSkew: 60, AdminToken: "bootstrap-token",
		Keys: mgr, Store: store,
		Now:    func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	authSrv.Config.Handler = httpserver.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mgr, nil, oauthHandler.Mount, adminHandler.Mount)
	authSrv.Start()
	t.Cleanup(authSrv.Close)

	call := func(method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, issuer+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, out
	}

	status, body := call(http.MethodPost, "/api/v1/apps", "", map[string]any{"name": "x", "client_type": "web"})
	if status != http.StatusUnauthorized || body["code"] != "AUTH_TOKEN_MISSING" {
		t.Fatalf("missing token %d %#v", status, body)
	}
	status, body = call(http.MethodPost, "/api/v1/apps", "nope", map[string]any{"name": "x", "client_type": "web", "redirect_uris": []string{"https://app.example/cb"}})
	if status != http.StatusUnauthorized || body["code"] != "AUTH_TOKEN_INVALID" {
		t.Fatalf("bad token %d %#v", status, body)
	}

	ttl := 90
	redirect := "https://app.example/cb"
	status, created := call(http.MethodPost, "/api/v1/apps", "bootstrap-token", map[string]any{
		"name": "会议", "client_type": "web", "redirect_uris": []string{redirect},
		"backchannel_logout_uri": "https://app.example/logout",
		"session_policy":         map[string]any{"access_token_ttl": ttl},
	})
	if status != http.StatusCreated {
		t.Fatalf("create %d %#v", status, created)
	}
	clientID, _ := created["client_id"].(string)
	secret, _ := created["client_secret"].(string)
	if clientID == "" || secret == "" || created["public"] != false {
		t.Fatalf("created %#v", created)
	}
	status, got := call(http.MethodGet, "/api/v1/apps/"+clientID, "bootstrap-token", nil)
	if status != http.StatusOK {
		t.Fatalf("get %d %#v", status, got)
	}
	if _, ok := got["client_secret"]; ok || strings.Contains(mustJSON(t, got), secret) {
		t.Fatalf("secret returned again %#v", got)
	}
	stored, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.SecretMatches(secret) || bcrypt.CompareHashAndPassword([]byte(stored.SecretHash), []byte(secret)) != nil {
		t.Fatal("stored hash does not match the secret shown once")
	}
	life, err := store.Resolve(stored)
	if err != nil {
		t.Fatal(err)
	}
	if life.AccessTokenTTL != 90 || life.RefreshTokenTTL != defaults.RefreshTokenTTL || life.IdleTimeout != defaults.WebIdleTimeout || life.AbsoluteSessionTTL != defaults.WebAbsoluteSessionTTL {
		t.Fatalf("lifetimes %+v", life)
	}

	emp := "E" + randomSuffix(t)
	name := "李四"
	if err := store.UpsertUserFromLogin(ctx, pgstore.User{EmpNo: emp, Name: &name}); err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	code := seedCode(t, ctx, sessions, clientID, config.ClientWeb, emp, redirect, verifier, now.Unix())
	status, tokenBody := token(t, issuer, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {clientID}, "client_secret": {secret}, "code_verifier": {verifier},
	})
	if status != http.StatusOK || tokenBody["token_type"] != "Bearer" || tokenBody["expires_in"] != float64(90) {
		t.Fatalf("exchange %d %#v", status, tokenBody)
	}

	status, publicApp := call(http.MethodPost, "/api/v1/apps", "bootstrap-token", map[string]any{
		"name": "SPA", "client_type": "web", "public": true, "redirect_uris": []string{redirect},
	})
	if status != http.StatusCreated || publicApp["client_secret"] != nil || publicApp["public"] != true {
		t.Fatalf("public %#v", publicApp)
	}
	publicID, _ := publicApp["client_id"].(string)
	publicStored, err := store.GetClient(ctx, publicID)
	if err != nil {
		t.Fatal(err)
	}
	publicLife, err := store.Resolve(publicStored)
	if err != nil {
		t.Fatal(err)
	}
	if publicLife.AccessTokenTTL != defaults.UserAccessTokenTTL || publicStored.SecretHash != "" {
		t.Fatalf("public defaults %+v hash %q", publicLife, publicStored.SecretHash)
	}
	code = seedCode(t, ctx, sessions, publicID, config.ClientWeb, emp, redirect, verifier, now.Unix())
	status, tokenBody = token(t, issuer, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {publicID}, "code_verifier": {verifier},
	})
	if status != http.StatusOK || tokenBody["expires_in"] != float64(defaults.UserAccessTokenTTL) {
		t.Fatalf("public exchange %d %#v", status, tokenBody)
	}

	status, _ = call(http.MethodPost, "/api/v1/apps", "bootstrap-token", map[string]any{
		"client_id": clientID, "name": "dup", "client_type": "web", "redirect_uris": []string{redirect},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("duplicate %d", status)
	}
	status, _ = call(http.MethodPost, "/api/v1/apps", "bootstrap-token", map[string]any{
		"name": "ssr", "client_type": "ssr", "public": true, "redirect_uris": []string{redirect},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("public ssr %d", status)
	}
	status, m2m := call(http.MethodPost, "/api/v1/apps", "bootstrap-token", map[string]any{
		"name": "worker", "client_type": "m2m",
	})
	if status != http.StatusCreated || m2m["client_secret"] == nil {
		t.Fatalf("m2m %d %#v", status, m2m)
	}

	status, rotated := call(http.MethodPost, "/api/v1/apps/"+clientID+"/secret", "bootstrap-token", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("rotate %d %#v", status, rotated)
	}
	newSecret, _ := rotated["client_secret"].(string)
	if newSecret == "" || newSecret == secret {
		t.Fatalf("rotated %#v", rotated)
	}
	stored, err = store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SecretMatches(secret) || !stored.SecretMatches(newSecret) {
		t.Fatal("rotation did not replace the hash")
	}
	status, got = call(http.MethodGet, "/api/v1/apps/"+clientID, "bootstrap-token", nil)
	if status != http.StatusOK || strings.Contains(mustJSON(t, got), newSecret) {
		t.Fatalf("secret still visible %#v", got)
	}

	status, patched := call(http.MethodPatch, "/api/v1/apps/"+clientID, "bootstrap-token", map[string]any{"enabled": false})
	if status != http.StatusOK || patched["enabled"] != false || patched["client_secret"] != nil {
		t.Fatalf("disable %#v", patched)
	}
	disabled := eventsFor(t, ctx, store, "admin.app.disabled", clientID)
	rotatedEvents := eventsFor(t, ctx, store, "admin.app.secret_rotated", clientID)
	if len(disabled) != 1 || len(rotatedEvents) != 1 {
		t.Fatalf("disabled %d rotated %d", len(disabled), len(rotatedEvents))
	}
	if strings.Contains(string(rotatedEvents[0]), newSecret) || strings.Contains(string(rotatedEvents[0]), secret) {
		t.Fatal("rotation audit contains a secret")
	}

	m2mToken, err := mgr.Sign(map[string]any{
		"iss": issuer, "sub": "client:registrar", "aud": "auth-center",
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
		"client_type": "m2m", "azp": "registrar", "scope": "ua.apps.register",
	}, "at+jwt")
	if err != nil {
		t.Fatal(err)
	}
	status, viaM2M := call(http.MethodPost, "/api/v1/apps", m2mToken, map[string]any{
		"name": "via-m2m", "client_type": "app", "public": true, "redirect_uris": []string{redirect},
	})
	if status != http.StatusCreated {
		t.Fatalf("m2m register %d %#v", status, viaM2M)
	}
	createdBy := eventsFor(t, ctx, store, "admin.app.created", viaM2M["client_id"].(string))
	if len(createdBy) != 1 || !strings.Contains(string(createdBy[0]), `"type": "client"`) {
		t.Fatalf("m2m audit %s", createdBy)
	}

	status, _ = call(http.MethodGet, "/api/v1/apps/missing-client", "bootstrap-token", nil)
	if status != http.StatusNotFound {
		t.Fatalf("missing %d", status)
	}
}

func eventsFor(t *testing.T, ctx context.Context, store *pgstore.Store, name, clientID string) []json.RawMessage {
	t.Helper()
	rows, err := store.ListAudit(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	var out []json.RawMessage
	for _, raw := range rows {
		var head struct {
			ClientID string `json:"client_id"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			t.Fatal(err)
		}
		if head.ClientID == clientID {
			if err := audit.Validate(raw); err != nil {
				t.Fatal(err)
			}
			out = append(out, raw)
		}
	}
	return out
}

func token(t *testing.T, issuer string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, issuer+"/oauth2/token", strings.NewReader(form.Encode()))
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
	return res.StatusCode, body
}

func seedCode(t *testing.T, ctx context.Context, sessions *session.Store, clientID, clientType, emp, redirect, verifier string, now int64) string {
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
	if err := sessions.PutCode(ctx, sha256Hex(raw), session.AuthCode{
		ClientID: clientID, RedirectURI: redirect, CodeChallenge: challenge,
		Scope: "openid", SID: sid, ASID: asid, Sub: emp, AuthTime: now,
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	return raw
}

func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf[:])
}
