package oauth

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/audit"
	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp/oidc"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func TestLoginAuditSuccessAndFailure(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	op := newMockOP(t)
	op.emp = "E" + randomSuffix(t)
	op.name = "张三"
	op.email = "audit-" + randomSuffix(t) + "@example.com"

	pemBytes, _, err := keys.GenerateRSA("audit-key", 2048)
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
	now := time.Unix(1_700_000_000, 123_000_000).UTC()
	handler, err := New(Deps{
		Issuer: issuer, DC: "local", Cap: 1800, ClockSkew: 60, Defaults: defaults,
		Keys: mgr, Store: store, Sessions: sessions,
		IDPs:   map[string]idp.IdentityProvider{"corp": adapter},
		Now:    func() time.Time { return now },
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
	clientID := "audit-" + randomSuffix(t)
	hash, err := pgstore.HashClientSecret("audit-secret", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	redirect := clientSrv.URL + "/cb"
	if err := store.CreateClient(ctx, pgstore.Client{
		ClientID: clientID, Name: clientID, ClientType: config.ClientWeb, SecretHash: hash,
		RedirectURIs: []string{redirect}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	login := func() *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, authorizeURL(issuer, clientID, redirect, "state-state-state", verifier, ""), nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}

	op.deny.Store(true)
	failed := login()
	if failed.StatusCode != http.StatusNoContent {
		t.Fatalf("failure status %d", failed.StatusCode)
	}
	got := capture.take("/cb")
	if got == nil || got.Query().Get("error") != "access_denied" {
		t.Fatalf("failure redirect %#v", got)
	}

	op.deny.Store(false)
	okRes := login()
	if okRes.StatusCode != http.StatusNoContent || capture.take("/cb").Query().Get("code") == "" {
		t.Fatal("success login did not return a code")
	}
	silent := login()
	if silent.StatusCode != http.StatusNoContent || capture.take("/cb").Query().Get("code") == "" {
		t.Fatal("silent login did not return a code")
	}

	success := eventsFor(t, ctx, store, "auth.login.success", clientID)
	failure := eventsFor(t, ctx, store, "auth.login.failure", clientID)
	if len(success) != 1 || len(failure) != 1 {
		t.Fatalf("success %d failure %d", len(success), len(failure))
	}
	var ev audit.Event
	if err := json.Unmarshal(success[0], &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Actor.Type != "user" || ev.Actor.ID != op.emp || ev.Result != "success" || ev.Reason != nil {
		t.Fatalf("success event %+v", ev)
	}
	if ev.ClientType != config.ClientWeb || ev.IDP != "corp" || ev.DC != "local" || !strings.HasPrefix(ev.SID, "local.") {
		t.Fatalf("success fields %+v", ev)
	}
	if ev.Target == nil || ev.Target.Type != "app" || ev.Target.ID != clientID {
		t.Fatalf("target %+v", ev.Target)
	}
	raw := string(success[0])
	if strings.Contains(raw, op.email) || strings.Contains(raw, op.name) || strings.Contains(raw, "audit-secret") {
		t.Fatalf("success event leaked profile or secret: %s", raw)
	}
	var bad audit.Event
	if err := json.Unmarshal(failure[0], &bad); err != nil {
		t.Fatal(err)
	}
	if bad.Actor.Type != "anonymous" || bad.Actor.ID != clientID || bad.Result != "failure" || bad.Reason == nil || *bad.Reason != apierr.CodeUpstreamFailed {
		t.Fatalf("failure event %+v", bad)
	}
	if bad.SID != "" {
		t.Fatalf("failure should not record a session: %+v", bad)
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
