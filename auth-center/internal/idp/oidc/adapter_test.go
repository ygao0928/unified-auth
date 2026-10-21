package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
)

func testConfig() Config {
	return Config{
		ID:           "corp-oidc",
		Issuer:       "https://idp.example.com",
		ClientID:     "auth-center",
		ClientSecret: "secret",
		RedirectURL:  "https://auth.example.com/idp/corp-oidc/callback",
		Mapping:      Mapping{EmpNo: "employeeNumber", Name: "displayName", Email: "mail"},
	}
}

func TestNewAndNotReady(t *testing.T) {
	a, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != "corp-oidc" || a.Protocol() != idp.ProtocolOIDC || a.DisplayName() != "corp-oidc" {
		t.Fatalf("id/protocol/name %s %s %s", a.ID(), a.Protocol(), a.DisplayName())
	}
	named := testConfig()
	named.DisplayName = " 公司 SSO "
	namedAdapter, err := New(named)
	if err != nil {
		t.Fatal(err)
	}
	if namedAdapter.DisplayName() != "公司 SSO" {
		t.Fatal(namedAdapter.DisplayName())
	}
	if _, err := a.BuildLoginRedirect(context.Background(), "state-value"); !errors.Is(err, ErrNotReady) {
		t.Fatal(err)
	}
	req := httptestRequest("https://auth.example.com/cb?code=abc")
	if _, err := a.HandleCallback(context.Background(), req); !errors.Is(err, ErrNotReady) {
		t.Fatal(err)
	}
	if url, ok := a.BuildLogoutRedirect(context.Background(), idp.LogoutHint{SID: "bj1.1"}); ok || url != "" {
		t.Fatalf("logout %q %v", url, ok)
	}
	cfg := testConfig()
	cfg.Mapping.EmpNo = ""
	if _, err := New(cfg); err == nil {
		t.Fatal("missing mapping")
	}
}

type fakeRemote struct {
	authURL string
	claims  map[string]any
	err     error
}

func (f *fakeRemote) AuthCodeURL(state string) string {
	return f.authURL + "?state=" + url.QueryEscape(state)
}

func (f *fakeRemote) Exchange(context.Context, string) (map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

func TestRedirectAndCallback(t *testing.T) {
	a, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	a.remote = &fakeRemote{authURL: "https://idp.example.com/authorize"}
	got, err := a.BuildLoginRedirect(context.Background(), "state-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://idp.example.com/authorize?state=state-1" {
		t.Fatal(got)
	}
	if _, err := a.BuildLoginRedirect(context.Background(), ""); err == nil {
		t.Fatal("empty state")
	}

	req := httptestRequest("https://auth.example.com/cb?error=access_denied")
	if _, err := a.HandleCallback(context.Background(), req); !errors.Is(err, ErrUpstream) {
		t.Fatal(err)
	}

	a.remote = &fakeRemote{claims: map[string]any{
		"employeeNumber": "E10023",
		"displayName":    "",
		"mail":           "a@example.com",
		"amr":            []any{"pwd"},
		"auth_time":      float64(1700000000),
	}}
	id, err := a.HandleCallback(context.Background(), httptestRequest("https://auth.example.com/cb?code=abc"))
	if err != nil {
		t.Fatal(err)
	}
	if id.EmpNo != "E10023" || id.Name != nil || id.Email == nil || *id.Email != "a@example.com" {
		t.Fatalf("identity %+v", id)
	}
	if id.Provider != "corp-oidc" || len(id.AMR) != 1 || id.AMR[0] != "pwd" || !id.AuthTime.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("meta %+v", id)
	}
}

func TestIdentityFromClaims(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	_, err := IdentityFromClaims("p", Mapping{EmpNo: "employeeNumber"}, map[string]any{}, now)
	if !errors.Is(err, ErrEmpNoRequired) {
		t.Fatal(err)
	}
	id, err := IdentityFromClaims("p", Mapping{EmpNo: "employeeNumber", DeptID: "department"}, map[string]any{
		"employeeNumber": "E1",
		"department":     12,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if id.DeptID != nil || id.EmpNo != "E1" {
		t.Fatalf("%+v", id)
	}
	if id.Raw["department"] != 12 {
		t.Fatal("raw dropped")
	}
}

func httptestRequest(raw string) *http.Request {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return &http.Request{URL: u}
}
