package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLifetimesDefaults(t *testing.T) {
	cap := DefaultAccessTokenTTLCap
	web, err := ResolveLifetimes(ClientWeb, SessionPolicy{}, cap, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if web.AccessTokenTTL != 600 || web.RefreshTokenTTL != 600 || web.IdleTimeout != 7200 || web.AbsoluteSessionTTL != 43200 || !web.IssuesRefresh {
		t.Fatalf("web defaults: %+v", web)
	}
	ssr, err := ResolveLifetimes(ClientSSR, SessionPolicy{}, cap, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if ssr != web {
		t.Fatalf("ssr = %+v, want web %+v", ssr, web)
	}
	app, err := ResolveLifetimes(ClientApp, SessionPolicy{}, cap, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if app.IdleTimeout != 604800 || app.AbsoluteSessionTTL != 2592000 || app.RefreshTokenTTL != 600 {
		t.Fatalf("app defaults: %+v", app)
	}
	mini, err := ResolveLifetimes(ClientMiniApp, SessionPolicy{}, cap, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if mini != app {
		t.Fatalf("miniapp = %+v, want app %+v", mini, app)
	}
	m2m, err := ResolveLifetimes(ClientM2M, SessionPolicy{}, cap, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if m2m.AccessTokenTTL != 1800 || m2m.IssuesRefresh || m2m.RefreshTokenTTL != 0 || m2m.IdleTimeout != 0 || m2m.AbsoluteSessionTTL != 0 {
		t.Fatalf("m2m defaults: %+v", m2m)
	}
}

func TestResolveLifetimesOverrideAndCap(t *testing.T) {
	access := 90
	idle := 100
	web, err := ResolveLifetimes(ClientWeb, SessionPolicy{AccessTokenTTL: &access, IdleTimeout: &idle}, 1800, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if web.AccessTokenTTL != 90 || web.IdleTimeout != 100 || web.RefreshTokenTTL != 600 || web.AbsoluteSessionTTL != 43200 {
		t.Fatalf("partial override: %+v", web)
	}

	tooLong := 99999
	capped, err := ResolveLifetimes(ClientWeb, SessionPolicy{AccessTokenTTL: &tooLong}, 1800, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if capped.AccessTokenTTL != 1800 {
		t.Fatalf("cap: got %d", capped.AccessTokenTTL)
	}
	// refresh 不受 access_token_ttl_cap 约束。
	longRefresh := 99999
	refreshed, err := ResolveLifetimes(ClientWeb, SessionPolicy{RefreshTokenTTL: &longRefresh}, 1800, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RefreshTokenTTL != 99999 {
		t.Fatalf("refresh cap applied: %+v", refreshed)
	}

	lowCap, err := ResolveLifetimes(ClientM2M, SessionPolicy{}, 100, BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if lowCap.AccessTokenTTL != 100 {
		t.Fatalf("m2m truncated to cap: %+v", lowCap)
	}

	if _, err := ResolveLifetimes("desktop", SessionPolicy{}, 1800, BuiltinLifetimeDefaults()); err == nil {
		t.Fatal("unknown client type")
	}
	zero := 0
	if _, err := ResolveLifetimes(ClientWeb, SessionPolicy{AccessTokenTTL: &zero}, 1800, BuiltinLifetimeDefaults()); err == nil {
		t.Fatal("zero ttl")
	}
	refresh := 60
	if _, err := ResolveLifetimes(ClientM2M, SessionPolicy{RefreshTokenTTL: &refresh}, 1800, BuiltinLifetimeDefaults()); err == nil {
		t.Fatal("m2m refresh")
	}
}

func TestRetentionWindow(t *testing.T) {
	if RetentionSeconds(DefaultAccessTokenTTLCap, DefaultClockSkew) != 1860 {
		t.Fatal(RetentionSeconds(DefaultAccessTokenTTLCap, DefaultClockSkew))
	}
	if PreviousKeyPublishSeconds(DefaultAccessTokenTTLCap, DefaultPreviousKeyBuffer) != 1860 {
		t.Fatal(PreviousKeyPublishSeconds(DefaultAccessTokenTTLCap, DefaultPreviousKeyBuffer))
	}
}

func TestLoadFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := []byte(`
issuer: https://auth.example.com
dc: bj1
http:
  addr: ":9090"
postgres:
  dsn: postgres://auth@db/auth
redis:
  addr: redis:6379
access_token_ttl_cap: 900
clock_skew: 30
log:
  level: debug
keys:
  - kid: from-file
    alg: RS256
    pem_file: /tmp/file.pem
    role: active
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"AUTH_CENTER_DC":                   "sh1",
		"AUTH_CENTER_ACCESS_TOKEN_TTL_CAP": "1200",
		"AUTH_CENTER_KEY_ACTIVE_PEM_FILE":  "/keys/active.pem",
		"AUTH_CENTER_KEY_ACTIVE_ALG":       "RS256",
		"AUTH_CENTER_KEY_NEXT_PEM_FILE":    "/keys/next.pem",
		"AUTH_CENTER_KEY_NEXT_ALG":         "ES256",
	}
	cfg, err := load(func(k string) string { return env[k] }, path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "https://auth.example.com" || cfg.DC != "sh1" || cfg.HTTPAddr != ":9090" {
		t.Fatalf("identity fields: %+v", cfg)
	}
	if cfg.AccessTokenTTLCap != 1200 || cfg.ClockSkew != 30 || cfg.PreviousKeyBuffer != DefaultPreviousKeyBuffer {
		t.Fatalf("lifetimes: %+v", cfg)
	}
	if cfg.UserAccessTokenTTL != DefaultUserAccessTokenTTL || cfg.RefreshTokenTTL != DefaultRefreshTokenTTL || cfg.AuthCodeTTL != DefaultAuthCodeTTL {
		t.Fatalf("builtin lifetime defaults were not kept: %+v", cfg.LifetimeDefaults())
	}
	if cfg.PostgresDSN != "postgres://auth@db/auth" || cfg.RedisAddr != "redis:6379" || cfg.LogLevel != "debug" {
		t.Fatalf("deps: %+v", cfg)
	}
	if len(cfg.Keys) != 2 || cfg.Keys[0].PEMFile != "/keys/active.pem" || cfg.Keys[0].Role != "active" || cfg.Keys[1].Alg != "ES256" {
		t.Fatalf("env keys replace file keys: %+v", cfg.Keys)
	}
	if err := cfg.ValidateForServe(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsBadIssuerAndUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("issuer: https://auth.example.com/\ndc: bj1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(func(string) string { return "" }, path); err == nil {
		t.Fatal("trailing slash")
	}
	if err := os.WriteFile(path, []byte("issuer: https://auth.example.com\ndc: bj1\nextra: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(func(string) string { return "" }, path); err == nil {
		t.Fatal("unknown field")
	}
	if _, err := load(func(string) string { return "" }, ""); err == nil {
		t.Fatal("missing issuer")
	}
}

func TestConfiguredLifetimeDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := []byte(`
issuer: https://auth.example.com
dc: bj1
user_access_token_ttl: 90
m2m_access_token_ttl: 200
refresh_token_ttl: 120
web_idle_timeout: 30
web_absolute_session_ttl: 40
app_idle_timeout: 50
app_absolute_session_ttl: 60
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"AUTH_CENTER_USER_ACCESS_TOKEN_TTL": "80",
		"AUTH_CENTER_APP_IDLE_TIMEOUT":      "70",
	}
	cfg, err := load(func(k string) string { return env[k] }, path)
	if err != nil {
		t.Fatal(err)
	}
	defaults := cfg.LifetimeDefaults()
	if defaults.UserAccessTokenTTL != 80 || defaults.M2MAccessTokenTTL != 200 || defaults.RefreshTokenTTL != 120 {
		t.Fatalf("env did not override file: %+v", defaults)
	}
	if defaults.WebIdleTimeout != 30 || defaults.AppIdleTimeout != 70 || defaults.AppAbsoluteSessionTTL != 60 {
		t.Fatalf("session defaults: %+v", defaults)
	}
	web, err := ResolveLifetimes(ClientWeb, SessionPolicy{}, cfg.AccessTokenTTLCap, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if web.AccessTokenTTL != 80 || web.IdleTimeout != 30 || web.RefreshTokenTTL != 120 {
		t.Fatalf("configured web default: %+v", web)
	}
	access := 30
	over, err := ResolveLifetimes(ClientWeb, SessionPolicy{AccessTokenTTL: &access}, cfg.AccessTokenTTLCap, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if over.AccessTokenTTL != 30 || over.RefreshTokenTTL != 120 {
		t.Fatalf("client override lost: %+v", over)
	}
	tooLong := 99999
	capped, err := ResolveLifetimes(ClientWeb, SessionPolicy{AccessTokenTTL: &tooLong, RefreshTokenTTL: &tooLong}, 1800, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if capped.AccessTokenTTL != 1800 || capped.RefreshTokenTTL != 99999 {
		t.Fatalf("cap applied to refresh or missed access: %+v", capped)
	}
	ssr, err := ResolveLifetimes(ClientSSR, SessionPolicy{}, 1800, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if ssr.IdleTimeout != defaults.WebIdleTimeout || ssr.AbsoluteSessionTTL != defaults.WebAbsoluteSessionTTL {
		t.Fatalf("ssr should use web session defaults: %+v", ssr)
	}
	app, err := ResolveLifetimes(ClientApp, SessionPolicy{}, 1800, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if app.IdleTimeout != 70 {
		t.Fatalf("app idle: %+v", app)
	}
}

func TestLoadIDPFromEnv(t *testing.T) {
	env := map[string]string{
		"AUTH_CENTER_ISSUER":            "https://auth.example.com",
		"AUTH_CENTER_DC":                "bj1",
		"AUTH_CENTER_IDP_ID":            "corp",
		"AUTH_CENTER_IDP_ISSUER":        "https://idp.example.com",
		"AUTH_CENTER_IDP_CLIENT_ID":     "auth-center",
		"AUTH_CENTER_IDP_CLIENT_SECRET": "secret",
		"AUTH_CENTER_IDP_REDIRECT_URL":  "https://auth.example.com/idp/corp/callback",
		"AUTH_CENTER_IDP_EMP_NO_CLAIM":  "employeeNumber",
		"AUTH_CENTER_IDP_NAME_CLAIM":    "name",
		"AUTH_CENTER_IDP_SCOPES":        "openid profile",
	}
	cfg, err := load(func(k string) string { return env[k] }, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IDPs) != 1 || cfg.IDPs[0].Protocol != "OIDC" || cfg.IDPs[0].Mapping.EmpNo != "employeeNumber" || len(cfg.IDPs[0].Scopes) != 2 {
		t.Fatalf("%+v", cfg.IDPs)
	}
	env["AUTH_CENTER_IDP_PROTOCOL"] = "CAS"
	if _, err := load(func(k string) string { return env[k] }, ""); err == nil {
		t.Fatal("CAS should be rejected")
	}
}
