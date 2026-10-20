package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
)

var (
	// ErrNotReady 表示还没有完成上游 discovery。
	ErrNotReady = errors.New("oidc adapter is not discovered")
	// ErrUpstream 表示上游拒绝或交换 code 失败。
	ErrUpstream = errors.New("upstream idp failed")
)

// Config 是一个 OIDC 上游身份源。属性映射的 claim 名由环境决定，这里不设默认 claim。
type Config struct {
	ID           string
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Mapping      Mapping
}

// Adapter 是 P1 的 OIDC 上游骨架。Discover 之后才能跳转和回调。
// 不检查 state：授权端点（P1-AC-04）持有期望值。登出跳转未做，见 R1。
type Adapter struct {
	cfg    Config
	remote remote
}

type remote interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (map[string]any, error)
}

type liveOIDC struct {
	cfg      oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func (l *liveOIDC) AuthCodeURL(state string) string {
	return l.cfg.AuthCodeURL(state)
}

func (l *liveOIDC) Exchange(ctx context.Context, code string) (map[string]any, error) {
	tok, err := l.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("id_token missing")
	}
	idToken, err := l.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// New 只检查配置，不访问上游。
func New(cfg Config) (*Adapter, error) {
	if cfg.ID == "" {
		return nil, errors.New("idp id is required")
	}
	if err := absoluteURL("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("upstream client_id and client_secret are required")
	}
	if err := absoluteURL("redirect_url", cfg.RedirectURL); err != nil {
		return nil, err
	}
	if cfg.Mapping.EmpNo == "" {
		return nil, errors.New("attribute mapping emp_no is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID}
	}
	return &Adapter{cfg: cfg}, nil
}

func absoluteURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", name)
	}
	return nil
}

// Discover 拉取上游 discovery 文档并准备 code 交换。
func (a *Adapter) Discover(ctx context.Context) error {
	provider, err := oidc.NewProvider(ctx, a.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	a.remote = &liveOIDC{
		cfg: oauth2.Config{
			ClientID:     a.cfg.ClientID,
			ClientSecret: a.cfg.ClientSecret,
			RedirectURL:  a.cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       a.cfg.Scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID}),
	}
	return nil
}

func (a *Adapter) ID() string { return a.cfg.ID }

func (a *Adapter) Protocol() idp.Protocol { return idp.ProtocolOIDC }

func (a *Adapter) BuildLoginRedirect(_ context.Context, state string) (string, error) {
	if a.remote == nil {
		return "", ErrNotReady
	}
	if state == "" {
		return "", errors.New("state is required")
	}
	return a.remote.AuthCodeURL(state), nil
}

func (a *Adapter) HandleCallback(ctx context.Context, r *http.Request) (*idp.Identity, error) {
	if a.remote == nil {
		return nil, ErrNotReady
	}
	if r == nil || r.URL == nil {
		return nil, errors.New("callback request is required")
	}
	if code := r.URL.Query().Get("error"); code != "" {
		return nil, fmt.Errorf("%w: %s", ErrUpstream, code)
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, errors.New("authorization code is missing")
	}
	claims, err := a.remote.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	return IdentityFromClaims(a.cfg.ID, a.cfg.Mapping, claims, time.Now().UTC())
}

// BuildLogoutRedirect 固定返回 ok=false。上游是否支持登出尚未确认（R1）。
func (a *Adapter) BuildLogoutRedirect(context.Context, idp.LogoutHint) (string, bool) {
	return "", false
}

var _ idp.IdentityProvider = (*Adapter)(nil)
