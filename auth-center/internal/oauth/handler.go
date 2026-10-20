package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

const (
	cookieName = "auth_sid"
	maxParam   = 1024
)

var (
	errLoginRequired = errors.New("login required")
	errInvalidGrant  = errors.New("invalid grant")
	errNoIDP         = errors.New("no identity provider")
	errNeedHint      = errors.New("idp hint required")
	errUnknownHint   = errors.New("unknown idp")

	// 客户端不存在时也做一次 bcrypt，避免用响应时间区分。
	dummyHash []byte
)

func init() {
	var err error
	dummyHash, err = bcrypt.GenerateFromPassword([]byte("dummy-client-secret"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
}

// Deps 是授权与令牌端点的依赖。Now 为空时用 time.Now。
type Deps struct {
	Issuer      string
	DC          string
	Cap         int
	ClockSkew   int
	Defaults    config.LifetimeDefaults
	AuthCodeTTL time.Duration
	TxnTTL      time.Duration
	Keys        *keys.Manager
	Store       *pgstore.Store
	Sessions    *session.Store
	IDPs        map[string]idp.IdentityProvider
	Now         func() time.Time
	Logger      *slog.Logger
}

// Handler 实现授权码、上游回调、令牌和 discovery。
// 有效期解析使用 pgstore，调用方要把同一份 LifetimeDefaults 交给仓储。
type Handler struct {
	Issuer      string
	DC          string
	Cap         int
	ClockSkew   int
	AuthCodeTTL time.Duration
	TxnTTL      time.Duration
	keys        *keys.Manager
	store       *pgstore.Store
	sessions    *session.Store
	idps        map[string]idp.IdentityProvider
	Now         func() time.Time
	logger      *slog.Logger
	secure      bool
}

// New 检查签发令牌所必需的依赖。身份源可以为空，此时需要登录的授权请求会失败。
func New(d Deps) (*Handler, error) {
	if d.Issuer == "" || d.DC == "" || d.Keys == nil || d.Store == nil || d.Sessions == nil {
		return nil, errors.New("oauth handler is incomplete")
	}
	if d.Cap < 1 {
		return nil, errors.New("access_token_ttl_cap must be >= 1")
	}
	if err := d.Defaults.Validate(); err != nil {
		return nil, err
	}
	if d.AuthCodeTTL <= 0 {
		d.AuthCodeTTL = time.Duration(config.DefaultAuthCodeTTL) * time.Second
	}
	if d.TxnTTL <= 0 {
		d.TxnTTL = time.Duration(config.DefaultAuthorizeTxnTTL) * time.Second
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	idps := make(map[string]idp.IdentityProvider, len(d.IDPs))
	for id, p := range d.IDPs {
		idps[id] = p
	}
	return &Handler{
		Issuer: d.Issuer, DC: d.DC, Cap: d.Cap, ClockSkew: d.ClockSkew,
		AuthCodeTTL: d.AuthCodeTTL, TxnTTL: d.TxnTTL,
		keys: d.Keys, store: d.Store, sessions: d.Sessions, idps: idps,
		Now: d.Now, logger: d.Logger, secure: strings.HasPrefix(strings.ToLower(d.Issuer), "https://"),
	}, nil
}

// Mount 注册 discovery、授权、令牌和上游回调。
func (h *Handler) Mount(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.discovery)
	r.Get("/oauth2/authorize", h.authorize)
	r.Post("/oauth2/token", h.token)
	r.Get("/idp/{id}/callback", h.callback)
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client_id and redirect_uri are required", "invalid_request")
		return
	}
	client, ok := h.lookupClient(w, r, clientID)
	if !ok {
		return
	}
	if !exactRedirect(client, redirectURI) {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "redirect_uri is not registered", "invalid_request")
		return
	}
	if client.ClientType == config.ClientM2M {
		h.redirectErr(w, r, redirectURI, q.Get("state"), "unauthorized_client", "m2m clients cannot use the authorization code flow")
		return
	}
	state := q.Get("state")
	if q.Get("response_type") != "code" {
		h.redirectErr(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if len(state) < 16 || len(state) > maxParam {
		echo := state
		if len(echo) > maxParam {
			echo = ""
		}
		h.redirectErr(w, r, redirectURI, echo, "invalid_request", "state must be between 16 and 1024 characters")
		return
	}
	scope := q.Get("scope")
	if len(scope) > maxParam || !scopeContains(scope, "openid") {
		h.redirectErr(w, r, redirectURI, state, "invalid_request", "scope must contain openid")
		return
	}
	challenge := q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || challenge == "" || len(challenge) > maxParam {
		h.redirectErr(w, r, redirectURI, state, "invalid_request", "PKCE S256 is required")
		return
	}
	prompt := q.Get("prompt")
	if prompt != "" && prompt != "none" && prompt != "login" {
		h.redirectErr(w, r, redirectURI, state, "invalid_request", "prompt is invalid")
		return
	}
	nonce := q.Get("nonce")
	if len(nonce) > maxParam {
		h.redirectErr(w, r, redirectURI, state, "invalid_request", "nonce is too long")
		return
	}

	if prompt != "login" {
		if gs, ok := h.validSession(r); ok {
			meta := h.metaFromLogin(r.Context(), gs.SID, scope)
			h.finishCode(w, r, client, gs, redirectURI, state, nonce, challenge, meta)
			return
		}
	}
	if prompt == "none" {
		h.redirectErr(w, r, redirectURI, state, "login_required", "login required")
		return
	}
	provider, err := h.selectIDP(q.Get("idp_hint"))
	if err != nil {
		switch {
		case errors.Is(err, errNoIDP):
			h.redirectErr(w, r, redirectURI, state, "temporarily_unavailable", "no upstream identity provider is configured")
		case errors.Is(err, errNeedHint):
			h.redirectErr(w, r, redirectURI, state, "invalid_request", "idp_hint is required")
		default:
			h.redirectErr(w, r, redirectURI, state, "invalid_request", "idp_hint is unknown")
		}
		return
	}
	txID, err := randomHex(32)
	if err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "authorization could not be started")
		return
	}
	txn := session.AuthTxn{
		ID: txID, ClientID: client.ClientID, RedirectURI: redirectURI, State: state,
		Nonce: nonce, CodeChallenge: challenge, Scope: scope, IDPID: provider.ID(),
	}
	if err := h.sessions.PutTxn(r.Context(), txn, h.TxnTTL); err != nil {
		h.logger.Error("save authorization transaction", "err", err.Error(), "trace_id", httpserver.TraceID(r.Context()))
		h.redirectErr(w, r, redirectURI, state, "server_error", "authorization could not be started")
		return
	}
	loc, err := provider.BuildLoginRedirect(r.Context(), txID)
	if err != nil {
		h.logger.Error("upstream redirect", "idp", provider.ID(), "trace_id", httpserver.TraceID(r.Context()))
		h.redirectErr(w, r, redirectURI, state, "server_error", "upstream identity provider is unavailable")
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	idpID := chi.URLParam(r, "id")
	txID := r.URL.Query().Get("state")
	if txID == "" {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "authorization transaction is missing", "invalid_request")
		return
	}
	txn, err := h.sessions.TakeTxn(r.Context(), txID)
	if err != nil {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "authorization transaction expired or unknown", "invalid_request")
		return
	}
	if txn.IDPID != idpID {
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "invalid_request", "identity provider does not match the authorization request")
		return
	}
	provider, ok := h.idps[idpID]
	if !ok {
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "server_error", "identity provider is not available")
		return
	}
	if upstreamErr := r.URL.Query().Get("error"); upstreamErr != "" {
		oauthErr := "server_error"
		if upstreamErr == "access_denied" || upstreamErr == "login_required" {
			oauthErr = upstreamErr
		}
		h.redirectErr(w, r, txn.RedirectURI, txn.State, oauthErr, "upstream identity provider denied the login")
		return
	}
	client, ok := h.lookupClient(w, r, txn.ClientID)
	if !ok {
		return
	}
	if !exactRedirect(client, txn.RedirectURI) {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "redirect_uri is not registered", "invalid_request")
		return
	}
	ident, err := provider.HandleCallback(r.Context(), r)
	if err != nil || ident == nil || ident.EmpNo == "" {
		h.logger.Error("upstream callback failed", "idp", idpID, "trace_id", httpserver.TraceID(r.Context()))
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "server_error", "upstream identity provider failed")
		return
	}
	if err := h.store.UpsertUserFromLogin(r.Context(), pgstore.User{
		EmpNo: ident.EmpNo, Name: ident.Name, Email: ident.Email, Mobile: ident.Mobile,
		DeptID: ident.DeptID, DeptName: ident.DeptName,
	}); err != nil {
		h.logger.Error("upsert user", "trace_id", httpserver.TraceID(r.Context()))
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "server_error", "user could not be stored")
		return
	}
	user, err := h.store.GetUser(r.Context(), ident.EmpNo)
	if err != nil || user.Disabled {
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "access_denied", "user cannot sign in")
		return
	}
	life, err := h.store.Resolve(client)
	if err != nil || !life.IssuesRefresh {
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "server_error", "client lifetimes are invalid")
		return
	}
	now := h.nowUnix()
	sid, err := randomID(h.DC + ".")
	if err != nil {
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "server_error", "session could not be created")
		return
	}
	authTime := ident.AuthTime.UTC().Unix()
	gs := session.GlobalSession{
		SID: sid, Sub: ident.EmpNo, IDP: provider.ID(),
		CreatedAt: now, LastActive: now, AbsExp: now + int64(life.AbsoluteSessionTTL),
		IP: clientIP(r), UA: trim(r.UserAgent(), 512),
	}
	if err := h.sessions.PutGlobal(r.Context(), gs); err != nil {
		h.logger.Error("save global session", "trace_id", httpserver.TraceID(r.Context()))
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "server_error", "session could not be created")
		return
	}
	login := session.LoginMeta{AMR: ident.AMR}
	if authTime > 0 {
		login.AuthTime = authTime
	}
	if err := h.sessions.PutLoginMeta(r.Context(), sid, login); err != nil {
		h.redirectErr(w, r, txn.RedirectURI, txn.State, "server_error", "session could not be created")
		return
	}
	meta := session.AuthMeta{AuthTime: login.AuthTime, AMR: login.AMR, Scope: txn.Scope}
	h.finishCode(w, r, client, gs, txn.RedirectURI, txn.State, txn.Nonce, txn.CodeChallenge, meta)
}

func (h *Handler) finishCode(w http.ResponseWriter, r *http.Request, client pgstore.Client, gs session.GlobalSession, redirectURI, state, nonce, challenge string, meta session.AuthMeta) {
	user, err := h.store.GetUser(r.Context(), gs.Sub)
	if err != nil || user.Disabled {
		h.redirectErr(w, r, redirectURI, state, "access_denied", "user cannot sign in")
		return
	}
	now := h.nowUnix()
	asid, err := randomID("as.")
	if err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "session could not be created")
		return
	}
	as := session.AppSession{
		ASID: asid, SID: gs.SID, ClientID: client.ClientID, ClientType: client.ClientType,
		CreatedAt: now, LastActive: now,
	}
	if err := h.sessions.PutApp(r.Context(), as); err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "session could not be created")
		return
	}
	if err := h.sessions.PutUserSession(r.Context(), gs.Sub, asid, now); err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "session could not be created")
		return
	}
	if err := h.sessions.PutAuthMeta(r.Context(), asid, meta); err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "session could not be created")
		return
	}
	rawCode, err := randomToken(32)
	if err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "authorization code could not be created")
		return
	}
	code := session.AuthCode{
		ClientID: client.ClientID, RedirectURI: redirectURI, CodeChallenge: challenge,
		Scope: meta.Scope, Nonce: nonce, SID: gs.SID, ASID: asid, Sub: gs.Sub,
		AuthTime: meta.AuthTime, AMR: meta.AMR,
	}
	if err := h.sessions.PutCode(r.Context(), tokenHash(rawCode), code, h.AuthCodeTTL); err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "authorization code could not be created")
		return
	}
	h.setSessionCookie(w, gs.SID, gs.AbsExp)
	h.redirectCode(w, r, redirectURI, rawCode, state)
}

func (h *Handler) validSession(r *http.Request) (session.GlobalSession, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return session.GlobalSession{}, false
	}
	gs, err := h.sessions.GetGlobal(r.Context(), c.Value)
	if err != nil || gs.Sub == "" || gs.AbsExp <= h.nowUnix() {
		return session.GlobalSession{}, false
	}
	revoked, err := h.sessions.IsSIDRevoked(r.Context(), gs.SID)
	if err != nil || revoked {
		return session.GlobalSession{}, false
	}
	return gs, true
}

func (h *Handler) metaFromLogin(ctx context.Context, sid, scope string) session.AuthMeta {
	meta := session.AuthMeta{Scope: scope}
	login, err := h.sessions.GetLoginMeta(ctx, sid)
	if err != nil {
		return meta
	}
	meta.AuthTime = login.AuthTime
	meta.AMR = login.AMR
	return meta
}

func (h *Handler) selectIDP(hint string) (idp.IdentityProvider, error) {
	if hint != "" {
		p, ok := h.idps[hint]
		if !ok {
			return nil, errUnknownHint
		}
		return p, nil
	}
	if len(h.idps) == 1 {
		for _, p := range h.idps {
			return p, nil
		}
	}
	if len(h.idps) == 0 {
		return nil, errNoIDP
	}
	return nil, errNeedHint
}

func (h *Handler) lookupClient(w http.ResponseWriter, r *http.Request, clientID string) (pgstore.Client, bool) {
	client, err := h.store.GetClient(r.Context(), clientID)
	if errors.Is(err, pgstore.ErrNotFound) || (err == nil && !client.Enabled) {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client is invalid", "invalid_request")
		return pgstore.Client{}, false
	}
	if err != nil {
		h.logger.Error("load client", "trace_id", httpserver.TraceID(r.Context()))
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client store is unavailable", "temporarily_unavailable")
		return pgstore.Client{}, false
	}
	return client, true
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, sid string, absExp int64) {
	maxAge := int(absExp - h.nowUnix())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: sid, Path: "/", HttpOnly: true,
		Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

func (h *Handler) writeErr(w http.ResponseWriter, r *http.Request, status int, code, message, oauthErr string) {
	apierr.WriteOAuth(w, status, code, message, httpserver.TraceID(r.Context()), oauthErr, message)
}

func (h *Handler) redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, state, oauthErr, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "redirect uri is invalid", "invalid_request")
		return
	}
	q := u.Query()
	q.Set("error", oauthErr)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *Handler) redirectCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "redirect uri is invalid", "invalid_request")
		return
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *Handler) nowUnix() int64 {
	if h.Now != nil {
		return h.Now().UTC().Unix()
	}
	return time.Now().UTC().Unix()
}

func (h *Handler) retention() time.Duration {
	return seconds(config.RetentionSeconds(h.Cap, h.ClockSkew))
}

func exactRedirect(client pgstore.Client, redirectURI string) bool {
	for _, registered := range client.RedirectURIs {
		if registered == redirectURI {
			return true
		}
	}
	return false
}

func scopeContains(scope, want string) bool {
	for _, part := range strings.Fields(scope) {
		if part == want {
			return true
		}
	}
	return false
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomID(prefix string) (string, error) {
	n, err := randomHex(8)
	if err != nil {
		return "", err
	}
	return prefix + n, nil
}

func seconds(n int) time.Duration {
	return time.Duration(n) * time.Second
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return trim(r.RemoteAddr, 128)
	}
	return trim(host, 128)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
