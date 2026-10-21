package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "request body is not a valid form", "invalid_request")
		return
	}
	client, ok := h.resolveClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-center"`)
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeInvalidClient, "client authentication failed", "invalid_client")
		return
	}
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		h.authorizationCode(w, r, client)
	case "refresh_token":
		h.refresh(w, r, client)
	case "":
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "grant_type is required", "invalid_request")
	default:
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "grant_type is not supported", "unsupported_grant_type")
	}
}

func (h *Handler) authorizationCode(w http.ResponseWriter, r *http.Request, client pgstore.Client) {
	rawCode := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	verifier := r.PostFormValue("code_verifier")
	if rawCode == "" || redirectURI == "" || verifier == "" {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "code, redirect_uri, and code_verifier are required", "invalid_request")
		return
	}
	stored, err := h.sessions.TakeCode(r.Context(), tokenHash(rawCode))
	if errors.Is(err, session.ErrNotFound) {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "authorization code is invalid", "invalid_grant")
		return
	}
	if err != nil {
		h.logger.Error("load authorization code", "trace_id", httpserver.TraceID(r.Context()))
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "authorization code store is unavailable", "temporarily_unavailable")
		return
	}
	if stored.ClientID != client.ClientID || stored.RedirectURI != redirectURI || VerifyPKCE(verifier, stored.CodeChallenge) != nil {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "authorization code is invalid", "invalid_grant")
		return
	}
	as, gs, ok := h.loadLiveSession(w, r, stored.ASID, stored.SID, stored.Sub, client)
	if !ok {
		return
	}
	resp, err := h.issueTokens(r.Context(), client, gs, as, stored.Nonce, true, "")
	if err != nil {
		h.tokenIssueError(w, r, err)
		return
	}
	h.writeToken(w, resp)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request, client pgstore.Client) {
	raw := r.PostFormValue("refresh_token")
	if raw == "" {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "refresh_token is required", "invalid_request")
		return
	}
	hash := tokenHash(raw)
	current, err := h.sessions.GetRefresh(r.Context(), hash)
	if errors.Is(err, session.ErrNotFound) {
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "refresh token is invalid or expired", "invalid_grant")
		return
	}
	if err != nil {
		h.logger.Error("load refresh token", "trace_id", httpserver.TraceID(r.Context()))
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return
	}
	if current.Used {
		h.revokeFromApp(r, current.ASID, current.FamilyID)
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeRefreshReused, "refresh token was reused", "invalid_grant")
		return
	}
	as, err := h.sessions.GetApp(r.Context(), current.ASID)
	if errors.Is(err, session.ErrNotFound) {
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "session is no longer valid", "invalid_grant")
		return
	}
	if err != nil {
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return
	}
	if as.ClientID != client.ClientID || as.ClientType != client.ClientType {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "refresh token does not belong to this client", "invalid_grant")
		return
	}
	gs, err := h.sessions.GetGlobal(r.Context(), as.SID)
	if errors.Is(err, session.ErrNotFound) {
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "session is no longer valid", "invalid_grant")
		return
	}
	if err != nil {
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return
	}
	revoked, err := h.sessions.IsSIDRevoked(r.Context(), gs.SID)
	if err != nil {
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return
	}
	if revoked {
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "session is no longer valid", "invalid_grant")
		return
	}
	life, err := h.store.Resolve(client)
	if err != nil {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client lifetimes are invalid", "invalid_grant")
		return
	}
	now := h.nowUnix()
	if now >= gs.AbsExp || now >= as.LastActive+int64(life.IdleTimeout) {
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "session expired", "invalid_grant")
		return
	}
	result, consumed, err := h.sessions.ConsumeRefresh(r.Context(), hash)
	if err != nil {
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return
	}
	switch result {
	case session.ConsumeMissing:
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "refresh token is invalid or expired", "invalid_grant")
		return
	case session.ConsumeReused:
		h.revokeFromApp(r, consumed.ASID, consumed.FamilyID)
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeRefreshReused, "refresh token was reused", "invalid_grant")
		return
	case session.ConsumeOK:
	default:
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return
	}
	resp, err := h.issueTokens(r.Context(), client, gs, as, "", false, consumed.FamilyID)
	if err != nil {
		h.tokenIssueError(w, r, err)
		return
	}
	h.writeToken(w, resp)
}

func (h *Handler) loadLiveSession(w http.ResponseWriter, r *http.Request, asid, sid, sub string, client pgstore.Client) (session.AppSession, session.GlobalSession, bool) {
	as, err := h.sessions.GetApp(r.Context(), asid)
	if errors.Is(err, session.ErrNotFound) || (err == nil && (as.SID != sid || as.ClientID != client.ClientID)) {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "authorization code is invalid", "invalid_grant")
		return session.AppSession{}, session.GlobalSession{}, false
	}
	if err != nil {
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return session.AppSession{}, session.GlobalSession{}, false
	}
	gs, err := h.sessions.GetGlobal(r.Context(), sid)
	if errors.Is(err, session.ErrNotFound) || (err == nil && (gs.Sub != sub || gs.AbsExp <= h.nowUnix())) {
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "session is no longer valid", "invalid_grant")
		return session.AppSession{}, session.GlobalSession{}, false
	}
	if err != nil {
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return session.AppSession{}, session.GlobalSession{}, false
	}
	revoked, err := h.sessions.IsSIDRevoked(r.Context(), gs.SID)
	if err != nil {
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return session.AppSession{}, session.GlobalSession{}, false
	}
	if revoked {
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "session is no longer valid", "invalid_grant")
		return session.AppSession{}, session.GlobalSession{}, false
	}
	return as, gs, true
}

func (h *Handler) revokeFromApp(r *http.Request, asid, family string) {
	as, err := h.sessions.GetApp(r.Context(), asid)
	if err == nil {
		sub := ""
		if gs, gerr := h.sessions.GetGlobal(r.Context(), as.SID); gerr == nil {
			sub = gs.Sub
		}
		if revErr := h.sessions.RevokeChain(r.Context(), as.SID, h.retention()); revErr != nil {
			h.logger.Error("revoke session chain", "trace_id", httpserver.TraceID(r.Context()))
			return
		}
		h.publishRevoked(r.Context(), sessionRevoked(as.SID, sub, "refresh_reused"))
		return
	}
	if err := h.sessions.DeleteFamily(r.Context(), family); err != nil {
		h.logger.Error("delete refresh family", "trace_id", httpserver.TraceID(r.Context()))
	}
}

func (h *Handler) tokenIssueError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errLoginRequired):
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeLoginRequired, "session is no longer valid", "invalid_grant")
	case errors.Is(err, errInvalidGrant):
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "token request is invalid", "invalid_grant")
	default:
		h.logger.Error("issue token", "trace_id", httpserver.TraceID(r.Context()))
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "token could not be issued", "temporarily_unavailable")
	}
}

func (h *Handler) writeToken(w http.ResponseWriter, resp tokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// resolveClient 解析令牌端点的客户端。
// 带了密钥就必须对上，不论公开还是机密。
// 没带密钥时，只有无密钥的 web / app / miniapp，且 grant 是 authorization_code 或 refresh_token，才放行。
// 授权码本身仍要过 PKCE S256。刷新不重新交 verifier，轮换和重放检测不变。
func (h *Handler) resolveClient(r *http.Request) (pgstore.Client, bool) {
	id, secret, presented := clientCredentials(r)
	if id == "" {
		if secret != "" {
			_ = compareDummy(secret)
		}
		return pgstore.Client{}, false
	}
	client, err := h.store.GetClient(r.Context(), id)
	if err != nil {
		_ = compareDummy(secret)
		return pgstore.Client{}, false
	}
	if presented {
		if !client.SecretMatches(secret) || !client.Enabled {
			return pgstore.Client{}, false
		}
		return client, true
	}
	grant := r.PostFormValue("grant_type")
	if client.Enabled && client.IsPublic() && (grant == "authorization_code" || grant == "refresh_token") {
		return client, true
	}
	return pgstore.Client{}, false
}

func compareDummy(secret string) error {
	return bcrypt.CompareHashAndPassword(dummyHash, []byte(secret))
}

func clientCredentials(r *http.Request) (id, secret string, secretPresented bool) {
	if rawID, rawSecret, ok := r.BasicAuth(); ok {
		var errID, errSecret error
		id, errID = url.QueryUnescape(rawID)
		secret, errSecret = url.QueryUnescape(rawSecret)
		if errID != nil || errSecret != nil || id == "" {
			return "", "", false
		}
		if formID := r.PostFormValue("client_id"); formID != "" && formID != id {
			return "", "", false
		}
		return id, secret, true
	}
	secret = r.PostFormValue("client_secret")
	return r.PostFormValue("client_id"), secret, secret != ""
}
