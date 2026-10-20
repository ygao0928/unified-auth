package oauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "request body is not a valid form", "invalid_request")
		return
	}
	client, ok := h.resolveRevokeClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-center"`)
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeInvalidRequest, "client authentication failed", "invalid_client")
		return
	}
	raw := r.PostFormValue("token")
	if raw == "" {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "token is required", "invalid_request")
		return
	}
	hint := r.PostFormValue("token_type_hint")
	switch hint {
	case "", "refresh_token", "access_token":
	default:
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "token_type_hint is invalid", "invalid_request")
		return
	}
	tryAccess := hint != "refresh_token"
	if tryAccess {
		handled, err := h.revokeAccess(r.Context(), client, raw)
		if h.finishRevoke(w, r, handled, err) {
			return
		}
	}
	handled, err := h.revokeRefresh(r.Context(), client, raw)
	if h.finishRevoke(w, r, handled, err) {
		return
	}
	if !tryAccess {
		handled, err = h.revokeAccess(r.Context(), client, raw)
		if h.finishRevoke(w, r, handled, err) {
			return
		}
	}
	h.writeRevoked(w)
}

func (h *Handler) finishRevoke(w http.ResponseWriter, r *http.Request, handled bool, err error) bool {
	if err != nil {
		h.logger.Error("revoke token", "trace_id", httpserver.TraceID(r.Context()))
		h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
		return true
	}
	if handled {
		h.writeRevoked(w)
		return true
	}
	return false
}

func (h *Handler) writeRevoked(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

// resolveRevokeClient 允许公开客户端只带 client_id。交了密钥就必须匹配。
func (h *Handler) resolveRevokeClient(r *http.Request) (pgstore.Client, bool) {
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
	if client.Enabled && client.IsPublic() {
		return client, true
	}
	return pgstore.Client{}, false
}

// revokeAccess 在这是一张验得过的 access token 时返回 handled。不属于这个客户端则不吊销。
func (h *Handler) revokeAccess(ctx context.Context, client pgstore.Client, raw string) (bool, error) {
	claims, err := h.verifyAccess(raw, true)
	if err != nil {
		return false, nil
	}
	aud, _ := claimString(claims, "aud")
	azp, _ := claimString(claims, "azp")
	if aud != client.ClientID && azp != client.ClientID {
		return true, nil
	}
	asid, _ := claimString(claims, "asid")
	sid, _ := claimString(claims, "sid")
	sub, _ := claimString(claims, "sub")
	as, err := h.sessions.GetApp(ctx, asid)
	if errors.Is(err, session.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if as.ClientID != client.ClientID || as.SID != sid {
		return true, nil
	}
	if _, err := h.sessions.RevokeApp(ctx, asid); err != nil && !errors.Is(err, session.ErrNotFound) {
		return false, err
	}
	h.publishRevoked(ctx, appSessionRevoked(asid, sid, sub, client.ClientID))
	return true, nil
}

func (h *Handler) revokeRefresh(ctx context.Context, client pgstore.Client, raw string) (bool, error) {
	current, err := h.sessions.GetRefresh(ctx, tokenHash(raw))
	if errors.Is(err, session.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	as, err := h.sessions.GetApp(ctx, current.ASID)
	if errors.Is(err, session.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if as.ClientID != client.ClientID {
		return true, nil
	}
	if _, err := h.sessions.RevokeApp(ctx, as.ASID); err != nil && !errors.Is(err, session.ErrNotFound) {
		return false, err
	}
	sub := ""
	if gs, gerr := h.sessions.GetGlobal(ctx, as.SID); gerr == nil {
		sub = gs.Sub
	} else if gerr != nil && !errors.Is(gerr, session.ErrNotFound) {
		return false, gerr
	}
	h.publishRevoked(ctx, appSessionRevoked(as.ASID, as.SID, sub, client.ClientID))
	return true, nil
}
