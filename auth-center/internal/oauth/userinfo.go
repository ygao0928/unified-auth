package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func (h *Handler) userinfo(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.CodeTokenMissing, "access token is required", httpserver.TraceID(r.Context()), nil)
		return
	}
	claims, err := h.verifyAccess(raw, false)
	if err != nil {
		h.writeTokenAuth(w, r, err)
		return
	}
	if err := h.accessLive(r.Context(), claims); err != nil {
		h.writeTokenAuth(w, r, err)
		return
	}
	sub, _ := claimString(claims, "sub")
	user, err := h.store.GetUser(r.Context(), sub)
	if errors.Is(err, pgstore.ErrNotFound) || (err == nil && user.Disabled) {
		apierr.Write(w, http.StatusUnauthorized, apierr.CodeSessionRevoked, "session is no longer valid", httpserver.TraceID(r.Context()), nil)
		return
	}
	if err != nil {
		h.logger.Error("load userinfo", "trace_id", httpserver.TraceID(r.Context()))
		apierr.Write(w, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "user store is unavailable", httpserver.TraceID(r.Context()), nil)
		return
	}
	body := map[string]any{"sub": user.EmpNo}
	putString(body, "name", deref(user.Name))
	putString(body, "email", deref(user.Email))
	putString(body, "dept_id", deref(user.DeptID))
	putString(body, "dept_name", deref(user.DeptName))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func (h *Handler) accessLive(ctx context.Context, claims map[string]any) error {
	sid, _ := claimString(claims, "sid")
	asid, _ := claimString(claims, "asid")
	azp, _ := claimString(claims, "azp")
	sub, _ := claimString(claims, "sub")
	revoked, err := h.sessions.IsSIDRevoked(ctx, sid)
	if err != nil {
		return err
	}
	if revoked {
		return errTokenRevoked
	}
	gs, err := h.sessions.GetGlobal(ctx, sid)
	if errors.Is(err, session.ErrNotFound) || (err == nil && (gs.AbsExp <= h.nowUnix() || gs.Sub != sub)) {
		if err == nil || errors.Is(err, session.ErrNotFound) {
			return errTokenRevoked
		}
	}
	if err != nil {
		return err
	}
	as, err := h.sessions.GetApp(ctx, asid)
	if errors.Is(err, session.ErrNotFound) {
		return errTokenRevoked
	}
	if err != nil {
		return err
	}
	if as.SID != sid || as.ClientID != azp {
		return errTokenInvalid
	}
	return nil
}

func (h *Handler) writeTokenAuth(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errTokenExpired):
		apierr.Write(w, http.StatusUnauthorized, apierr.CodeTokenExpired, "access token expired", httpserver.TraceID(r.Context()), nil)
	case errors.Is(err, errTokenRevoked):
		apierr.Write(w, http.StatusUnauthorized, apierr.CodeSessionRevoked, "session is no longer valid", httpserver.TraceID(r.Context()), nil)
	case errors.Is(err, errTokenInvalid):
		apierr.Write(w, http.StatusUnauthorized, apierr.CodeTokenInvalid, "access token is invalid", httpserver.TraceID(r.Context()), nil)
	default:
		h.logger.Error("check access token", "trace_id", httpserver.TraceID(r.Context()))
		apierr.Write(w, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", httpserver.TraceID(r.Context()), nil)
	}
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.Contains(token, " ") {
		return ""
	}
	return token
}
