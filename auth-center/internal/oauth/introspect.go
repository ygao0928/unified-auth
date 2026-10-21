package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
)

func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "request body is not a valid form", "invalid_request")
		return
	}
	client, ok := h.authenticateConfidential(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-center"`)
		h.writeErr(w, r, http.StatusUnauthorized, apierr.CodeInvalidClient, "client authentication failed", "invalid_client")
		return
	}
	raw := r.PostFormValue("token")
	if raw == "" {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "token is required", "invalid_request")
		return
	}
	if body, handled := h.introspectAccess(r, client, raw); handled {
		h.writeIntrospect(w, body)
		return
	}
	h.writeIntrospect(w, h.introspectRefresh(r, client, raw))
}

func (h *Handler) authenticateConfidential(r *http.Request) (pgstore.Client, bool) {
	id, secret, presented := clientCredentials(r)
	if id == "" || !presented {
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
	if !client.SecretMatches(secret) || !client.Enabled {
		return pgstore.Client{}, false
	}
	return client, true
}

func (h *Handler) introspectAccess(r *http.Request, client pgstore.Client, raw string) (map[string]any, bool) {
	claims, err := h.verifyAccess(raw, false)
	if errors.Is(err, errTokenInvalid) {
		return nil, false
	}
	inactive := map[string]any{"active": false}
	if err != nil {
		return inactive, true
	}
	aud, _ := claimString(claims, "aud")
	azp, _ := claimString(claims, "azp")
	if aud != client.ClientID && azp != client.ClientID {
		return inactive, true
	}
	if err := h.accessLive(r.Context(), claims); err != nil {
		return inactive, true
	}
	sub, _ := claimString(claims, "sub")
	user, err := h.store.GetUser(r.Context(), sub)
	if err != nil || user.Disabled {
		return inactive, true
	}
	return accessIntrospection(claims), true
}

func accessIntrospection(claims map[string]any) map[string]any {
	out := map[string]any{
		"active":      true,
		"token_type":  "Bearer",
		"iss":         mustString(claims, "iss"),
		"sub":         mustString(claims, "sub"),
		"aud":         mustString(claims, "aud"),
		"exp":         mustInt(claims, "exp"),
		"iat":         mustInt(claims, "iat"),
		"jti":         mustString(claims, "jti"),
		"azp":         mustString(claims, "azp"),
		"client_id":   mustString(claims, "azp"),
		"client_type": mustString(claims, "client_type"),
		"perm_ver":    mustInt(claims, "perm_ver"),
		"sid":         mustString(claims, "sid"),
		"asid":        mustString(claims, "asid"),
	}
	for _, key := range []string{"name", "email", "dept_id", "dept_name", "scope"} {
		if s, ok := claimString(claims, key); ok {
			out[key] = s
		}
	}
	if n, ok := claimInt(claims, "auth_time"); ok && n > 0 {
		out["auth_time"] = n
	}
	if amr, ok := claims["amr"].([]any); ok && len(amr) > 0 {
		out["amr"] = amr
	}
	return out
}

func (h *Handler) introspectRefresh(r *http.Request, client pgstore.Client, raw string) map[string]any {
	inactive := map[string]any{"active": false}
	current, err := h.sessions.GetRefresh(r.Context(), tokenHash(raw))
	if err != nil || current.Used {
		return inactive
	}
	as, err := h.sessions.GetApp(r.Context(), current.ASID)
	if err != nil || as.ClientID != client.ClientID {
		return inactive
	}
	gs, err := h.sessions.GetGlobal(r.Context(), as.SID)
	if err != nil || gs.AbsExp <= h.nowUnix() {
		return inactive
	}
	revoked, err := h.sessions.IsSIDRevoked(r.Context(), gs.SID)
	if err != nil || revoked {
		return inactive
	}
	life, err := h.store.Resolve(client)
	if err != nil || h.nowUnix() >= as.LastActive+int64(life.IdleTimeout) {
		return inactive
	}
	ttl, err := h.sessions.RefreshTTL(r.Context(), current.Hash)
	if err != nil || ttl <= 0 {
		return inactive
	}
	return map[string]any{
		"active":     true,
		"token_type": "refresh_token",
		"client_id":  client.ClientID,
		"sub":        gs.Sub,
		"sid":        gs.SID,
		"asid":       as.ASID,
		"exp":        h.nowUnix() + int64(ttl/time.Second),
	}
}

func (h *Handler) writeIntrospect(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func mustString(m map[string]any, key string) string {
	s, _ := claimString(m, key)
	return s
}

func mustInt(m map[string]any, key string) int64 {
	n, _ := claimInt(m, key)
	return n
}
