package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

type backchannelTarget struct {
	URI      string
	ClientID string
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hint := q.Get("id_token_hint")
	clientID := q.Get("client_id")
	post := q.Get("post_logout_redirect_uri")
	state := q.Get("state")
	if len(state) > maxParam || len(post) > maxParam || len(clientID) > maxParam || len(hint) > 8192 {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "logout request is invalid", "invalid_request")
		return
	}
	var hintSID, hintAud, hintSub string
	if hint != "" {
		sid, aud, sub, ok := h.parseLogoutHint(hint)
		if !ok {
			h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "id_token_hint is invalid", "invalid_request")
			return
		}
		if clientID != "" && aud != clientID {
			h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client_id does not match id_token_hint", "invalid_request")
			return
		}
		hintSID, hintAud, hintSub = sid, aud, sub
	}
	if post != "" {
		id := clientID
		if id == "" {
			id = hintAud
		}
		if id == "" {
			h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client_id is required with post_logout_redirect_uri", "invalid_request")
			return
		}
		client, err := h.store.GetClient(r.Context(), id)
		if err != nil || !exactRedirect(client, post) {
			h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "post_logout_redirect_uri is not registered", "invalid_request")
			return
		}
	}

	sid := hintSID
	fromCookie := false
	if sid == "" {
		if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
			sid = c.Value
			fromCookie = true
		}
	}
	upstream := ""
	if sid != "" {
		var err error
		upstream, err = h.endGlobalSession(r, sid, hint != "", hintSub)
		if err != nil {
			h.logger.Error("end global session", "trace_id", httpserver.TraceID(r.Context()))
			h.writeErr(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "session store is unavailable", "temporarily_unavailable")
			return
		}
	}
	if fromCookie || (hintSID != "" && cookieSID(r) == hintSID) {
		h.clearSessionCookie(w)
	}
	if upstream != "" {
		if u, err := url.Parse(upstream); err == nil && u.Scheme != "" && u.Host != "" {
			http.Redirect(w, r, upstream, http.StatusFound)
			return
		}
	}
	if post != "" {
		h.redirectLogout(w, r, post, state)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) parseLogoutHint(compact string) (sid, aud, sub string, ok bool) {
	hdr, claims, err := h.keys.Verify(compact)
	if err != nil || (!typEquals(hdr, "JWT") && !typEquals(hdr, "at+jwt")) {
		return "", "", "", false
	}
	iss, issOK := claimString(claims, "iss")
	sid, sidOK := claimString(claims, "sid")
	aud, audOK := claimString(claims, "aud")
	if !issOK || iss != h.Issuer || !sidOK || !audOK {
		return "", "", "", false
	}
	sub, _ = claimString(claims, "sub")
	if iat, iatOK := claimInt(claims, "iat"); iatOK && h.issuedInFuture(iat) {
		return "", "", "", false
	}
	return sid, aud, sub, true
}

func (h *Handler) endGlobalSession(r *http.Request, sid string, hinted bool, hintSub string) (string, error) {
	gs, err := h.sessions.GetGlobal(r.Context(), sid)
	exists := err == nil
	if err != nil && !errors.Is(err, session.ErrNotFound) {
		return "", err
	}
	if !exists && !hinted {
		return "", nil
	}
	sub := hintSub
	upstreamURL := ""
	if exists {
		sub = gs.Sub
		if provider := h.idps[gs.IDP]; provider != nil {
			if loc, ok := provider.BuildLogoutRedirect(r.Context(), idp.LogoutHint{Subject: sub, SID: sid}); ok {
				upstreamURL = loc
			}
		}
	}
	targets, err := h.backchannelTargets(r.Context(), sid)
	if err != nil {
		return "", err
	}
	if err := h.sessions.RevokeChain(r.Context(), sid, h.retention()); err != nil {
		return "", err
	}
	h.publishRevoked(r.Context(), sessionRevoked(sid, sub, "logout"))
	h.notifyBackchannels(r.Context(), targets, sid, sub)
	return upstreamURL, nil
}

func (h *Handler) backchannelTargets(ctx context.Context, sid string) ([]backchannelTarget, error) {
	ids, err := h.sessions.ListAppIDs(ctx, sid)
	if err != nil {
		return nil, err
	}
	var out []backchannelTarget
	for _, asid := range ids {
		as, err := h.sessions.GetApp(ctx, asid)
		if errors.Is(err, session.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		client, err := h.store.GetClient(ctx, as.ClientID)
		if errors.Is(err, pgstore.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if client.BackchannelLogoutURI == "" {
			continue
		}
		out = append(out, backchannelTarget{URI: client.BackchannelLogoutURI, ClientID: client.ClientID})
	}
	return out, nil
}

func (h *Handler) notifyBackchannels(ctx context.Context, targets []backchannelTarget, sid, sub string) {
	if len(targets) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(target backchannelTarget) {
			defer wg.Done()
			h.postLogoutToken(ctx, target, sid, sub)
		}(target)
	}
	wg.Wait()
}

func (h *Handler) postLogoutToken(ctx context.Context, target backchannelTarget, sid, sub string) {
	jti, err := randomHex(16)
	if err != nil {
		h.logger.Error("backchannel logout", "trace_id", httpserver.TraceID(ctx))
		return
	}
	claims := map[string]any{
		"iss": h.Issuer,
		"aud": target.ClientID,
		"iat": h.nowUnix(),
		"jti": jti,
		"sid": sid,
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	if sub != "" {
		claims["sub"] = sub
	}
	tok, err := h.keys.Sign(claims, "logout+jwt")
	if err != nil {
		h.logger.Error("backchannel logout", "trace_id", httpserver.TraceID(ctx))
		return
	}
	form := url.Values{"logout_token": {tok}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URI, strings.NewReader(form.Encode()))
	if err != nil {
		h.logger.Error("backchannel logout", "trace_id", httpserver.TraceID(ctx))
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := h.httpClient.Do(req)
	if err != nil {
		h.logger.Error("backchannel logout", "trace_id", httpserver.TraceID(ctx))
		return
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		h.logger.Error("backchannel logout", "trace_id", httpserver.TraceID(ctx), "status", res.StatusCode)
	}
}

func (h *Handler) redirectLogout(w http.ResponseWriter, r *http.Request, post, state string) {
	u, err := url.Parse(post)
	if err != nil || u.Scheme == "" || u.Host == "" {
		h.writeErr(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "post_logout_redirect_uri is not registered", "invalid_request")
		return
	}
	if state != "" {
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func cookieSID(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
