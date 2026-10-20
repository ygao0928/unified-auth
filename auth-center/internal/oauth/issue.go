package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func putString(dst map[string]any, key, value string) {
	if value != "" {
		dst[key] = value
	}
}

// issueTokens 签发 at+jwt、可选 ID Token，以及同一 family 里的新 refresh。
// family 为空时新建家族。调用方已经确认会话没过期。
func (h *Handler) issueTokens(ctx context.Context, client pgstore.Client, gs session.GlobalSession, as session.AppSession, nonce string, withID bool, family string) (tokenResponse, error) {
	user, err := h.store.GetUser(ctx, gs.Sub)
	if err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return tokenResponse{}, errLoginRequired
		}
		return tokenResponse{}, err
	}
	if user.Disabled || user.EmpNo == "" {
		return tokenResponse{}, errLoginRequired
	}
	life, err := h.store.Resolve(client)
	if err != nil {
		return tokenResponse{}, err
	}
	if !life.IssuesRefresh || life.AccessTokenTTL < 1 || life.RefreshTokenTTL < 1 {
		return tokenResponse{}, errInvalidGrant
	}
	meta, err := h.sessions.GetAuthMeta(ctx, as.ASID)
	if errors.Is(err, session.ErrNotFound) {
		meta = session.AuthMeta{}
	} else if err != nil {
		return tokenResponse{}, err
	}
	if family == "" {
		family, err = randomID("rf.")
		if err != nil {
			return tokenResponse{}, err
		}
	}
	jti, err := randomHex(16)
	if err != nil {
		return tokenResponse{}, err
	}
	rawRefresh, err := randomToken(32)
	if err != nil {
		return tokenResponse{}, err
	}
	now := h.nowUnix()
	claims := map[string]any{
		"iss":         h.Issuer,
		"sub":         user.EmpNo,
		"aud":         client.ClientID,
		"exp":         now + int64(life.AccessTokenTTL),
		"iat":         now,
		"jti":         jti,
		"azp":         client.ClientID,
		"client_type": client.ClientType,
		"perm_ver":    user.PermVer,
		"sid":         gs.SID,
		"asid":        as.ASID,
	}
	putString(claims, "name", deref(user.Name))
	putString(claims, "email", deref(user.Email))
	putString(claims, "dept_id", deref(user.DeptID))
	putString(claims, "dept_name", deref(user.DeptName))
	putString(claims, "scope", meta.Scope)
	if len(meta.AMR) > 0 {
		claims["amr"] = meta.AMR
	}
	if meta.AuthTime > 0 {
		claims["auth_time"] = meta.AuthTime
	}
	access, err := h.keys.Sign(claims, "at+jwt")
	if err != nil {
		return tokenResponse{}, err
	}
	var idToken string
	if withID && scopeContains(meta.Scope, "openid") {
		idClaims := map[string]any{
			"iss": h.Issuer,
			"sub": user.EmpNo,
			"aud": client.ClientID,
			"exp": now + int64(life.AccessTokenTTL),
			"iat": now,
		}
		putString(idClaims, "nonce", nonce)
		putString(idClaims, "name", deref(user.Name))
		putString(idClaims, "email", deref(user.Email))
		if meta.AuthTime > 0 {
			idClaims["auth_time"] = meta.AuthTime
		}
		if len(meta.AMR) > 0 {
			idClaims["amr"] = meta.AMR
		}
		idToken, err = h.keys.Sign(idClaims, "JWT")
		if err != nil {
			return tokenResponse{}, err
		}
	}
	if err := h.sessions.PutRefresh(ctx, session.Refresh{
		Hash: tokenHash(rawRefresh), ASID: as.ASID, FamilyID: family,
	}, seconds(life.RefreshTokenTTL)); err != nil {
		return tokenResponse{}, err
	}
	if err := h.sessions.Touch(ctx, gs.SID, as.ASID, now); err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    life.AccessTokenTTL,
		RefreshToken: rawRefresh,
		IDToken:      idToken,
		Scope:        meta.Scope,
	}, nil
}
