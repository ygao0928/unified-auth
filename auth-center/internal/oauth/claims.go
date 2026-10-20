package oauth

import (
	"errors"
	"math"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

var (
	errTokenInvalid = errors.New("token invalid")
	errTokenExpired = errors.New("token expired")
	errTokenRevoked = errors.New("token revoked")
)

func claimString(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

func claimInt(m map[string]any, key string) (int64, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	n, ok := v.(float64)
	if !ok || n != math.Trunc(n) {
		return 0, false
	}
	return int64(n), true
}

func (h *Handler) expired(exp int64) bool {
	return h.nowUnix() > exp+int64(h.ClockSkew)
}

func (h *Handler) issuedInFuture(iat int64) bool {
	return iat > h.nowUnix()+int64(h.ClockSkew)
}

func headerTyp(hdr jose.Header) string {
	v, ok := hdr.ExtraHeaders[jose.HeaderKey("typ")]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func typEquals(hdr jose.Header, want string) bool {
	return strings.EqualFold(headerTyp(hdr), want)
}

// verifyAccess 验 at+jwt。过期与签名失败分开返回。不检查会话是否还在。
func (h *Handler) verifyAccess(compact string, allowExpired bool) (map[string]any, error) {
	hdr, claims, err := h.keys.Verify(compact)
	if err != nil || !typEquals(hdr, "at+jwt") {
		return nil, errTokenInvalid
	}
	iss, ok := claimString(claims, "iss")
	if !ok || iss != h.Issuer {
		return nil, errTokenInvalid
	}
	exp, ok := claimInt(claims, "exp")
	if !ok {
		return nil, errTokenInvalid
	}
	iat, ok := claimInt(claims, "iat")
	if !ok || h.issuedInFuture(iat) {
		return nil, errTokenInvalid
	}
	if !allowExpired && h.expired(exp) {
		return nil, errTokenExpired
	}
	for _, key := range []string{"sub", "aud", "jti", "azp", "client_type", "sid", "asid"} {
		if s, ok := claimString(claims, key); !ok || s == "" {
			return nil, errTokenInvalid
		}
	}
	perm, ok := claimInt(claims, "perm_ver")
	if !ok || perm < 0 {
		return nil, errTokenInvalid
	}
	return claims, nil
}
