package keys

import (
	"errors"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Verify 用 active 或 next 的公钥验签。不检查 typ、iss 或过期，调用方自己判断。
// 拒绝未知 kid、alg 与密钥不一致，以及 RS256 / ES256 以外的算法。
func (m *Manager) Verify(compact string) (jose.Header, map[string]any, error) {
	parsed, err := jwt.ParseSigned(compact, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil || len(parsed.Headers) != 1 {
		return jose.Header{}, nil, errors.New("token rejected")
	}
	hdr := parsed.Headers[0]
	jwk, ok := m.publicByKid(hdr.KeyID)
	if !ok || jwk.Algorithm != string(hdr.Algorithm) {
		return jose.Header{}, nil, errors.New("token rejected")
	}
	claims := map[string]any{}
	if err := parsed.Claims(jwk.Key, &claims); err != nil {
		return jose.Header{}, nil, errors.New("token rejected")
	}
	return hdr, claims, nil
}

func (m *Manager) publicByKid(kid string) (jose.JSONWebKey, bool) {
	if kid == "" {
		return jose.JSONWebKey{}, false
	}
	if m.active.KeyID == kid {
		return publicOf(m.active), true
	}
	if m.next != nil && m.next.KeyID == kid {
		return publicOf(*m.next), true
	}
	return jose.JSONWebKey{}, false
}
