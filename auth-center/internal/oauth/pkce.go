package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// VerifyPKCE 按 RFC 7636 校验 S256。verifier 长度 43 到 128，字符集是 unreserved。
func VerifyPKCE(verifier, challenge string) error {
	if len(verifier) < 43 || len(verifier) > 128 {
		return errors.New("code_verifier length")
	}
	for _, c := range verifier {
		if !unreserved(c) {
			return errors.New("code_verifier charset")
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) != 1 {
		return errors.New("code_challenge mismatch")
	}
	return nil
}

func unreserved(c rune) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	default:
		return false
	}
}
