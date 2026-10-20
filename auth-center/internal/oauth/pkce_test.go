package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := VerifyPKCE(verifier, challenge); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPKCE(verifier, challenge+"x"); err == nil {
		t.Fatal("mismatch accepted")
	}
	if err := VerifyPKCE("short", challenge); err == nil {
		t.Fatal("short verifier")
	}
	if err := VerifyPKCE(verifier+" ", challenge); err == nil {
		t.Fatal("space accepted")
	}
}
