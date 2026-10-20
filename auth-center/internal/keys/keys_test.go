package keys

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestEmbeddedJWKSMatchesRepo(t *testing.T) {
	for _, name := range []string{"jwks.json", "jwks-rotated.json"} {
		embedded, err := forbiddenFS.ReadFile("forbidden/" + name)
		if err != nil {
			t.Fatal(err)
		}
		repo, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "keys", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(embedded, repo) {
			t.Fatalf("%s drifted from conformance/keys", name)
		}
	}
}

func TestGeneratedKeyPassesAndConformanceKeysFail(t *testing.T) {
	pemBytes, jwk, err := GenerateRSA("", 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "active.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := LoadFiles([]Input{{Alg: AlgRS256, PEMFile: path, Role: RoleActive}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := mgr.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != jwk.KeyID || set.Keys[0].Algorithm != AlgRS256 || set.Keys[0].Use != "sig" {
		t.Fatalf("jwks: %s", body)
	}
	if _, ok := set.Keys[0].Key.(*ecdsa.PublicKey); ok {
		t.Fatal("expected rsa public key")
	}

	jwk.KeyID = "rsa-1"
	if err := Check(jwk); err == nil {
		t.Fatal("kid rsa-1 was accepted")
	}

	repoPEM, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "keys", "rsa-1.private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	copied, err := ParsePrivatePEM(repoPEM, "not-the-test-kid", AlgRS256)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(copied); err == nil {
		t.Fatal("conformance public key was accepted under a new kid")
	}
	for _, tc := range []struct {
		file, kid, alg string
	}{
		{"ec-1.private.pem", "not-ec", AlgES256},
		{"attacker.private.pem", "not-attacker", AlgRS256},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "keys", tc.file))
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := ParsePrivatePEM(raw, tc.kid, tc.alg)
		if err != nil {
			t.Fatal(err)
		}
		if err := Check(jwk); err == nil {
			t.Fatalf("%s public key accepted", tc.file)
		}
	}
}

func TestEveryConformancePrivateKeyIsRejected(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "conformance", "keys")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, e := range entries {
		if !stringsHasSuffix(e.Name(), ".private.pem") {
			continue
		}
		kid := e.Name()[:len(e.Name())-len(".private.pem")]
		alg := AlgRS256
		if kid == "ec-1" {
			alg = AlgES256
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := ParsePrivatePEM(raw, kid, alg)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if err := Check(jwk); err == nil {
			t.Fatalf("%s was not rejected", e.Name())
		}
		n++
	}
	if n < 5 {
		t.Fatalf("expected rsa-1/2/3, ec-1, attacker; checked %d", n)
	}
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func TestSignSetsTypAndKid(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		alg string
		gen func(string) ([]byte, jose.JSONWebKey, error)
	}{
		{AlgRS256, func(kid string) ([]byte, jose.JSONWebKey, error) { return GenerateRSA(kid, 2048) }},
		{AlgES256, func(kid string) ([]byte, jose.JSONWebKey, error) { return GenerateES256(kid) }},
	} {
		pemBytes, _, err := tc.gen("kid-" + tc.alg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, tc.alg+".pem")
		if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		mgr, err := LoadFiles([]Input{{Alg: tc.alg, PEMFile: path, Role: RoleActive}})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := mgr.Sign(map[string]any{"iss": "https://auth.example.com", "exp": int64(10)}, "at+jwt")
		if err != nil {
			t.Fatal(err)
		}
		headerJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
		if err != nil {
			t.Fatal(err)
		}
		var header map[string]any
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			t.Fatal(err)
		}
		if header["typ"] != "at+jwt" || header["alg"] != tc.alg || header["kid"] != "kid-"+tc.alg {
			t.Fatalf("%s header %#v", tc.alg, header)
		}
		if mgr.ActiveAlgorithm() != tc.alg {
			t.Fatal(mgr.ActiveAlgorithm())
		}
	}
	if _, err := (&Manager{}).Sign(map[string]any{}, ""); err == nil {
		t.Fatal("empty typ")
	}
}

func TestRejectsSmallRSAAndBadAlg(t *testing.T) {
	if _, _, err := GenerateRSA("dev-small", 1024); err == nil {
		t.Fatal("1024 accepted")
	}
}
