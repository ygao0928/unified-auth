package oauth

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
)

func TestReferenceValidatorAcceptsBothAlgorithms(t *testing.T) {
	now := int64(1_700_000_000)
	for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
		mgr := testManager(t, alg)
		raw, err := mgr.Sign(sampleClaims(now), "at+jwt")
		if err != nil {
			t.Fatal(err)
		}
		jwks, err := mgr.PublicJWKS()
		if err != nil {
			t.Fatal(err)
		}
		user := verifyReference(t, "https://auth.example.com", "meeting", 60, jwks, raw, now)
		if user["emp_no"] != "E10023" || user["client_id"] != "meeting" || user["perm_ver"] != float64(7) {
			t.Fatalf("%s user %#v", alg, user)
		}
		idToken, err := mgr.Sign(map[string]any{
			"iss": "https://auth.example.com", "sub": "E10023", "aud": "meeting",
			"exp": now + 600, "iat": now,
		}, "JWT")
		if err != nil {
			t.Fatal(err)
		}
		if code := referenceCode(t, "https://auth.example.com", "meeting", 60, jwks, idToken, now); code != "AUTH_TOKEN_INVALID" {
			t.Fatalf("%s id token code %s", alg, code)
		}
	}
}

func sampleClaims(now int64) map[string]any {
	return map[string]any{
		"iss": "https://auth.example.com", "sub": "E10023", "aud": "meeting",
		"exp": now + 600, "iat": now, "jti": "jti-1", "azp": "meeting",
		"client_type": "web", "perm_ver": 7, "sid": "bj1.abc", "asid": "as.1",
		"name": "张三", "amr": []string{"pwd"}, "auth_time": now - 10,
	}
}

func testManager(t *testing.T, alg string) *keys.Manager {
	t.Helper()
	var pemBytes []byte
	var err error
	if alg == keys.AlgES256 {
		pemBytes, _, err = keys.GenerateES256("kid-" + alg)
	} else {
		pemBytes, _, err = keys.GenerateRSA("kid-"+alg, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "active.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := keys.LoadFiles([]keys.Input{{Kid: "kid-" + alg, Alg: alg, PEMFile: path, Role: keys.RoleActive}})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func verifyReference(t *testing.T, issuer, clientID string, skew int, jwks []byte, token string, now int64) map[string]any {
	t.Helper()
	user, code := runReference(t, issuer, clientID, skew, jwks, token, now)
	if code != "" {
		t.Fatalf("reference validator: %s", code)
	}
	return user
}

func referenceCode(t *testing.T, issuer, clientID string, skew int, jwks []byte, token string, now int64) string {
	t.Helper()
	_, code := runReference(t, issuer, clientID, skew, jwks, token, now)
	return code
}

func runReference(t *testing.T, issuer, clientID string, skew int, jwks []byte, token string, now int64) (map[string]any, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"issuer": issuer, "client_id": clientID, "clock_skew": skew,
		"jwks": json.RawMessage(jwks), "token": token, "now": now,
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", referenceProgram, conformanceTools(t))
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reference.py: %v\n%s", err, out)
	}
	var resp struct {
		OK   bool           `json:"ok"`
		Code string         `json:"code"`
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("reference output: %s", out)
	}
	if resp.OK {
		return resp.User, ""
	}
	return nil, resp.Code
}

func conformanceTools(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "conformance", "tools")
		if _, err := os.Stat(filepath.Join(candidate, "reference.py")); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("conformance/tools/reference.py not found")
	return ""
}

const referenceProgram = `
import json, sys
sys.path.insert(0, sys.argv[1])
from reference import Verifier, AuthError
req = json.load(sys.stdin)
verifier = Verifier(
    issuer=req["issuer"],
    client_id=req["client_id"],
    clock_skew=int(req["clock_skew"]),
    jwks=req["jwks"],
    now=lambda: int(req["now"]),
)
try:
    json.dump({"ok": True, "user": verifier.verify(req["token"])}, sys.stdout)
except AuthError as exc:
    json.dump({"ok": False, "code": exc.code}, sys.stdout)
`
