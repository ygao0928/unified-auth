package apierr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCodesExistInSpec(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/error-codes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Codes []struct {
			Code string `yaml:"code"`
		} `yaml:"codes"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, c := range doc.Codes {
		have[c.Code] = true
	}
	for _, code := range []string{CodeDependencyUnavailable, CodeNotFound} {
		if !have[code] {
			t.Fatalf("code %s missing from spec", code)
		}
	}
}

func TestWriteShape(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusServiceUnavailable, CodeDependencyUnavailable, "dependency unavailable", "abc", map[string]any{"dependencies": []string{"redis"}})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatal(rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["code"] != CodeDependencyUnavailable || got["trace_id"] != "abc" || got["message"] != "dependency unavailable" {
		t.Fatalf("%s", rec.Body.String())
	}
}
