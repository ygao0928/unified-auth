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
			Code   string `yaml:"code"`
			Status int    `yaml:"http_status"`
		} `yaml:"codes"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	have := map[string]int{}
	for _, c := range doc.Codes {
		have[c.Code] = c.Status
	}
	for _, code := range []string{CodeDependencyUnavailable, CodeNotFound, CodeInvalidRequest, CodeInvalidClient, CodeInternalError, CodeLoginRequired, CodeRefreshReused, CodeUpstreamFailed} {
		if _, ok := have[code]; !ok {
			t.Fatalf("code %s missing from spec", code)
		}
	}
	if have[CodeInvalidRequest] != http.StatusBadRequest || have[CodeInvalidClient] != http.StatusUnauthorized || have[CodeInternalError] != http.StatusInternalServerError {
		t.Fatalf("status %#v", have)
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
