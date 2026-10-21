package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
)

func TestHealthReadyAndNotFound(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ok := Checker{Name: "postgres", Ping: func(context.Context) error { return nil }}
	h := New(logger, nil, []Checker{ok})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("health %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("traceparent") != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatal(rec.Header().Get("traceparent"))
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready %d %s", rec.Code, rec.Body.String())
	}

	bad := Checker{Name: "redis", Ping: func(context.Context) error { return errors.New("down") }}
	h = New(logger, nil, []Checker{ok, bad})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatal(rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != apierr.CodeDependencyUnavailable || body["trace_id"] == "" {
		t.Fatalf("%s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), apierr.CodeNotFound) {
		t.Fatalf("not found %d %s", rec.Code, rec.Body.String())
	}
}

func TestJWKS(t *testing.T) {
	pemBytes, _, err := keys.GenerateRSA("local-1", 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "active.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := keys.LoadFiles([]keys.Input{{Kid: "local-1", Alg: keys.AlgRS256, PEMFile: path, Role: keys.RoleActive}})
	if err != nil {
		t.Fatal(err)
	}
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), mgr, []Checker{{Name: "redis", Ping: func(context.Context) error { return nil }}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != JWKSCacheControl {
		t.Fatal(rec.Header().Get("Cache-Control"))
	}
	if !strings.Contains(rec.Body.String(), `"kid":"local-1"`) {
		t.Fatal(rec.Body.String())
	}
}

func TestRecover(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	rec := httptest.NewRecorder()
	inner := (&server{logger: logger}).recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("token secret")
	}))
	inner.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatal(rec.Code, rec.Header().Get("Content-Type"))
	}
	if strings.Contains(rec.Body.String(), "token secret") || !strings.Contains(rec.Body.String(), apierr.CodeInternalError) {
		t.Fatal(rec.Body.String())
	}
	if !strings.Contains(buf.String(), "token secret") {
		t.Fatal(buf.String())
	}
}
