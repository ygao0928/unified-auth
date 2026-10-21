package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
)

// JWKSCacheControl 与 OpenAPI 对 /oauth2/jwks 的要求一致。
const JWKSCacheControl = "max-age=600"

type traceKey struct{}

// Checker 是一项就绪检查。Name 出现在 503 的 details.dependencies 里。
type Checker struct {
	Name string
	Ping func(context.Context) error
}

// New 挂上健康检查、就绪检查和 JWKS。mounts 用来加上授权、令牌和 discovery，且走同一套 trace 与恢复中间件。
func New(logger *slog.Logger, km *keys.Manager, checks []Checker, mounts ...func(chi.Router)) http.Handler {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &server{logger: logger, keys: km, checks: checks}
	r := chi.NewRouter()
	r.Use(s.recover)
	r.Use(s.trace)
	r.Use(s.accessLog)
	r.Get("/healthz", s.health)
	r.Get("/readyz", s.ready)
	r.Get("/oauth2/jwks", s.jwks)
	for _, mount := range mounts {
		if mount != nil {
			mount(r)
		}
	}
	r.NotFound(s.notFound)
	return r
}

type server struct {
	logger *slog.Logger
	keys   *keys.Manager
	checks []Checker
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) ready(w http.ResponseWriter, r *http.Request) {
	if len(s.checks) == 0 {
		apierr.Write(w, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "dependency unavailable", TraceID(r.Context()), map[string]any{"dependencies": []string{"unconfigured"}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	var failed []string
	for _, c := range s.checks {
		if err := c.Ping(ctx); err != nil {
			s.logger.Warn("readiness check failed", "dependency", c.Name, "err", err.Error(), "trace_id", TraceID(r.Context()))
			failed = append(failed, c.Name)
		}
	}
	if len(failed) > 0 {
		apierr.Write(w, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "dependency unavailable", TraceID(r.Context()), map[string]any{"dependencies": failed})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *server) jwks(w http.ResponseWriter, r *http.Request) {
	if s.keys == nil {
		apierr.Write(w, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "signing keys are not loaded", TraceID(r.Context()), nil)
		return
	}
	body, err := s.keys.PublicJWKS()
	if err != nil {
		s.logger.Error("jwks", "err", err.Error(), "trace_id", TraceID(r.Context()))
		apierr.Write(w, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "signing keys are unavailable", TraceID(r.Context()), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", JWKSCacheControl)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *server) notFound(w http.ResponseWriter, r *http.Request) {
	apierr.Write(w, http.StatusNotFound, apierr.CodeNotFound, "not found", TraceID(r.Context()), nil)
}

func (s *server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic", "err", rec, "stack", string(debug.Stack()), "trace_id", TraceID(r.Context()))
				apierr.Write(w, http.StatusInternalServerError, apierr.CodeInternalError, "internal error", TraceID(r.Context()), nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *server) trace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid, span, ok := parseTraceparent(r.Header.Get("traceparent"))
		if !ok {
			tid = randomHex(16)
			span = randomHex(8)
		}
		w.Header().Set("traceparent", "00-"+tid+"-"+span+"-01")
		ctx := context.WithValue(r.Context(), traceKey{}, tid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"trace_id", TraceID(r.Context()),
		)
	})
}

// TraceID 返回中间件放进 context 的 trace id。授权和令牌处理函数用它填错误体。
func TraceID(ctx context.Context) string {
	v, _ := ctx.Value(traceKey{}).(string)
	return v
}

func parseTraceparent(raw string) (traceID, spanID string, ok bool) {
	parts := strings.Split(raw, "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 {
		return "", "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", "", false
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", n*2)
	}
	return hex.EncodeToString(buf)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Unwrap 让 http.ResponseController 仍能找到底层 ResponseWriter。
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
