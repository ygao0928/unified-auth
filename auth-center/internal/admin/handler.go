// Package admin 提供应用注册 API。页面用 Vue3 还是 React 尚未决定，这里只做 HTTP。
package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"

	"github.com/ygao0928/unified-auth/auth-center/internal/apierr"
	"github.com/ygao0928/unified-auth/auth-center/internal/audit"
	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
)

const appsRegisterScope = "ua.apps.register"

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Deps 是管理接口的依赖。AdminToken 为空时，只接受带 ua.apps.register 的 m2m access token。
type Deps struct {
	Issuer     string
	DC         string
	ClockSkew  int
	AdminToken string
	Keys       *keys.Manager
	Store      *pgstore.Store
	Now        func() time.Time
	Logger     *slog.Logger
}

// Handler 注册、查询、更新客户端，并轮换只展示一次的密钥。
type Handler struct {
	issuer     string
	dc         string
	clockSkew  int
	adminToken string
	keys       *keys.Manager
	store      *pgstore.Store
	now        func() time.Time
	logger     *slog.Logger
}

// New 检查依赖。引导令牌可以空着，此时管理接口返回 401，进程仍可启动。
func New(d Deps) (*Handler, error) {
	if d.Issuer == "" || d.DC == "" || d.Keys == nil || d.Store == nil {
		return nil, errors.New("admin handler is incomplete")
	}
	if d.ClockSkew < 0 {
		return nil, errors.New("clock_skew must be >= 0")
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Handler{
		issuer: d.Issuer, dc: d.DC, clockSkew: d.ClockSkew, adminToken: d.AdminToken,
		keys: d.Keys, store: d.Store, now: d.Now, logger: d.Logger,
	}, nil
}

// Mount 注册应用管理路由。
func (h *Handler) Mount(r chi.Router) {
	r.Post("/api/v1/apps", h.create)
	r.Get("/api/v1/apps", h.list)
	r.Get("/api/v1/apps/{client_id}", h.get)
	r.Patch("/api/v1/apps/{client_id}", h.patch)
	r.Post("/api/v1/apps/{client_id}/secret", h.rotate)
}

type appBody struct {
	ClientID             string               `json:"client_id"`
	Name                 string               `json:"name"`
	ClientType           string               `json:"client_type"`
	RedirectURIs         []string             `json:"redirect_uris"`
	BackchannelLogoutURI string               `json:"backchannel_logout_uri,omitempty"`
	SessionPolicy        config.SessionPolicy `json:"session_policy"`
	Enabled              bool                 `json:"enabled"`
	Public               bool                 `json:"public"`
	ClientSecret         string               `json:"client_secret,omitempty"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authed(w, r)
	if !ok {
		return
	}
	var req struct {
		ClientID      string               `json:"client_id"`
		Name          string               `json:"name"`
		ClientType    string               `json:"client_type"`
		RedirectURIs  []string             `json:"redirect_uris"`
		Backchannel   *string              `json:"backchannel_logout_uri"`
		SessionPolicy config.SessionPolicy `json:"session_policy"`
		Public        bool                 `json:"public"`
	}
	if !h.readJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || req.ClientType == "" {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "name and client_type are required")
		return
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID != "" && !clientIDPattern.MatchString(clientID) {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client_id is invalid")
		return
	}
	if req.Public && !publicType(req.ClientType) {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "only web, app, and miniapp clients can be public")
		return
	}
	back := ""
	if req.Backchannel != nil {
		back = strings.TrimSpace(*req.Backchannel)
	}
	if req.RedirectURIs == nil {
		req.RedirectURIs = []string{}
	}
	if req.ClientType != config.ClientM2M && len(req.RedirectURIs) == 0 {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "redirect_uris is required")
		return
	}
	generated := clientID == ""
	if generated {
		var err error
		clientID, err = randomID("c_")
		if err != nil {
			h.fail(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client_id could not be generated")
			return
		}
	}
	c := pgstore.Client{
		ClientID: clientID, Name: name, ClientType: req.ClientType,
		RedirectURIs: req.RedirectURIs, SessionPolicy: req.SessionPolicy, Enabled: true,
		BackchannelLogoutURI: back,
	}
	if err := h.store.CheckClient(c); err != nil {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client registration is invalid")
		return
	}
	var secret string
	if !req.Public {
		var hash string
		var err error
		secret, hash, err = newSecret()
		if err != nil {
			h.fail(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client secret could not be generated")
			return
		}
		c.SecretHash = hash
	}
	if err := h.insert(r, &c, generated); err != nil {
		if errors.Is(err, pgstore.ErrConflict) {
			h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client_id already exists")
			return
		}
		h.logger.Error("create client", "trace_id", httpserver.TraceID(r.Context()))
		h.fail(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client store is unavailable")
		return
	}
	h.record(r, actor, "admin.app.created", c, nil)
	h.write(w, http.StatusCreated, view(c, secret))
}

func (h *Handler) insert(r *http.Request, c *pgstore.Client, generated bool) error {
	var last error
	for i := 0; i < 3; i++ {
		if i > 0 {
			if !generated {
				return last
			}
			id, err := randomID("c_")
			if err != nil {
				return err
			}
			c.ClientID = id
		}
		last = h.store.CreateClient(r.Context(), *c)
		if !errors.Is(last, pgstore.ErrConflict) {
			return last
		}
	}
	return last
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authed(w, r); !ok {
		return
	}
	clients, err := h.store.ListClients(r.Context())
	if err != nil {
		h.logger.Error("list clients", "trace_id", httpserver.TraceID(r.Context()))
		h.fail(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client store is unavailable")
		return
	}
	out := make([]appBody, 0, len(clients))
	for _, c := range clients {
		out = append(out, view(c, ""))
	}
	h.write(w, http.StatusOK, map[string]any{"apps": out})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authed(w, r); !ok {
		return
	}
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	h.write(w, http.StatusOK, view(c, ""))
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authed(w, r)
	if !ok {
		return
	}
	current, ok := h.load(w, r)
	if !ok {
		return
	}
	raw, ok := h.object(w, r)
	if !ok {
		return
	}
	if len(raw) == 0 {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "patch body is empty")
		return
	}
	allowed := map[string]bool{
		"name": true, "client_type": true, "redirect_uris": true,
		"backchannel_logout_uri": true, "session_policy": true, "enabled": true,
	}
	for key := range raw {
		if !allowed[key] {
			h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "patch contains an unknown field")
			return
		}
	}
	next := current
	fields := make([]string, 0, len(raw))
	if v, ok := raw["name"]; ok {
		var name string
		if err := json.Unmarshal(v, &name); err != nil {
			h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "name is invalid")
			return
		}
		next.Name = strings.TrimSpace(name)
		fields = append(fields, "name")
	}
	if v, ok := raw["client_type"]; ok {
		if err := json.Unmarshal(v, &next.ClientType); err != nil {
			h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client_type is invalid")
			return
		}
		fields = append(fields, "client_type")
	}
	if v, ok := raw["redirect_uris"]; ok {
		if err := json.Unmarshal(v, &next.RedirectURIs); err != nil || next.RedirectURIs == nil {
			h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "redirect_uris is invalid")
			return
		}
		fields = append(fields, "redirect_uris")
	}
	if v, ok := raw["backchannel_logout_uri"]; ok {
		var uri string
		if err := json.Unmarshal(v, &uri); err != nil {
			h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "backchannel_logout_uri is invalid")
			return
		}
		next.BackchannelLogoutURI = strings.TrimSpace(uri)
		fields = append(fields, "backchannel_logout_uri")
	}
	if v, ok := raw["session_policy"]; ok {
		dec := json.NewDecoder(strings.NewReader(string(v)))
		dec.DisallowUnknownFields()
		var policy config.SessionPolicy
		if err := dec.Decode(&policy); err != nil {
			h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "session_policy is invalid")
			return
		}
		next.SessionPolicy = policy
		fields = append(fields, "session_policy")
	}
	disabling := false
	if v, ok := raw["enabled"]; ok {
		if err := json.Unmarshal(v, &next.Enabled); err != nil {
			h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "enabled is invalid")
			return
		}
		disabling = current.Enabled && !next.Enabled
		fields = append(fields, "enabled")
	}
	if next.ClientType != config.ClientM2M && len(next.RedirectURIs) == 0 {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "redirect_uris is required")
		return
	}
	if next.SecretHash == "" && !publicType(next.ClientType) {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "ssr and m2m clients need a secret")
		return
	}
	if err := h.store.CheckClient(next); err != nil {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client registration is invalid")
		return
	}
	if err := h.store.UpdateClient(r.Context(), next); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			h.fail(w, r, http.StatusNotFound, apierr.CodeNotFound, "client not found")
			return
		}
		h.logger.Error("update client", "trace_id", httpserver.TraceID(r.Context()))
		h.fail(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client store is unavailable")
		return
	}
	event := "admin.app.updated"
	changes := map[string]any{"fields": fields}
	if disabling {
		event = "admin.app.disabled"
		changes = map[string]any{"enabled": false}
	}
	h.record(r, actor, event, next, changes)
	h.write(w, http.StatusOK, view(next, ""))
}

func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.authed(w, r)
	if !ok {
		return
	}
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	secret, hash, err := newSecret()
	if err != nil {
		h.fail(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client secret could not be generated")
		return
	}
	if err := h.store.SetClientSecret(r.Context(), c.ClientID, hash); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			h.fail(w, r, http.StatusNotFound, apierr.CodeNotFound, "client not found")
			return
		}
		h.logger.Error("rotate client secret", "trace_id", httpserver.TraceID(r.Context()))
		h.fail(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client store is unavailable")
		return
	}
	c.SecretHash = hash
	h.record(r, actor, "admin.app.secret_rotated", c, map[string]any{"rotated": true})
	h.write(w, http.StatusOK, view(c, secret))
}

func (h *Handler) load(w http.ResponseWriter, r *http.Request) (pgstore.Client, bool) {
	id := chi.URLParam(r, "client_id")
	if !clientIDPattern.MatchString(id) {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "client_id is invalid")
		return pgstore.Client{}, false
	}
	c, err := h.store.GetClient(r.Context(), id)
	if errors.Is(err, pgstore.ErrNotFound) {
		h.fail(w, r, http.StatusNotFound, apierr.CodeNotFound, "client not found")
		return pgstore.Client{}, false
	}
	if err != nil {
		h.logger.Error("load client", "trace_id", httpserver.TraceID(r.Context()))
		h.fail(w, r, http.StatusServiceUnavailable, apierr.CodeDependencyUnavailable, "client store is unavailable")
		return pgstore.Client{}, false
	}
	return c, true
}

func (h *Handler) authed(w http.ResponseWriter, r *http.Request) (audit.Actor, bool) {
	raw := bearer(r)
	if raw == "" {
		h.fail(w, r, http.StatusUnauthorized, apierr.CodeTokenMissing, "admin credential is required")
		return audit.Actor{}, false
	}
	if h.adminToken != "" && secretEqual(raw, h.adminToken) {
		return audit.Actor{Type: "system", ID: "admin"}, true
	}
	actor, ok := h.m2mActor(raw)
	if !ok {
		h.fail(w, r, http.StatusUnauthorized, apierr.CodeTokenInvalid, "admin credential is invalid")
		return audit.Actor{}, false
	}
	return actor, true
}

func (h *Handler) m2mActor(compact string) (audit.Actor, bool) {
	hdr, claims, err := h.keys.Verify(compact)
	if err != nil || !strings.EqualFold(headerTyp(hdr), "at+jwt") {
		return audit.Actor{}, false
	}
	iss, ok := claimString(claims, "iss")
	if !ok || iss != h.issuer {
		return audit.Actor{}, false
	}
	exp, ok := claimInt(claims, "exp")
	if !ok || h.nowUnix() > exp+int64(h.clockSkew) {
		return audit.Actor{}, false
	}
	if iat, ok := claimInt(claims, "iat"); ok && iat > h.nowUnix()+int64(h.clockSkew) {
		return audit.Actor{}, false
	}
	ct, ok := claimString(claims, "client_type")
	if !ok || ct != config.ClientM2M {
		return audit.Actor{}, false
	}
	scope, ok := claimString(claims, "scope")
	if !ok || !scopeHas(scope, appsRegisterScope) {
		return audit.Actor{}, false
	}
	id, _ := claimString(claims, "azp")
	if id == "" {
		sub, _ := claimString(claims, "sub")
		id = strings.TrimPrefix(sub, "client:")
	}
	if id == "" {
		id = "m2m"
	}
	return audit.Actor{Type: "client", ID: id}, true
}

func (h *Handler) record(r *http.Request, actor audit.Actor, event string, c pgstore.Client, changes map[string]any) {
	trace := httpserver.TraceID(r.Context())
	if trace == "" {
		trace = "unknown"
	}
	id, err := randomID("ae_")
	if err != nil {
		h.logger.Error("audit id", "trace_id", trace)
		return
	}
	ev := audit.Event{
		ID: id, TS: audit.FormatTime(h.nowTime()), Event: event,
		Actor: actor, Target: &audit.Target{Type: "app", ID: c.ClientID},
		ClientID: c.ClientID, ClientType: c.ClientType,
		Result: "success", Changes: changes, TraceID: trace, DC: h.dc,
	}
	raw, err := audit.Marshal(ev)
	if err != nil {
		h.logger.Error("audit encode", "event", event, "trace_id", trace)
		return
	}
	if err := h.store.AppendAudit(r.Context(), raw); err != nil {
		h.logger.Error("audit write", "event", event, "trace_id", trace)
	}
}

func (h *Handler) readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec, ok := h.decoder(w, r)
	if !ok {
		return false
	}
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "request body is invalid")
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "request body is invalid")
		return false
	}
	return true
}

func (h *Handler) object(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, bool) {
	dec, ok := h.decoder(w, r)
	if !ok {
		return nil, false
	}
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "request body is invalid")
		return nil, false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		h.fail(w, r, http.StatusBadRequest, apierr.CodeInvalidRequest, "request body is invalid")
		return nil, false
	}
	return raw, true
}

func (h *Handler) decoder(w http.ResponseWriter, r *http.Request) (*json.Decoder, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	return json.NewDecoder(r.Body), true
}

func (h *Handler) write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	apierr.Write(w, status, code, message, httpserver.TraceID(r.Context()), nil)
}

func (h *Handler) nowUnix() int64 { return h.nowTime().Unix() }

func (h *Handler) nowTime() time.Time {
	if h.now != nil {
		return h.now().UTC()
	}
	return time.Now().UTC()
}

func view(c pgstore.Client, secret string) appBody {
	uris := c.RedirectURIs
	if uris == nil {
		uris = []string{}
	}
	return appBody{
		ClientID: c.ClientID, Name: c.Name, ClientType: c.ClientType,
		RedirectURIs: uris, BackchannelLogoutURI: c.BackchannelLogoutURI,
		SessionPolicy: c.SessionPolicy, Enabled: c.Enabled, Public: c.IsPublic(),
		ClientSecret: secret,
	}
}

func publicType(clientType string) bool {
	switch clientType {
	case config.ClientWeb, config.ClientApp, config.ClientMiniApp:
		return true
	default:
		return false
	}
}

func newSecret() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	hash, err := pgstore.HashClientSecret(secret, 0)
	if err != nil {
		return "", "", err
	}
	return secret, hash, nil
}

func secretEqual(got, want string) bool {
	sumGot := sha256.Sum256([]byte(got))
	sumWant := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(sumGot[:], sumWant[:]) == 1
}

func bearer(r *http.Request) string {
	value := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(value[len(prefix):])
}

func scopeHas(scope, want string) bool {
	for _, part := range strings.Fields(scope) {
		if part == want {
			return true
		}
	}
	return false
}

func headerTyp(hdr jose.Header) string {
	v, ok := hdr.ExtraHeaders[jose.HeaderKey("typ")]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func claimString(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

func claimInt(m map[string]any, key string) (int64, bool) {
	v, ok := m[key]
	n, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int64(n), true
}

func randomID(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buf), nil
}
