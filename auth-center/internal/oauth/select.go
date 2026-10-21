package oauth

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

// 选择页只认这两种语言。都没有命中时用中文。
const (
	localeZH = "zh"
	localeEN = "en"
)

type selectCopy struct {
	Title        string
	Instruction  string
	Unknown      string
	Mismatch     string
	Upstream     string
	ExpiredTitle string
	Expired      string
}

var selectText = map[string]selectCopy{
	localeZH: {
		Title:        "选择登录方式",
		Instruction:  "请选择要使用的身份源。",
		Unknown:      "未知的身份源，请重新选择。",
		Mismatch:     "这次登录已经选定了其他身份源。",
		Upstream:     "暂时无法连接该身份源，请重试。",
		ExpiredTitle: "登录已失效",
		Expired:      "登录请求已过期或无效，请从应用重新发起。",
	},
	localeEN: {
		Title:        "Choose how to sign in",
		Instruction:  "Select an identity provider.",
		Unknown:      "That identity provider is not available. Choose another.",
		Mismatch:     "This sign-in is already bound to a different identity provider.",
		Upstream:     "That identity provider is unavailable. Try again.",
		ExpiredTitle: "Sign-in expired",
		Expired:      "This sign-in request expired or is invalid. Start again from the application.",
	},
}

type idpChoice struct {
	ID    string
	Label string
}

type selectPage struct {
	Lang        string
	Title       string
	Instruction string
	Error       string
	Tx          string
	Providers   []idpChoice
}

var selectTpl = template.Must(template.New("idp-select").Parse(`<!DOCTYPE html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
body{font-family:sans-serif;margin:2rem auto;max-width:28rem;color:#1a1a1a;padding:0 1rem}
h1{font-size:1.25rem}
form{margin:0.75rem 0}
button{font:inherit;padding:0.55rem 0.75rem;width:100%;text-align:left;cursor:pointer}
p.err{color:#8a1f11}
</style>
</head>
<body>
<h1>{{.Title}}</h1>
<p>{{.Instruction}}</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
{{range .Providers}}
<form method="post" action="/oauth2/authorize/idp">
<input type="hidden" name="tx" value="{{$.Tx}}">
<input type="hidden" name="idp" value="{{.ID}}">
<input type="hidden" name="lang" value="{{$.Lang}}">
<button type="submit">{{.Label}}</button>
</form>
{{end}}
</body>
</html>
`))

// startUpstream 保存已绑定身份源的授权事务，并跳到上游。
func (h *Handler) startUpstream(w http.ResponseWriter, r *http.Request, provider idp.IdentityProvider, clientID, redirectURI, state, nonce, challenge, scope string) {
	txID, err := randomHex(32)
	if err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "authorization could not be started")
		return
	}
	txn := session.AuthTxn{
		ID: txID, ClientID: clientID, RedirectURI: redirectURI, State: state,
		Nonce: nonce, CodeChallenge: challenge, Scope: scope, IDPID: provider.ID(),
	}
	if err := h.sessions.PutTxn(r.Context(), txn, h.TxnTTL); err != nil {
		h.logger.Error("save authorization transaction", "err", err.Error(), "trace_id", httpserver.TraceID(r.Context()))
		h.redirectErr(w, r, redirectURI, state, "server_error", "authorization could not be started")
		return
	}
	loc, err := provider.BuildLoginRedirect(r.Context(), txID)
	if err != nil {
		h.logger.Error("upstream redirect", "idp", provider.ID(), "trace_id", httpserver.TraceID(r.Context()))
		h.redirectErr(w, r, redirectURI, state, "server_error", "upstream identity provider is unavailable")
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

// startSelection 先保存尚未绑定身份源的授权事务，再渲染选择页。
// 刷新页面会再次进入授权端点，生成新事务；旧事务到期失效。
func (h *Handler) startSelection(w http.ResponseWriter, r *http.Request, clientID, redirectURI, state, nonce, challenge, scope string) {
	txID, err := randomHex(32)
	if err != nil {
		h.redirectErr(w, r, redirectURI, state, "server_error", "authorization could not be started")
		return
	}
	txn := session.AuthTxn{
		ID: txID, ClientID: clientID, RedirectURI: redirectURI, State: state,
		Nonce: nonce, CodeChallenge: challenge, Scope: scope,
	}
	if err := h.sessions.PutTxn(r.Context(), txn, h.TxnTTL); err != nil {
		h.logger.Error("save authorization transaction", "err", err.Error(), "trace_id", httpserver.TraceID(r.Context()))
		h.redirectErr(w, r, redirectURI, state, "server_error", "authorization could not be started")
		return
	}
	h.writeSelect(w, txn, http.StatusOK, "", pickLocale(r))
}

// chooseIDP 把选择页提交的身份源绑定到已有事务，再跳转上游。
// 不读取客户端重新提交的授权参数。事务不存在时不重定向。
func (h *Handler) chooseIDP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		h.writeExpired(w, localeFromAccept(r.Header.Get("Accept-Language")))
		return
	}
	lang := formLocale(r)
	txID := r.PostForm.Get("tx")
	idpID := r.PostForm.Get("idp")
	if txID == "" || len(txID) > 128 || idpID == "" || len(idpID) > maxParam {
		h.writeExpired(w, lang)
		return
	}
	txn, err := h.sessions.GetTxn(r.Context(), txID)
	if err != nil {
		if !errors.Is(err, session.ErrNotFound) {
			h.logger.Error("load authorization transaction", "err", err.Error(), "trace_id", httpserver.TraceID(r.Context()))
		}
		h.writeExpired(w, lang)
		return
	}
	if txn.IDPID != "" && txn.IDPID != idpID {
		h.writeSelect(w, txn, http.StatusBadRequest, "mismatch", lang)
		return
	}
	provider, ok := h.idps[idpID]
	if !ok {
		h.writeSelect(w, txn, http.StatusBadRequest, "unknown", lang)
		return
	}
	txn.IDPID = provider.ID()
	if err := h.sessions.PutTxn(r.Context(), txn, h.TxnTTL); err != nil {
		h.logger.Error("save authorization transaction", "err", err.Error(), "trace_id", httpserver.TraceID(r.Context()))
		h.writeSelect(w, txn, http.StatusServiceUnavailable, "upstream", lang)
		return
	}
	loc, err := provider.BuildLoginRedirect(r.Context(), txn.ID)
	if err != nil {
		h.logger.Error("upstream redirect", "idp", provider.ID(), "trace_id", httpserver.TraceID(r.Context()))
		h.writeSelect(w, txn, http.StatusServiceUnavailable, "upstream", lang)
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func (h *Handler) writeSelect(w http.ResponseWriter, txn session.AuthTxn, status int, kind, lang string) {
	if lang != localeEN {
		lang = localeZH
	}
	text := selectText[lang]
	page := selectPage{
		Lang: lang, Title: text.Title, Instruction: text.Instruction, Tx: txn.ID,
		Providers: h.idpChoices(""),
	}
	switch kind {
	case "unknown":
		page.Error = text.Unknown
	case "mismatch":
		page.Error = text.Mismatch
		page.Providers = h.idpChoices(txn.IDPID)
	case "upstream":
		page.Error = text.Upstream
		page.Providers = h.idpChoices(txn.IDPID)
	}
	h.writeHTML(w, status, page)
}

func (h *Handler) writeExpired(w http.ResponseWriter, lang string) {
	if lang != localeEN {
		lang = localeZH
	}
	text := selectText[lang]
	h.writeHTML(w, http.StatusBadRequest, selectPage{
		Lang: lang, Title: text.ExpiredTitle, Instruction: text.Expired,
	})
}

func (h *Handler) writeHTML(w http.ResponseWriter, status int, page selectPage) {
	var buf bytes.Buffer
	if err := selectTpl.Execute(&buf, page); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Referrer-Policy", "no-referrer")
	// 不限制 form-action。提交后会 302 到上游身份源，来源不固定。
	// form-action 'self' 会在浏览器里拦下这次跨源跳转。
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	hdr.Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// idpChoices 按身份源 ID 排序。onlyID 非空时只返回那一个，避免改绑。
func (h *Handler) idpChoices(onlyID string) []idpChoice {
	out := make([]idpChoice, 0, len(h.idps))
	for id, provider := range h.idps {
		if onlyID != "" && id != onlyID {
			continue
		}
		label := strings.TrimSpace(provider.DisplayName())
		if label == "" {
			label = id
		}
		out = append(out, idpChoice{ID: id, Label: label})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// pickLocale 先取 ui_locales 里第一个支持的标签，再看 Accept-Language，最后用中文。
func pickLocale(r *http.Request) string {
	for _, tag := range strings.Fields(r.URL.Query().Get("ui_locales")) {
		if loc := matchLocale(tag); loc != "" {
			return loc
		}
	}
	return localeFromAccept(r.Header.Get("Accept-Language"))
}

func formLocale(r *http.Request) string {
	switch r.PostForm.Get("lang") {
	case localeZH, localeEN:
		return r.PostForm.Get("lang")
	default:
		return localeFromAccept(r.Header.Get("Accept-Language"))
	}
}

func localeFromAccept(header string) string {
	type cand struct {
		lang string
		q    float64
		i    int
	}
	var cands []cand
	for i, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bits := strings.Split(part, ";")
		loc := matchLocale(bits[0])
		if loc == "" {
			continue
		}
		q := 1.0
		for _, param := range bits[1:] {
			param = strings.TrimSpace(param)
			if !strings.HasPrefix(param, "q=") {
				continue
			}
			if v, err := strconv.ParseFloat(strings.TrimPrefix(param, "q="), 64); err == nil {
				q = v
			}
		}
		cands = append(cands, cand{lang: loc, q: q, i: i})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].q == cands[j].q {
			return cands[i].i < cands[j].i
		}
		return cands[i].q > cands[j].q
	})
	if len(cands) == 0 {
		return localeZH
	}
	return cands[0].lang
}

func matchLocale(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" || tag == "*" {
		return ""
	}
	primary := tag
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		primary = tag[:i]
	}
	switch primary {
	case localeZH, localeEN:
		return primary
	default:
		return ""
	}
}
