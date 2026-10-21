package oauth

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

func TestPickLocale(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?ui_locales=fr+en-US", nil)
	req.Header.Set("Accept-Language", "zh")
	if pickLocale(req) != localeEN {
		t.Fatal(pickLocale(req))
	}
	req = httptest.NewRequest(http.MethodGet, "/oauth2/authorize?ui_locales=zh-Hans+en", nil)
	req.Header.Set("Accept-Language", "en")
	if pickLocale(req) != localeZH {
		t.Fatal(pickLocale(req))
	}
	req = httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)
	req.Header.Set("Accept-Language", "fr,en;q=0.4,zh-CN;q=0.8")
	if pickLocale(req) != localeZH {
		t.Fatal(pickLocale(req))
	}
	req = httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)
	if pickLocale(req) != localeZH {
		t.Fatal(pickLocale(req))
	}
}

func TestAuthorizeIDPSelection(t *testing.T) {
	pool := pgtest.Pool(t)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	pemBytes, _, err := keys.GenerateRSA("select-key", 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/active.pem"
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := keys.LoadFiles([]keys.Input{{Alg: keys.AlgRS256, PEMFile: path, Role: keys.RoleActive}})
	if err != nil {
		t.Fatal(err)
	}
	store := pgstore.New(pool, 1800, config.BuiltinLifetimeDefaults())
	sess := session.New(rdb)
	var landed string
	clientSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landed = r.URL.String()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(clientSrv.Close)
	redirect := clientSrv.URL + "/cb"
	hash, err := pgstore.HashClientSecret("secret", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "sel-" + randomSuffix(t)
	if err := store.CreateClient(context.Background(), pgstore.Client{
		ClientID: clientID, Name: clientID, ClientType: config.ClientWeb, SecretHash: hash,
		RedirectURIs: []string{redirect}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	state := "state-state-state"
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	challenge := sha256Sum(verifier)
	xss := `<img src=x onerror=alert(1)>`

	newSrv := func(idps map[string]idp.IdentityProvider) *httptest.Server {
		t.Helper()
		srv := httptest.NewUnstartedServer(nil)
		handler, err := New(Deps{
			Issuer: "http://" + srv.Listener.Addr().String(), DC: "local", Cap: 1800, ClockSkew: 60,
			Defaults: config.BuiltinLifetimeDefaults(),
			Keys:     mgr, Store: store, Sessions: sess,
			IDPs:   idps,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if err != nil {
			t.Fatal(err)
		}
		srv.Config.Handler = httpserver.New(nil, mgr, nil, handler.Mount)
		srv.Start()
		t.Cleanup(srv.Close)
		return srv
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	follow := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == "idp.example" {
			return http.ErrUseLastResponse
		}
		return nil
	}}

	multi := newSrv(map[string]idp.IdentityProvider{
		"zeta": stubIDP{id: "zeta", name: "Zeta SSO"},
		"corp": stubIDP{id: "corp", name: xss},
	})

	pageURL := authorizeURL(multi.URL, clientID, redirect, state, verifier, "login")
	res, err := client.Get(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatal(ct)
	}
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal(res.Header)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "form-action") {
		t.Fatal(csp)
	}
	if !strings.Contains(body, "选择登录方式") || !strings.Contains(body, "Zeta SSO") {
		t.Fatalf("page %s", body)
	}
	if strings.Contains(body, "<img") || !strings.Contains(body, "&lt;img") {
		t.Fatal("display name was not escaped")
	}
	if strings.Contains(body, state) || strings.Contains(body, challenge) || strings.Contains(body, redirect) {
		t.Fatal("page echoed the authorize request")
	}
	corpAt := strings.Index(body, `name="idp" value="corp"`)
	zetaAt := strings.Index(body, `name="idp" value="zeta"`)
	if corpAt < 0 || zetaAt < 0 || corpAt > zetaAt {
		t.Fatalf("providers not sorted: corp %d zeta %d", corpAt, zetaAt)
	}
	tx := hiddenValue(t, body, "tx")
	got, err := sess.GetTxn(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if got.IDPID != "" || got.State != state || got.CodeChallenge != challenge || got.ClientID != clientID || got.RedirectURI != redirect || got.Scope != "openid profile" || got.Nonce != "nonce-nonce-nonce" {
		t.Fatalf("%+v", got)
	}

	again, err := client.Get(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	againBody := readBody(t, again)
	tx2 := hiddenValue(t, againBody, "tx")
	if tx2 == tx {
		t.Fatal("refresh reused the transaction")
	}
	if _, err := sess.GetTxn(context.Background(), tx); err != nil {
		t.Fatal(err)
	}

	bad := postIDP(t, client, multi.URL, tx, "missing", "")
	badBody := readBody(t, bad)
	if bad.StatusCode != http.StatusBadRequest || !strings.Contains(badBody, "未知的身份源") {
		t.Fatalf("unknown %d %s", bad.StatusCode, badBody)
	}
	still, err := sess.GetTxn(context.Background(), tx)
	if err != nil || still.IDPID != "" {
		t.Fatalf("bound on unknown %+v %v", still, err)
	}

	pick := postIDP(t, client, multi.URL, tx, "corp", "")
	if pick.StatusCode != http.StatusFound {
		t.Fatalf("pick %d %s", pick.StatusCode, readBody(t, pick))
	}
	loc, err := url.Parse(pick.Header.Get("Location"))
	if err != nil || loc.Query().Get("state") != tx || !strings.Contains(loc.Path, "/corp/login") {
		t.Fatal(pick.Header.Get("Location"))
	}
	bound, err := sess.GetTxn(context.Background(), tx)
	if err != nil || bound.IDPID != "corp" || bound.State != state {
		t.Fatalf("after pick %+v %v", bound, err)
	}

	repeat := postIDP(t, client, multi.URL, tx, "corp", localeEN)
	if repeat.StatusCode != http.StatusFound || !strings.Contains(repeat.Header.Get("Location"), tx) {
		t.Fatalf("repeat %d %s", repeat.StatusCode, repeat.Header.Get("Location"))
	}
	repeat.Body.Close()

	other := postIDP(t, client, multi.URL, tx, "zeta", localeEN)
	otherBody := readBody(t, other)
	if other.StatusCode != http.StatusBadRequest || !strings.Contains(otherBody, "already bound") || strings.Contains(otherBody, "Zeta SSO") {
		t.Fatalf("mismatch %d %s", other.StatusCode, otherBody)
	}
	kept, err := sess.GetTxn(context.Background(), tx)
	if err != nil || kept.IDPID != "corp" {
		t.Fatalf("mismatch changed %+v %v", kept, err)
	}

	expired := postIDP(t, client, multi.URL, "no-such-transaction", "corp", "")
	expiredBody := readBody(t, expired)
	if expired.StatusCode != http.StatusBadRequest || !strings.Contains(expiredBody, "登录已失效") || expired.Header.Get("Location") != "" {
		t.Fatalf("expired %d %s", expired.StatusCode, expiredBody)
	}
	if landed != "" {
		t.Fatalf("expired redirected to client %s", landed)
	}

	enReq, err := http.NewRequest(http.MethodGet, pageURL+"&ui_locales=en", nil)
	if err != nil {
		t.Fatal(err)
	}
	enReq.Header.Set("Accept-Language", "zh")
	enRes, err := client.Do(enReq)
	if err != nil {
		t.Fatal(err)
	}
	enBody := readBody(t, enRes)
	if !strings.Contains(enBody, "Choose how to sign in") || strings.Contains(enBody, "选择登录方式") {
		t.Fatal(enBody)
	}

	accReq, err := http.NewRequest(http.MethodGet, pageURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	accReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	accRes, err := client.Do(accReq)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readBody(t, accRes), "Choose how to sign in") {
		t.Fatal("accept-language")
	}

	before := mr.Keys()
	landed = ""
	hintRes, err := follow.Get(pageURL + "&idp_hint=zeta")
	if err != nil {
		t.Fatal(err)
	}
	hintRes.Body.Close()
	if hintRes.StatusCode != http.StatusFound || !strings.Contains(hintRes.Header.Get("Location"), "/zeta/login") {
		t.Fatalf("hint %d %s", hintRes.StatusCode, hintRes.Header.Get("Location"))
	}
	if landed != "" {
		t.Fatal(landed)
	}

	unknown := followGet(t, follow, pageURL+"&idp_hint=nope")
	u, err := url.Parse(unknown)
	if err != nil || u.Query().Get("error") != "invalid_request" {
		t.Fatal(unknown)
	}
	if extraTx(before, mr.Keys()) != 1 {
		t.Fatal("unknown hint stored a transaction")
	}

	before = mr.Keys()
	none := followGet(t, follow, authorizeURL(multi.URL, clientID, redirect, state, verifier, "none"))
	u, err = url.Parse(none)
	if err != nil || u.Query().Get("error") != "login_required" {
		t.Fatal(none)
	}
	if extraTx(before, mr.Keys()) != 0 {
		t.Fatal("prompt=none stored a transaction")
	}

	one := newSrv(map[string]idp.IdentityProvider{"only": stubIDP{id: "only", name: "Only"}})
	oneRes, err := client.Get(authorizeURL(one.URL, clientID, redirect, state, verifier, ""))
	if err != nil {
		t.Fatal(err)
	}
	oneBody := readBody(t, oneRes)
	if oneRes.StatusCode != http.StatusFound || strings.Contains(oneBody, "选择登录方式") || !strings.Contains(oneRes.Header.Get("Location"), "/only/login") {
		t.Fatalf("single %d %s %s", oneRes.StatusCode, oneRes.Header.Get("Location"), oneBody)
	}

	noneIDP := newSrv(nil)
	landed = ""
	missing := followGet(t, follow, authorizeURL(noneIDP.URL, clientID, redirect, state, verifier, ""))
	u, err = url.Parse(missing)
	if err != nil || u.Query().Get("error") != "temporarily_unavailable" {
		t.Fatal(missing)
	}
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func hiddenValue(t *testing.T, body, name string) string {
	t.Helper()
	needle := `name="` + name + `" value="`
	i := strings.Index(body, needle)
	if i < 0 {
		t.Fatalf("missing %s in %s", name, body)
	}
	rest := body[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatal(rest)
	}
	return rest[:j]
}

func postIDP(t *testing.T, client *http.Client, issuer, tx, idpID, lang string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("tx", tx)
	form.Set("idp", idpID)
	if lang != "" {
		form.Set("lang", lang)
	}
	req, err := http.NewRequest(http.MethodPost, issuer+"/oauth2/authorize/idp", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func followGet(t *testing.T, client *http.Client, raw string) string {
	t.Helper()
	res, err := client.Get(raw)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.Request.URL.String()
}

func extraTx(before, after []string) int {
	seen := map[string]bool{}
	for _, key := range before {
		seen[key] = true
	}
	n := 0
	for _, key := range after {
		if !seen[key] && strings.HasPrefix(key, "auth:tx:") {
			n++
		}
	}
	return n
}
