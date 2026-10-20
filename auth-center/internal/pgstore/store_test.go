package pgstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/migrate"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
)

func uniqueID(t *testing.T) string {
	t.Helper()
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	return t.Name() + "-" + hex.EncodeToString(buf[:])
}

func TestValidateClient(t *testing.T) {
	ttl := 90
	c := Client{ClientID: "meeting", Name: "会议", ClientType: config.ClientWeb, RedirectURIs: []string{"https://meeting.example.com/cb"}, SessionPolicy: config.SessionPolicy{AccessTokenTTL: &ttl}, Enabled: true}
	defaults := config.BuiltinLifetimeDefaults()
	if err := ValidateClient(c, 1800, defaults); err != nil {
		t.Fatal(err)
	}
	c.ClientType = "desktop"
	if err := ValidateClient(c, 1800, defaults); err == nil {
		t.Fatal("bad type")
	}
	c.ClientType = config.ClientM2M
	refresh := 10
	c.SessionPolicy.RefreshTokenTTL = &refresh
	if err := ValidateClient(c, 1800, defaults); err == nil {
		t.Fatal("m2m refresh")
	}
}

func TestClientAndUserRoundTrip(t *testing.T) {
	pool := pgtest.Pool(t)
	if err := migrate.Apply(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	store := New(pool, config.DefaultAccessTokenTTLCap, config.BuiltinLifetimeDefaults())
	ctx := context.Background()
	ttl := 120
	c := Client{
		ClientID:      uniqueID(t),
		Name:          "会议",
		ClientType:    config.ClientWeb,
		SecretHash:    "opaque-hash",
		RedirectURIs:  []string{"https://meeting.example.com/cb"},
		SessionPolicy: config.SessionPolicy{AccessTokenTTL: &ttl},
		Enabled:       true,
	}
	if err := store.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateClient(ctx, c); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := store.GetClient(ctx, c.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SecretHash != c.SecretHash || got.ClientType != config.ClientWeb || !got.Enabled {
		t.Fatalf("%+v", got)
	}
	if got.SessionPolicy.AccessTokenTTL == nil || *got.SessionPolicy.AccessTokenTTL != 120 || got.SessionPolicy.RefreshTokenTTL != nil {
		t.Fatalf("policy %+v", got.SessionPolicy)
	}
	resolved, err := config.ResolveLifetimes(got.ClientType, got.SessionPolicy, config.DefaultAccessTokenTTLCap, config.BuiltinLifetimeDefaults())
	if err != nil {
		t.Fatal(err)
	}
	if resolved.AccessTokenTTL != 120 || resolved.RefreshTokenTTL != 600 {
		t.Fatalf("resolved %+v", resolved)
	}
	if _, err := store.GetClient(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	name := "张三"
	email := "a@example.com"
	emp := uniqueID(t)
	if err := store.UpsertUserFromLogin(ctx, User{EmpNo: emp, Name: &name, Email: &email}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET perm_ver = 4, disabled = true WHERE emp_no = $1`, emp); err != nil {
		t.Fatal(err)
	}
	empty := ""
	newEmail := "b@example.com"
	if err := store.UpsertUserFromLogin(ctx, User{EmpNo: emp, Name: &empty, Email: &newEmail}); err != nil {
		t.Fatal(err)
	}
	user, err := store.GetUser(ctx, emp)
	if err != nil {
		t.Fatal(err)
	}
	if user.Name == nil || *user.Name != "张三" || user.Email == nil || *user.Email != "b@example.com" {
		t.Fatalf("attrs %+v %v", user.Name, user.Email)
	}
	if user.PermVer != 4 || !user.Disabled {
		t.Fatalf("login overwrote perm_ver/disabled: %+v", user)
	}
	var (
		roles  int
		source string
		scope  string
		data   string
	)
	if err := pool.QueryRow(ctx, `
		SELECT count(*), min(ur.grant_source), min(r.scope), min(r.data_scope)
		FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.emp_no = $1 AND ur.role_id = $2`, emp, DefaultRoleViewer).Scan(&roles, &source, &scope, &data); err != nil {
		t.Fatal(err)
	}
	if roles != 1 || source != "default" || scope != "global" || data != "self" {
		t.Fatalf("default role roles=%d source=%s scope=%s data=%s", roles, source, scope, data)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM user_roles WHERE emp_no = $1`, emp); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertUserFromLogin(ctx, User{EmpNo: emp, Email: &newEmail}); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_roles WHERE emp_no = $1`, emp).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles != 0 {
		t.Fatalf("existing user was granted the default role again: %d", roles)
	}
}

func TestIsPublic(t *testing.T) {
	if !(Client{ClientType: config.ClientWeb}).IsPublic() {
		t.Fatal("web")
	}
	if !(Client{ClientType: config.ClientApp}).IsPublic() {
		t.Fatal("app")
	}
	if !(Client{ClientType: config.ClientMiniApp}).IsPublic() {
		t.Fatal("miniapp")
	}
	if (Client{ClientType: config.ClientWeb, SecretHash: "x"}).IsPublic() {
		t.Fatal("web with secret")
	}
	if (Client{ClientType: config.ClientSSR}).IsPublic() || (Client{ClientType: config.ClientM2M}).IsPublic() {
		t.Fatal("ssr or m2m")
	}
}

func TestClientSecretIsBcrypt(t *testing.T) {
	hash, err := HashClientSecret("s3cret", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if hash == "s3cret" || len(hash) < 20 {
		t.Fatal(hash)
	}
	c := Client{SecretHash: hash}
	if !c.SecretMatches("s3cret") || c.SecretMatches("other") || c.SecretMatches("") {
		t.Fatal("match")
	}
}
