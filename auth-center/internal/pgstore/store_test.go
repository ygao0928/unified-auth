package pgstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

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
	if err := ValidateClient(c, 1800); err != nil {
		t.Fatal(err)
	}
	c.ClientType = "desktop"
	if err := ValidateClient(c, 1800); err == nil {
		t.Fatal("bad type")
	}
	c.ClientType = config.ClientM2M
	refresh := 10
	c.SessionPolicy.RefreshTokenTTL = &refresh
	if err := ValidateClient(c, 1800); err == nil {
		t.Fatal("m2m refresh")
	}
}

func TestClientAndUserRoundTrip(t *testing.T) {
	pool := pgtest.Pool(t)
	if err := migrate.Apply(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	store := New(pool, config.DefaultAccessTokenTTLCap)
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
	resolved, err := config.ResolveLifetimes(got.ClientType, got.SessionPolicy, config.DefaultAccessTokenTTLCap)
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
}
