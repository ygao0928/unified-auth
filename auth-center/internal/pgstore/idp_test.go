package pgstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
)

func TestIdentityProviderTable(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	id := "corp-oidc-" + hex.EncodeToString(buf[:])
	_, err := pool.Exec(ctx, `
		INSERT INTO identity_providers (id, protocol, display_name, config, attribute_mapping)
		VALUES ($1, 'OIDC', 'corp', '{"issuer":"https://idp.example.com"}', '{"emp_no":"employeeNumber"}')`, id)
	if err != nil {
		t.Fatal(err)
	}
	var protocol string
	if err := pool.QueryRow(ctx, `SELECT protocol FROM identity_providers WHERE id = $1`, id).Scan(&protocol); err != nil {
		t.Fatal(err)
	}
	if protocol != "OIDC" {
		t.Fatal(protocol)
	}
}
