package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ygao0928/unified-auth/auth-center/internal/audit"
	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgtest"
)

func TestAppendAndListAudit(t *testing.T) {
	pool := pgtest.Pool(t)
	store := New(pool, config.DefaultAccessTokenTTLCap, config.BuiltinLifetimeDefaults())
	ctx := context.Background()
	eventID := "ae_" + uniqueID(t)
	raw, err := audit.Marshal(audit.Event{
		ID: eventID, TS: audit.FormatTime(time.Unix(1_700_000_000, 123_000_000).UTC()),
		Event: "admin.app.created", Actor: audit.Actor{Type: "system", ID: "admin"},
		Target: &audit.Target{Type: "app", ID: "meeting"}, ClientID: "meeting", ClientType: "web",
		Result: "success", TraceID: "trace", DC: "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAudit(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAudit(ctx, []byte(`{"event":"nope"}`)); !errors.Is(err, ErrAuditRejected) {
		t.Fatalf("rejected: %v", err)
	}
	rows, err := store.ListAudit(ctx, "admin.app.created")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		var head struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(row, &head); err != nil {
			t.Fatal(err)
		}
		if head.ID == eventID {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing event in %d rows", len(rows))
	}
}
