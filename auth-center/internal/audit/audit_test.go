package audit

import (
	"strings"
	"testing"
	"time"
)

func TestMarshalRejectsSecrets(t *testing.T) {
	reason := "user_disabled"
	raw, err := Marshal(Event{
		ID: "ae_1", TS: FormatTime(time.Unix(1_700_000_000, 0).UTC()), Event: "auth.login.failure",
		Actor: Actor{Type: "user", ID: "E1"}, Result: "failure", Reason: &reason,
		TraceID: "trace", DC: "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"reason":"user_disabled"`) {
		t.Fatalf("%s", raw)
	}
	if err := Validate(raw); err != nil {
		t.Fatal(err)
	}
	bad := []byte(`{"id":"ae_1","ts":"2026-10-19T10:00:00.000Z","event":"auth.login.failure","actor":{"type":"user","id":"E1"},"result":"failure","reason":null,"trace_id":"t","dc":"local","changes":{"client_secret":"nope"}}`)
	if err := Validate(bad); err == nil {
		t.Fatal("secret field accepted")
	}
}
