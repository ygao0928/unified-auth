package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestJSONLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	logger := New("info", &buf)
	logger.Debug("hidden")
	logger.Info("visible", slog.String("trace_id", "abc"))
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Fatalf("debug leaked: %s", out)
	}
	if !strings.Contains(out, `"msg":"visible"`) || !strings.Contains(out, `"trace_id":"abc"`) {
		t.Fatalf("info log: %s", out)
	}
}
