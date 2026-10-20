package oauth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ygao0928/unified-auth/auth-center/internal/eventbus"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
)

func sessionRevoked(sid, sub, reason string) map[string]any {
	fields := map[string]any{"type": "session", "sid": sid, "reason": reason}
	if sub != "" {
		fields["sub"] = sub
	}
	return fields
}

func appSessionRevoked(asid, sid, sub, clientID string) map[string]any {
	fields := map[string]any{"type": "app_session", "asid": asid, "reason": "logout"}
	if sid != "" {
		fields["sid"] = sid
	}
	if sub != "" {
		fields["sub"] = sub
	}
	if clientID != "" {
		fields["client_id"] = clientID
	}
	return fields
}

// publishRevoked 往 EventBus 写 auth.revoked。没有总线或发布失败只记日志，不改变已经完成的登出或吊销。
func (h *Handler) publishRevoked(ctx context.Context, fields map[string]any) {
	if h.bus == nil {
		return
	}
	id, err := randomID("rv_")
	if err != nil {
		h.logger.Error("publish auth.revoked", "trace_id", httpserver.TraceID(ctx))
		return
	}
	fields["id"] = id
	fields["event"] = eventbus.EventRevoked
	fields["ts"] = h.nowUnix()
	if h.DC != "" {
		fields["dc"] = h.DC
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		h.logger.Error("publish auth.revoked", "trace_id", httpserver.TraceID(ctx))
		return
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if _, err := h.bus.Publish(pctx, eventbus.Event{ID: id, Name: eventbus.EventRevoked, Data: raw}); err != nil {
		h.logger.Error("publish auth.revoked", "trace_id", httpserver.TraceID(ctx))
	}
}
