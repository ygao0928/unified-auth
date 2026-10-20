package oauth

import (
	"net/http"

	"github.com/ygao0928/unified-auth/auth-center/internal/audit"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
)

// loginAudit 是一次上游登录的审计输入。不要放 token、授权码或密码。
type loginAudit struct {
	Event     string
	Result    string
	ActorType string
	ActorID   string
	Client    *pgstore.Client
	ClientID  string
	IDP       string
	SID       string
	Reason    string
}

// auditLogin 追加一条登录审计。写失败只记日志，不改变登录结果。
func (h *Handler) auditLogin(r *http.Request, in loginAudit) {
	trace := httpserver.TraceID(r.Context())
	if trace == "" {
		trace = "unknown"
	}
	id, err := randomID("ae_")
	if err != nil {
		h.logger.Error("audit id", "trace_id", trace)
		return
	}
	actorID := in.ActorID
	if actorID == "" {
		actorID = "unknown"
	}
	actorType := in.ActorType
	if actorType == "" {
		actorType = "anonymous"
	}
	ev := audit.Event{
		ID: id, TS: audit.FormatTime(h.nowTime()), Event: in.Event,
		Actor:   audit.Actor{Type: actorType, ID: actorID},
		Result:  in.Result,
		TraceID: trace,
		DC:      h.DC,
		IP:      clientIP(r),
		UA:      trim(r.UserAgent(), 512),
		IDP:     in.IDP,
		SID:     in.SID,
	}
	if in.Reason != "" {
		reason := in.Reason
		ev.Reason = &reason
	}
	clientID := in.ClientID
	if in.Client != nil {
		clientID = in.Client.ClientID
		ev.ClientType = in.Client.ClientType
	}
	if clientID != "" {
		ev.ClientID = clientID
		ev.Target = &audit.Target{Type: "app", ID: clientID}
	}
	raw, err := audit.Marshal(ev)
	if err != nil {
		h.logger.Error("audit encode", "event", in.Event, "trace_id", trace)
		return
	}
	if err := h.store.AppendAudit(r.Context(), raw); err != nil {
		h.logger.Error("audit write", "event", in.Event, "trace_id", trace)
	}
}
