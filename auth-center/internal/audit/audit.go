// Package audit 构造并检查审计事件。事件形状以 spec/schemas/audit-event.schema.json 为准。
// 这里不选择 ES 或 ClickHouse。P1 把通过检查的 JSON 追加进 PostgreSQL。
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

// Event 是一条可落库的审计事件。Reason 用指针，成功时写成 null。
type Event struct {
	ID         string         `json:"id"`
	TS         string         `json:"ts"`
	Event      string         `json:"event"`
	Actor      Actor          `json:"actor"`
	Target     *Target        `json:"target,omitempty"`
	ClientID   string         `json:"client_id,omitempty"`
	ClientType string         `json:"client_type,omitempty"`
	IDP        string         `json:"idp,omitempty"`
	SID        string         `json:"sid,omitempty"`
	ASID       string         `json:"asid,omitempty"`
	IP         string         `json:"ip,omitempty"`
	UA         string         `json:"ua,omitempty"`
	Result     string         `json:"result"`
	Reason     *string        `json:"reason"`
	Changes    map[string]any `json:"changes,omitempty"`
	TraceID    string         `json:"trace_id"`
	DC         string         `json:"dc"`
}

type Actor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Target struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

var events = map[string]bool{
	"auth.login.success": true, "auth.login.failure": true, "auth.upstream.failure": true, "auth.logout": true,
	"session.expired": true, "session.kicked": true, "session.refresh_reused": true,
	"token.issued": true, "token.revoked": true, "token.exchanged": true,
	"authz.role.created": true, "authz.role.updated": true, "authz.role.deleted": true,
	"authz.user_role.granted": true, "authz.user_role.revoked": true, "authz.app_admin.changed": true,
	"authz.permissions.synced": true,
	"admin.app.created":        true, "admin.app.updated": true, "admin.app.secret_rotated": true, "admin.app.disabled": true,
	"admin.idp.updated": true, "admin.key.rotated": true,
	"audit.query": true, "openapi.call": true,
}

var actorTypes = map[string]bool{"user": true, "client": true, "system": true, "anonymous": true}
var targetTypes = map[string]bool{"user": true, "app": true, "role": true, "session": true, "app_session": true, "idp": true, "key": true, "permission": true}
var clientTypes = map[string]bool{"web": true, "ssr": true, "app": true, "miniapp": true, "m2m": true}

var forbiddenKeys = map[string]bool{
	"secret": true, "client_secret": true, "password": true, "token": true,
	"access_token": true, "refresh_token": true, "id_token": true, "logout_token": true,
	"ticket": true, "assertion": true, "code": true, "code_verifier": true, "verifier": true,
}

// FormatTime 写成 RFC 3339，带毫秒。UTC 用 Z。
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// Marshal 检查事件并返回 JSON。调用方不得把 token、密码或 ticket 放进字段。
func Marshal(e Event) ([]byte, error) {
	if err := check(e); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if err := Validate(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Validate 按 schema 的必填、枚举和禁止字段再查一遍已经编码的 JSON。
func Validate(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var e Event
	if err := dec.Decode(&e); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("audit event must be one json object")
		}
		return err
	}
	if err := check(e); err != nil {
		return err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return err
	}
	if forbidden(generic) {
		return errors.New("audit event contains a secret field")
	}
	return nil
}

func check(e Event) error {
	if e.ID == "" || e.TS == "" || e.TraceID == "" || e.DC == "" {
		return errors.New("audit id, ts, trace_id, and dc are required")
	}
	if _, err := time.Parse(time.RFC3339Nano, e.TS); err != nil {
		return errors.New("audit ts must be RFC3339")
	}
	if !events[e.Event] {
		return errors.New("audit event is not in the schema enum")
	}
	if !actorTypes[e.Actor.Type] || e.Actor.ID == "" {
		return errors.New("audit actor is invalid")
	}
	if e.Result != "success" && e.Result != "failure" {
		return errors.New("audit result is invalid")
	}
	if e.Target != nil && (!targetTypes[e.Target.Type] || e.Target.ID == "") {
		return errors.New("audit target is invalid")
	}
	if e.ClientType != "" && !clientTypes[e.ClientType] {
		return errors.New("audit client_type is invalid")
	}
	if len(e.UA) > 512 {
		return errors.New("audit ua is too long")
	}
	return nil
}

func forbidden(v any) bool {
	switch n := v.(type) {
	case map[string]any:
		for k, child := range n {
			if forbiddenKeys[strings.ToLower(k)] || forbidden(child) {
				return true
			}
		}
	case []any:
		for _, child := range n {
			if forbidden(child) {
				return true
			}
		}
	}
	return false
}
