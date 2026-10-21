package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ygao0928/unified-auth/auth-center/internal/audit"
)

// AppendAudit 追加一条已经通过 schema 检查的事件。没有更新或删除。
func (s *Store) AppendAudit(ctx context.Context, raw []byte) error {
	if err := audit.Validate(raw); err != nil {
		return fmt.Errorf("%w: %s", ErrAuditRejected, err.Error())
	}
	var head struct {
		ID    string `json:"id"`
		TS    string `json:"ts"`
		Event string `json:"event"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_events (id, ts, event, payload)
		VALUES ($1, $2::timestamptz, $3, $4::jsonb)`,
		head.ID, head.TS, head.Event, raw)
	return err
}

// ListAudit 按事件名返回 payload，时间升序。name 为空时返回全部。
func (s *Store) ListAudit(ctx context.Context, name string) ([]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT payload FROM audit_events
		WHERE ($1 = '' OR event = $1)
		ORDER BY ts, id`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(raw))
	}
	return out, rows.Err()
}

// ErrAuditRejected 表示事件没有通过检查，没有写入。
var ErrAuditRejected = errors.New("audit event rejected")
