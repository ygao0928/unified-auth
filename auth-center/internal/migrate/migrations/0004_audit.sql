-- 审计事件只追加。长期保存和查询审计本身再记一条，见 P7-AUD-01。
-- payload 是 audit-event.schema.json 的一条事件。

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    event TEXT NOT NULL,
    payload JSONB NOT NULL,
    CONSTRAINT audit_events_id_chk CHECK (length(id) > 0),
    CONSTRAINT audit_events_event_chk CHECK (length(event) > 0)
);

CREATE INDEX audit_events_event_ts_idx ON audit_events (event, ts);
