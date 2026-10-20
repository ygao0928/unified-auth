// Package redisstream 是 EventBus 的 Redis Streams 桩。
//
// 已做：向本机房的 auth:events XADD，再用 XRANGE 按调用方自己的游标读。不使用 consumer group。
// 未做（P4-BUS-01 / P4-BUS-02）：按 access_token_ttl_cap + clock_skew 裁剪、阻塞订阅、
// 把同一条事件写到其他机房、游标被裁掉之后的补拉。
package redisstream

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/ygao0928/unified-auth/auth-center/internal/eventbus"
)

// Bus 是单机房 Redis Stream。
type Bus struct {
	rdb redis.Cmdable
}

func New(rdb redis.Cmdable) *Bus {
	return &Bus{rdb: rdb}
}

var _ eventbus.Bus = (*Bus)(nil)

func (b *Bus) Publish(ctx context.Context, event eventbus.Event) (string, error) {
	if event.ID == "" || event.Name == "" {
		return "", errors.New("event id and name are required")
	}
	return b.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: eventbus.StreamName,
		Values: map[string]any{
			"id":      event.ID,
			"name":    event.Name,
			"payload": string(event.Data),
		},
	}).Result()
}

// ReadAfter 返回游标之后的事件。cursor 为空表示从头读。limit 必须大于 0。
// 这里用 XRANGE，不阻塞。一次最多向 Redis 取 limit+1 条，以便丢掉与游标相同的那条。
func (b *Bus) ReadAfter(ctx context.Context, cursor string, limit int64) ([]eventbus.Delivered, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be > 0")
	}
	start := "-"
	if cursor != "" {
		start = cursor
	}
	msgs, err := b.rdb.XRangeN(ctx, eventbus.StreamName, start, "+", limit+1).Result()
	if err != nil {
		return nil, err
	}
	out := make([]eventbus.Delivered, 0, len(msgs))
	for _, msg := range msgs {
		if msg.ID == cursor {
			continue
		}
		ev, err := decode(msg.Values)
		if err != nil {
			return nil, err
		}
		out = append(out, eventbus.Delivered{Cursor: msg.ID, Event: ev})
		if int64(len(out)) == limit {
			break
		}
	}
	return out, nil
}

func decode(values map[string]any) (eventbus.Event, error) {
	id, err := asString(values["id"])
	if err != nil {
		return eventbus.Event{}, fmt.Errorf("event id: %w", err)
	}
	name, err := asString(values["name"])
	if err != nil {
		return eventbus.Event{}, fmt.Errorf("event name: %w", err)
	}
	payload, err := asString(values["payload"])
	if err != nil {
		return eventbus.Event{}, fmt.Errorf("event payload: %w", err)
	}
	return eventbus.Event{ID: id, Name: name, Data: []byte(payload)}, nil
}

func asString(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("got %T", v)
	}
	return s, nil
}
