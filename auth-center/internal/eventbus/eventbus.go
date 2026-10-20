package eventbus

import "context"

const (
	// EventRevoked 是吊销事件名，负载为 revocation-event.schema.json。
	EventRevoked = "auth.revoked"
	// EventAuthzChanged 是权限变更事件名。
	EventAuthzChanged = "authz.changed"
	// StreamName 是每个机房一条的 Redis Stream。Kafka 实现以后仍用同一接口，不使用这个键名。
	StreamName = "auth:events"
)

// Event 是 EventBus 上的一条记录。ID 是业务事件 ID（消费方按它去重），不是 Redis stream ID。
type Event struct {
	ID   string
	Name string
	Data []byte
}

// Delivered 把传输层游标和事件一起返回。Redis 实现里 Cursor 是 stream ID。
type Delivered struct {
	Cursor string
	Event  Event
}

// Bus 是可替换的事件通道。首期实现是 Redis Streams；Kafka 是以后的另一实现。
// 每个订阅者保存自己的游标，不共享 consumer group。
type Bus interface {
	Publish(ctx context.Context, event Event) (cursor string, err error)
	ReadAfter(ctx context.Context, cursor string, limit int64) ([]Delivered, error)
}
