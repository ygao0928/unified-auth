package redisstream

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/ygao0928/unified-auth/auth-center/internal/eventbus"
)

func TestPublishAndIndependentCursors(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	bus := New(rdb)
	ctx := context.Background()

	first, err := bus.Publish(ctx, eventbus.Event{ID: "rv_1", Name: eventbus.EventRevoked, Data: []byte(`{"id":"rv_1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := bus.Publish(ctx, eventbus.Event{ID: "az_1", Name: eventbus.EventAuthzChanged, Data: []byte(`{"id":"az_1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("stream ids collided")
	}

	a, err := bus.ReadAfter(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.ReadAfter(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 2 || len(b) != 2 || a[0].Event.ID != "rv_1" || a[1].Event.ID != "az_1" {
		t.Fatalf("a=%+v b=%+v", a, b)
	}
	if string(a[0].Event.Data) != `{"id":"rv_1"}` {
		t.Fatalf("payload %s", a[0].Event.Data)
	}

	rest, err := bus.ReadAfter(ctx, a[0].Cursor, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 1 || rest[0].Event.ID != "az_1" || rest[0].Cursor != second {
		t.Fatalf("after cursor: %+v", rest)
	}
	none, err := bus.ReadAfter(ctx, second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("tail: %+v", none)
	}
	if _, err := bus.Publish(ctx, eventbus.Event{}); err == nil {
		t.Fatal("empty event")
	}
	if _, err := bus.ReadAfter(ctx, "", 0); err == nil {
		t.Fatal("zero limit")
	}
}
