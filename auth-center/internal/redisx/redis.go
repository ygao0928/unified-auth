package redisx

import "github.com/redis/go-redis/v9"

// Options 是 Redis 连接参数。
type Options struct {
	Addr     string
	Password string
	DB       int
}

// New 创建客户端。真正的连接发生在第一次命令。
func New(opt Options) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     opt.Addr,
		Password: opt.Password,
		DB:       opt.DB,
	})
}
