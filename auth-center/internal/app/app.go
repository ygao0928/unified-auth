package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/migrate"
	"github.com/ygao0928/unified-auth/auth-center/internal/postgres"
	"github.com/ygao0928/unified-auth/auth-center/internal/redisx"
)

// Run 连接 PostgreSQL 和 Redis，执行迁移，然后启动 HTTP。
// 会话存储、EventBus 和上游适配器已有包，但授权码流程还没挂到路由上。
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	if err := cfg.ValidateForServe(); err != nil {
		return err
	}
	inputs := make([]keys.Input, 0, len(cfg.Keys))
	for _, k := range cfg.Keys {
		inputs = append(inputs, keys.Input{Kid: k.Kid, Alg: k.Alg, PEMFile: k.PEMFile, Role: k.Role})
	}
	km, err := keys.LoadFiles(inputs)
	if err != nil {
		return err
	}
	pool, err := postgres.Connect(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := migrate.Apply(ctx, pool); err != nil {
		return err
	}
	rdb := redisx.New(redisx.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB})
	defer rdb.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	pgErr := pool.Ping(pingCtx)
	redisErr := rdb.Ping(pingCtx).Err()
	cancel()
	if pgErr != nil {
		return fmt.Errorf("postgres: %w", pgErr)
	}
	if redisErr != nil {
		return fmt.Errorf("redis: %w", redisErr)
	}

	logger.Info("auth center starting",
		"issuer", cfg.Issuer,
		"dc", cfg.DC,
		"addr", cfg.HTTPAddr,
		"kids", km.Kids(),
		"access_token_ttl_cap", cfg.AccessTokenTTLCap,
		"previous_key_buffer", cfg.PreviousKeyBuffer,
		"clock_skew", cfg.ClockSkew,
	)
	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpserver.New(logger, km, []httpserver.Checker{
			{Name: "postgres", Ping: pool.Ping},
			{Name: "redis", Ping: func(ctx context.Context) error { return rdb.Ping(ctx).Err() }},
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
