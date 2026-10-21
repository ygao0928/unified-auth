package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/ygao0928/unified-auth/auth-center/internal/admin"
	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"github.com/ygao0928/unified-auth/auth-center/internal/eventbus/redisstream"
	"github.com/ygao0928/unified-auth/auth-center/internal/httpserver"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
	"github.com/ygao0928/unified-auth/auth-center/internal/idp/oidc"
	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
	"github.com/ygao0928/unified-auth/auth-center/internal/migrate"
	"github.com/ygao0928/unified-auth/auth-center/internal/oauth"
	"github.com/ygao0928/unified-auth/auth-center/internal/pgstore"
	"github.com/ygao0928/unified-auth/auth-center/internal/postgres"
	"github.com/ygao0928/unified-auth/auth-center/internal/redisx"
	"github.com/ygao0928/unified-auth/auth-center/internal/session"
)

// Run 连接 PostgreSQL 和 Redis，执行迁移，发现已配置的 OIDC 上游，然后启动 HTTP。
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

	providers, err := loadProviders(ctx, cfg)
	if err != nil {
		return err
	}
	idpIDs := make([]string, 0, len(providers))
	for id := range providers {
		idpIDs = append(idpIDs, id)
	}
	sort.Strings(idpIDs)
	store := pgstore.New(pool, cfg.AccessTokenTTLCap, cfg.LifetimeDefaults())
	handler, err := oauth.New(oauth.Deps{
		Issuer: cfg.Issuer, DC: cfg.DC,
		Cap: cfg.AccessTokenTTLCap, ClockSkew: cfg.ClockSkew, Defaults: cfg.LifetimeDefaults(),
		AuthCodeTTL: time.Duration(cfg.AuthCodeTTL) * time.Second,
		TxnTTL:      time.Duration(cfg.AuthorizeTxnTTL) * time.Second,
		Keys:        km,
		Store:       store,
		Sessions:    session.New(rdb),
		IDPs:        providers,
		Bus:         redisstream.New(rdb),
		Logger:      logger,
	})
	if err != nil {
		return err
	}
	adminHandler, err := admin.New(admin.Deps{
		Issuer: cfg.Issuer, DC: cfg.DC, ClockSkew: cfg.ClockSkew, AdminToken: cfg.AdminToken,
		Keys: km, Store: store, Logger: logger,
	})
	if err != nil {
		return err
	}
	logger.Info("auth center starting",
		"issuer", cfg.Issuer,
		"dc", cfg.DC,
		"addr", cfg.HTTPAddr,
		"kids", km.Kids(),
		"idps", idpIDs,
		"access_token_ttl_cap", cfg.AccessTokenTTLCap,
		"user_access_token_ttl", cfg.UserAccessTokenTTL,
		"m2m_access_token_ttl", cfg.M2MAccessTokenTTL,
		"refresh_token_ttl", cfg.RefreshTokenTTL,
		"previous_key_buffer", cfg.PreviousKeyBuffer,
		"clock_skew", cfg.ClockSkew,
	)
	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpserver.New(logger, km, []httpserver.Checker{
			{Name: "postgres", Ping: pool.Ping},
			{Name: "redis", Ping: func(ctx context.Context) error { return rdb.Ping(ctx).Err() }},
		}, handler.Mount, adminHandler.Mount),
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

func loadProviders(ctx context.Context, cfg config.Config) (map[string]idp.IdentityProvider, error) {
	out := make(map[string]idp.IdentityProvider, len(cfg.IDPs))
	if len(cfg.IDPs) == 0 {
		return out, nil
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, item := range cfg.IDPs {
		adapter, err := oidc.New(oidc.Config{
			ID: item.ID, Issuer: item.Issuer, ClientID: item.ClientID, ClientSecret: item.ClientSecret,
			RedirectURL: item.RedirectURL, Scopes: item.Scopes,
			Mapping: oidc.Mapping{
				EmpNo: item.Mapping.EmpNo, Name: item.Mapping.Name, Email: item.Mapping.Email,
				Mobile: item.Mapping.Mobile, DeptID: item.Mapping.DeptID, DeptName: item.Mapping.DeptName,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("idp %s: %w", item.ID, err)
		}
		if err := adapter.Discover(dctx); err != nil {
			return nil, fmt.Errorf("idp %s: %w", item.ID, err)
		}
		out[adapter.ID()] = adapter
	}
	return out, nil
}
