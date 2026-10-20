package config

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// KeyFile 是一把签名密钥在配置里的位置。Kid 可以为空，此时从 PEM 文件首行注释读取。
type KeyFile struct {
	Kid     string `yaml:"kid"`
	Alg     string `yaml:"alg"`
	PEMFile string `yaml:"pem_file"`
	Role    string `yaml:"role"` // active 或 next
}

// Config 是认证中心进程配置。全局默认有效期不在这里，见 lifetimes.go。
type Config struct {
	Issuer            string
	DC                string
	HTTPAddr          string
	PostgresDSN       string
	RedisAddr         string
	RedisPassword     string
	RedisDB           int
	AccessTokenTTLCap int
	PreviousKeyBuffer int
	ClockSkew         int
	LogLevel          string
	Keys              []KeyFile
}

var dcPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Load 读取可选的 YAML 文件，再用环境变量覆盖。AUTH_CENTER_CONFIG 指向文件；未设置则只用环境变量和内置默认。
func Load() (Config, error) {
	return load(os.Getenv, os.Getenv("AUTH_CENTER_CONFIG"))
}

func load(getenv func(string) string, path string) (Config, error) {
	cfg := Config{
		HTTPAddr:          ":8080",
		AccessTokenTTLCap: DefaultAccessTokenTTLCap,
		PreviousKeyBuffer: DefaultPreviousKeyBuffer,
		ClockSkew:         DefaultClockSkew,
		LogLevel:          "info",
	}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return Config{}, fmt.Errorf("open config: %w", err)
		}
		defer f.Close()
		if err := applyFile(&cfg, f); err != nil {
			return Config{}, err
		}
	}
	if err := applyEnv(&cfg, getenv); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type fileConfig struct {
	Issuer            *string    `yaml:"issuer"`
	DC                *string    `yaml:"dc"`
	HTTP              *httpFile  `yaml:"http"`
	Postgres          *dsnFile   `yaml:"postgres"`
	Redis             *redisFile `yaml:"redis"`
	AccessTokenTTLCap *int       `yaml:"access_token_ttl_cap"`
	PreviousKeyBuffer *int       `yaml:"previous_key_buffer"`
	ClockSkew         *int       `yaml:"clock_skew"`
	Log               *logFile   `yaml:"log"`
	Keys              []KeyFile  `yaml:"keys"`
}

type httpFile struct {
	Addr *string `yaml:"addr"`
}

type dsnFile struct {
	DSN *string `yaml:"dsn"`
}

type redisFile struct {
	Addr     *string `yaml:"addr"`
	Password *string `yaml:"password"`
	DB       *int    `yaml:"db"`
}

type logFile struct {
	Level *string `yaml:"level"`
}

func applyFile(cfg *Config, r io.Reader) error {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var f fileConfig
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if f.Issuer != nil {
		cfg.Issuer = *f.Issuer
	}
	if f.DC != nil {
		cfg.DC = *f.DC
	}
	if f.HTTP != nil && f.HTTP.Addr != nil {
		cfg.HTTPAddr = *f.HTTP.Addr
	}
	if f.Postgres != nil && f.Postgres.DSN != nil {
		cfg.PostgresDSN = *f.Postgres.DSN
	}
	if f.Redis != nil {
		if f.Redis.Addr != nil {
			cfg.RedisAddr = *f.Redis.Addr
		}
		if f.Redis.Password != nil {
			cfg.RedisPassword = *f.Redis.Password
		}
		if f.Redis.DB != nil {
			cfg.RedisDB = *f.Redis.DB
		}
	}
	if f.AccessTokenTTLCap != nil {
		cfg.AccessTokenTTLCap = *f.AccessTokenTTLCap
	}
	if f.PreviousKeyBuffer != nil {
		cfg.PreviousKeyBuffer = *f.PreviousKeyBuffer
	}
	if f.ClockSkew != nil {
		cfg.ClockSkew = *f.ClockSkew
	}
	if f.Log != nil && f.Log.Level != nil {
		cfg.LogLevel = *f.Log.Level
	}
	if f.Keys != nil {
		cfg.Keys = f.Keys
	}
	return nil
}

func applyEnv(cfg *Config, getenv func(string) string) error {
	set := func(key string, dst *string) {
		if v := getenv(key); v != "" {
			*dst = v
		}
	}
	set("AUTH_CENTER_ISSUER", &cfg.Issuer)
	set("AUTH_CENTER_DC", &cfg.DC)
	set("AUTH_CENTER_HTTP_ADDR", &cfg.HTTPAddr)
	set("AUTH_CENTER_POSTGRES_DSN", &cfg.PostgresDSN)
	set("AUTH_CENTER_REDIS_ADDR", &cfg.RedisAddr)
	set("AUTH_CENTER_REDIS_PASSWORD", &cfg.RedisPassword)
	set("AUTH_CENTER_LOG_LEVEL", &cfg.LogLevel)
	if err := setInt(getenv, "AUTH_CENTER_REDIS_DB", &cfg.RedisDB); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_ACCESS_TOKEN_TTL_CAP", &cfg.AccessTokenTTLCap); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_PREVIOUS_KEY_BUFFER", &cfg.PreviousKeyBuffer); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_CLOCK_SKEW", &cfg.ClockSkew); err != nil {
		return err
	}
	if pemFile := getenv("AUTH_CENTER_KEY_ACTIVE_PEM_FILE"); pemFile != "" {
		keys := []KeyFile{{
			Kid:     getenv("AUTH_CENTER_KEY_ACTIVE_KID"),
			Alg:     getenv("AUTH_CENTER_KEY_ACTIVE_ALG"),
			PEMFile: pemFile,
			Role:    "active",
		}}
		if next := getenv("AUTH_CENTER_KEY_NEXT_PEM_FILE"); next != "" {
			keys = append(keys, KeyFile{
				Kid:     getenv("AUTH_CENTER_KEY_NEXT_KID"),
				Alg:     getenv("AUTH_CENTER_KEY_NEXT_ALG"),
				PEMFile: next,
				Role:    "next",
			})
		}
		cfg.Keys = keys
	}
	return nil
}

func setInt(getenv func(string) string, key string, dst *int) error {
	v := getenv(key)
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = n
	return nil
}

// Validate 检查与依赖无关的字段。密钥文件是否存在、是否为测试密钥，由 keys.LoadFiles 检查。
func (c Config) Validate() error {
	if err := validateIssuer(c.Issuer); err != nil {
		return err
	}
	if !dcPattern.MatchString(c.DC) {
		return fmt.Errorf("dc must match %s", dcPattern.String())
	}
	if c.HTTPAddr == "" {
		return fmt.Errorf("http addr is required")
	}
	if c.AccessTokenTTLCap < 1 {
		return fmt.Errorf("access_token_ttl_cap must be >= 1")
	}
	if c.PreviousKeyBuffer < 0 {
		return fmt.Errorf("previous_key_buffer must be >= 0")
	}
	if c.ClockSkew < 0 || c.ClockSkew > 300 {
		return fmt.Errorf("clock_skew must be between 0 and 300")
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log level must be debug, info, warn, or error")
	}
	if c.RedisDB < 0 {
		return fmt.Errorf("redis db must be >= 0")
	}
	return validateKeys(c.Keys, false)
}

// ValidateForServe 在 Validate 之上要求数据库、Redis 和恰好一把 active 密钥。
func (c Config) ValidateForServe() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.PostgresDSN == "" {
		return fmt.Errorf("postgres dsn is required")
	}
	if c.RedisAddr == "" {
		return fmt.Errorf("redis addr is required")
	}
	return validateKeys(c.Keys, true)
}

func validateIssuer(issuer string) error {
	if issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("issuer must be an absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("issuer scheme must be http or https")
	}
	if u.User != nil {
		return fmt.Errorf("issuer must not contain userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("issuer must not contain a query or fragment")
	}
	if strings.HasSuffix(issuer, "/") {
		return fmt.Errorf("issuer must not have a trailing slash")
	}
	return nil
}

func validateKeys(keys []KeyFile, requireActive bool) error {
	active, next := 0, 0
	for i, k := range keys {
		if k.PEMFile == "" {
			return fmt.Errorf("keys[%d]: pem_file is required", i)
		}
		if k.Alg != "RS256" && k.Alg != "ES256" {
			return fmt.Errorf("keys[%d]: alg must be RS256 or ES256", i)
		}
		switch k.Role {
		case "active":
			active++
		case "next":
			next++
		default:
			return fmt.Errorf("keys[%d]: role must be active or next", i)
		}
	}
	if active > 1 {
		return fmt.Errorf("at most one active signing key")
	}
	if next > 1 {
		return fmt.Errorf("at most one next signing key")
	}
	if requireActive && active != 1 {
		return fmt.Errorf("one active signing key is required")
	}
	return nil
}
