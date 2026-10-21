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

// AttributeMapping 把上游 claim 名映射到用户属性。EmpNo 必填。
type AttributeMapping struct {
	EmpNo    string `yaml:"emp_no"`
	Name     string `yaml:"name"`
	Email    string `yaml:"email"`
	Mobile   string `yaml:"mobile"`
	DeptID   string `yaml:"dept_id"`
	DeptName string `yaml:"dept_name"`
}

// IdentityProviderConfig 是一个上游身份源。P1 只接受 OIDC。
type IdentityProviderConfig struct {
	ID           string
	Protocol     string
	DisplayName  string
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Mapping      AttributeMapping
}

// Config 是认证中心进程配置。全局默认有效期有内置数字，也可以被 YAML 和环境变量覆盖。
type Config struct {
	Issuer                string
	DC                    string
	HTTPAddr              string
	PostgresDSN           string
	RedisAddr             string
	RedisPassword         string
	RedisDB               int
	AccessTokenTTLCap     int
	PreviousKeyBuffer     int
	ClockSkew             int
	UserAccessTokenTTL    int
	M2MAccessTokenTTL     int
	RefreshTokenTTL       int
	WebIdleTimeout        int
	WebAbsoluteSessionTTL int
	AppIdleTimeout        int
	AppAbsoluteSessionTTL int
	AuthCodeTTL           int
	AuthorizeTxnTTL       int
	LogLevel              string
	AdminToken            string
	Keys                  []KeyFile
	IDPs                  []IdentityProviderConfig
}

// LifetimeDefaults 返回这个进程当前的全局默认。
func (c Config) LifetimeDefaults() LifetimeDefaults {
	return LifetimeDefaults{
		UserAccessTokenTTL:    c.UserAccessTokenTTL,
		M2MAccessTokenTTL:     c.M2MAccessTokenTTL,
		RefreshTokenTTL:       c.RefreshTokenTTL,
		WebIdleTimeout:        c.WebIdleTimeout,
		WebAbsoluteSessionTTL: c.WebAbsoluteSessionTTL,
		AppIdleTimeout:        c.AppIdleTimeout,
		AppAbsoluteSessionTTL: c.AppAbsoluteSessionTTL,
	}
}

var dcPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Load 读取可选的 YAML 文件，再用环境变量覆盖。AUTH_CENTER_CONFIG 指向文件；未设置则只用环境变量和内置默认。
func Load() (Config, error) {
	return load(os.Getenv, os.Getenv("AUTH_CENTER_CONFIG"))
}

func load(getenv func(string) string, path string) (Config, error) {
	builtin := BuiltinLifetimeDefaults()
	cfg := Config{
		HTTPAddr:              ":8080",
		AccessTokenTTLCap:     DefaultAccessTokenTTLCap,
		PreviousKeyBuffer:     DefaultPreviousKeyBuffer,
		ClockSkew:             DefaultClockSkew,
		UserAccessTokenTTL:    builtin.UserAccessTokenTTL,
		M2MAccessTokenTTL:     builtin.M2MAccessTokenTTL,
		RefreshTokenTTL:       builtin.RefreshTokenTTL,
		WebIdleTimeout:        builtin.WebIdleTimeout,
		WebAbsoluteSessionTTL: builtin.WebAbsoluteSessionTTL,
		AppIdleTimeout:        builtin.AppIdleTimeout,
		AppAbsoluteSessionTTL: builtin.AppAbsoluteSessionTTL,
		AuthCodeTTL:           DefaultAuthCodeTTL,
		AuthorizeTxnTTL:       DefaultAuthorizeTxnTTL,
		LogLevel:              "info",
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
	for i := range cfg.IDPs {
		protocol := strings.ToUpper(strings.TrimSpace(cfg.IDPs[i].Protocol))
		if protocol == "" {
			protocol = "OIDC"
		}
		cfg.IDPs[i].Protocol = protocol
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type fileConfig struct {
	Issuer                *string    `yaml:"issuer"`
	DC                    *string    `yaml:"dc"`
	HTTP                  *httpFile  `yaml:"http"`
	Postgres              *dsnFile   `yaml:"postgres"`
	Redis                 *redisFile `yaml:"redis"`
	AccessTokenTTLCap     *int       `yaml:"access_token_ttl_cap"`
	PreviousKeyBuffer     *int       `yaml:"previous_key_buffer"`
	ClockSkew             *int       `yaml:"clock_skew"`
	UserAccessTokenTTL    *int       `yaml:"user_access_token_ttl"`
	M2MAccessTokenTTL     *int       `yaml:"m2m_access_token_ttl"`
	RefreshTokenTTL       *int       `yaml:"refresh_token_ttl"`
	WebIdleTimeout        *int       `yaml:"web_idle_timeout"`
	WebAbsoluteSessionTTL *int       `yaml:"web_absolute_session_ttl"`
	AppIdleTimeout        *int       `yaml:"app_idle_timeout"`
	AppAbsoluteSessionTTL *int       `yaml:"app_absolute_session_ttl"`
	AuthCodeTTL           *int       `yaml:"auth_code_ttl"`
	AuthorizeTxnTTL       *int       `yaml:"authorize_txn_ttl"`
	Log                   *logFile   `yaml:"log"`
	Keys                  []KeyFile  `yaml:"keys"`
	IDPs                  []idpFile  `yaml:"idps"`
}

type idpFile struct {
	ID           string           `yaml:"id"`
	Protocol     string           `yaml:"protocol"`
	DisplayName  string           `yaml:"display_name"`
	Issuer       string           `yaml:"issuer"`
	ClientID     string           `yaml:"client_id"`
	ClientSecret string           `yaml:"client_secret"`
	RedirectURL  string           `yaml:"redirect_url"`
	Scopes       []string         `yaml:"scopes"`
	Mapping      AttributeMapping `yaml:"attribute_mapping"`
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
	assignInt(f.UserAccessTokenTTL, &cfg.UserAccessTokenTTL)
	assignInt(f.M2MAccessTokenTTL, &cfg.M2MAccessTokenTTL)
	assignInt(f.RefreshTokenTTL, &cfg.RefreshTokenTTL)
	assignInt(f.WebIdleTimeout, &cfg.WebIdleTimeout)
	assignInt(f.WebAbsoluteSessionTTL, &cfg.WebAbsoluteSessionTTL)
	assignInt(f.AppIdleTimeout, &cfg.AppIdleTimeout)
	assignInt(f.AppAbsoluteSessionTTL, &cfg.AppAbsoluteSessionTTL)
	assignInt(f.AuthCodeTTL, &cfg.AuthCodeTTL)
	assignInt(f.AuthorizeTxnTTL, &cfg.AuthorizeTxnTTL)
	if f.Log != nil && f.Log.Level != nil {
		cfg.LogLevel = *f.Log.Level
	}
	if f.Keys != nil {
		cfg.Keys = f.Keys
	}
	if f.IDPs != nil {
		cfg.IDPs = make([]IdentityProviderConfig, 0, len(f.IDPs))
		for _, item := range f.IDPs {
			cfg.IDPs = append(cfg.IDPs, IdentityProviderConfig{
				ID: item.ID, Protocol: item.Protocol, DisplayName: item.DisplayName,
				Issuer: item.Issuer, ClientID: item.ClientID, ClientSecret: item.ClientSecret,
				RedirectURL: item.RedirectURL, Scopes: item.Scopes, Mapping: item.Mapping,
			})
		}
	}
	return nil
}

func assignInt(src *int, dst *int) {
	if src != nil {
		*dst = *src
	}
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
	set("AUTH_CENTER_ADMIN_TOKEN", &cfg.AdminToken)
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
	if err := setInt(getenv, "AUTH_CENTER_USER_ACCESS_TOKEN_TTL", &cfg.UserAccessTokenTTL); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_M2M_ACCESS_TOKEN_TTL", &cfg.M2MAccessTokenTTL); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_REFRESH_TOKEN_TTL", &cfg.RefreshTokenTTL); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_WEB_IDLE_TIMEOUT", &cfg.WebIdleTimeout); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_WEB_ABSOLUTE_SESSION_TTL", &cfg.WebAbsoluteSessionTTL); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_APP_IDLE_TIMEOUT", &cfg.AppIdleTimeout); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_APP_ABSOLUTE_SESSION_TTL", &cfg.AppAbsoluteSessionTTL); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_AUTH_CODE_TTL", &cfg.AuthCodeTTL); err != nil {
		return err
	}
	if err := setInt(getenv, "AUTH_CENTER_AUTHORIZE_TXN_TTL", &cfg.AuthorizeTxnTTL); err != nil {
		return err
	}
	if id := getenv("AUTH_CENTER_IDP_ID"); id != "" {
		scopes := strings.Fields(getenv("AUTH_CENTER_IDP_SCOPES"))
		cfg.IDPs = []IdentityProviderConfig{{
			ID:           id,
			Protocol:     getenv("AUTH_CENTER_IDP_PROTOCOL"),
			DisplayName:  getenv("AUTH_CENTER_IDP_DISPLAY_NAME"),
			Issuer:       getenv("AUTH_CENTER_IDP_ISSUER"),
			ClientID:     getenv("AUTH_CENTER_IDP_CLIENT_ID"),
			ClientSecret: getenv("AUTH_CENTER_IDP_CLIENT_SECRET"),
			RedirectURL:  getenv("AUTH_CENTER_IDP_REDIRECT_URL"),
			Scopes:       scopes,
			Mapping: AttributeMapping{
				EmpNo:    getenv("AUTH_CENTER_IDP_EMP_NO_CLAIM"),
				Name:     getenv("AUTH_CENTER_IDP_NAME_CLAIM"),
				Email:    getenv("AUTH_CENTER_IDP_EMAIL_CLAIM"),
				Mobile:   getenv("AUTH_CENTER_IDP_MOBILE_CLAIM"),
				DeptID:   getenv("AUTH_CENTER_IDP_DEPT_ID_CLAIM"),
				DeptName: getenv("AUTH_CENTER_IDP_DEPT_NAME_CLAIM"),
			},
		}}
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
	if err := c.LifetimeDefaults().Validate(); err != nil {
		return err
	}
	if c.AuthCodeTTL < 1 {
		return fmt.Errorf("auth_code_ttl must be >= 1")
	}
	if c.AuthorizeTxnTTL < 1 {
		return fmt.Errorf("authorize_txn_ttl must be >= 1")
	}
	if err := validateIDPs(c.IDPs); err != nil {
		return err
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

func validateIDPs(idps []IdentityProviderConfig) error {
	seen := map[string]bool{}
	for i, item := range idps {
		if item.ID == "" || !dcPattern.MatchString(item.ID) {
			return fmt.Errorf("idps[%d]: id must match %s", i, dcPattern.String())
		}
		if seen[item.ID] {
			return fmt.Errorf("idps[%d]: duplicate id %q", i, item.ID)
		}
		seen[item.ID] = true
		protocol := strings.ToUpper(strings.TrimSpace(item.Protocol))
		if protocol == "" {
			protocol = "OIDC"
		}
		if protocol != "OIDC" {
			return fmt.Errorf("idps[%d]: only OIDC upstream is implemented", i)
		}
		if err := absoluteHTTP("idps issuer", item.Issuer); err != nil {
			return fmt.Errorf("idps[%d]: %w", i, err)
		}
		if item.ClientID == "" || item.ClientSecret == "" {
			return fmt.Errorf("idps[%d]: client_id and client_secret are required", i)
		}
		if err := absoluteHTTP("idps redirect_url", item.RedirectURL); err != nil {
			return fmt.Errorf("idps[%d]: %w", i, err)
		}
		if item.Mapping.EmpNo == "" {
			return fmt.Errorf("idps[%d]: attribute_mapping.emp_no is required", i)
		}
	}
	return nil
}

func absoluteHTTP(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", name)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s scheme must be http or https", name)
	}
	return nil
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
