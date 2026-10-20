package pgstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ygao0928/unified-auth/auth-center/internal/config"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrNotFound 表示行不存在。
	ErrNotFound = errors.New("not found")
	// ErrConflict 表示主键冲突。
	ErrConflict = errors.New("conflict")
)

// Client 是注册客户端。SessionPolicy 只存覆盖项，不把全局默认写回去。
// SecretHash 是 bcrypt 哈希。明文 secret 不入库。
type Client struct {
	ClientID      string
	Name          string
	ClientType    string
	SecretHash    string
	RedirectURIs  []string
	SessionPolicy config.SessionPolicy
	Enabled       bool
}

// User 是按工号落库的用户。PermVer 与 Disabled 不由登录更新改写。
type User struct {
	EmpNo    string
	Name     *string
	Email    *string
	Mobile   *string
	DeptID   *string
	DeptName *string
	PermVer  int
	Disabled bool
}

// Store 读写客户端和用户。运行中的上游身份源来自进程配置，不读 identity_providers 表。
type Store struct {
	pool     *pgxpool.Pool
	cap      int
	defaults config.LifetimeDefaults
}

func New(pool *pgxpool.Pool, accessTokenTTLCap int, defaults config.LifetimeDefaults) *Store {
	return &Store{pool: pool, cap: accessTokenTTLCap, defaults: defaults}
}

// Resolve 用进程里的全局默认和 cap 解析这个客户端的有效期。
func (s *Store) Resolve(c Client) (config.Lifetimes, error) {
	return config.ResolveLifetimes(c.ClientType, c.SessionPolicy, s.cap, s.defaults)
}

// HashClientSecret 用 bcrypt 保存客户端密钥。cost 为 0 时用 bcrypt 的默认成本。
func HashClientSecret(secret string, cost int) (string, error) {
	if secret == "" {
		return "", errors.New("client secret is required")
	}
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// SecretMatches 报告明文是否对得上 bcrypt 哈希。空哈希或空明文一律不匹配。
func (c Client) SecretMatches(secret string) bool {
	if c.SecretHash == "" || secret == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(secret)) == nil
}

// ValidateClient 检查注册字段。空的 redirect_uris 允许，注册接口再决定哪些客户端必须填。
func ValidateClient(c Client, accessTokenTTLCap int, defaults config.LifetimeDefaults) error {
	if c.ClientID == "" || c.Name == "" {
		return errors.New("client_id and name are required")
	}
	if !config.KnownClientType(c.ClientType) {
		return fmt.Errorf("unknown client_type %q", c.ClientType)
	}
	for _, raw := range c.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("redirect uri must be absolute")
		}
	}
	if _, err := config.ResolveLifetimes(c.ClientType, c.SessionPolicy, accessTokenTTLCap, defaults); err != nil {
		return err
	}
	return nil
}

func (s *Store) CreateClient(ctx context.Context, c Client) error {
	if err := ValidateClient(c, s.cap, s.defaults); err != nil {
		return err
	}
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	policy, err := json.Marshal(c.SessionPolicy)
	if err != nil {
		return err
	}
	var secret any
	if c.SecretHash != "" {
		secret = c.SecretHash
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO clients (client_id, name, client_type, secret_hash, redirect_uris, session_policy, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.ClientID, c.Name, c.ClientType, secret, c.RedirectURIs, policy, c.Enabled)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: client %s", ErrConflict, c.ClientID)
		}
		return err
	}
	return nil
}

func (s *Store) GetClient(ctx context.Context, clientID string) (Client, error) {
	var (
		c      Client
		secret *string
		policy []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, name, client_type, secret_hash, redirect_uris, session_policy, enabled
		FROM clients WHERE client_id = $1`, clientID).Scan(
		&c.ClientID, &c.Name, &c.ClientType, &secret, &c.RedirectURIs, &policy, &c.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, err
	}
	if secret != nil {
		c.SecretHash = *secret
	}
	dec := json.NewDecoder(bytes.NewReader(policy))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c.SessionPolicy); err != nil {
		return Client{}, fmt.Errorf("session_policy: %w", err)
	}
	return c, nil
}

// UpsertUserFromLogin 首次插入用户。再次登录只刷新非空属性，空值不覆盖已有值。
// 不授予默认角色，那是 P1-AC-03 尚未完成的部分。
func (s *Store) UpsertUserFromLogin(ctx context.Context, u User) error {
	if u.EmpNo == "" {
		return errors.New("emp_no is required")
	}
	u.Name = blankToNil(u.Name)
	u.Email = blankToNil(u.Email)
	u.Mobile = blankToNil(u.Mobile)
	u.DeptID = blankToNil(u.DeptID)
	u.DeptName = blankToNil(u.DeptName)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO users (emp_no, name, email, mobile, dept_id, dept_name)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (emp_no) DO UPDATE SET
			name = COALESCE(EXCLUDED.name, users.name),
			email = COALESCE(EXCLUDED.email, users.email),
			mobile = COALESCE(EXCLUDED.mobile, users.mobile),
			dept_id = COALESCE(EXCLUDED.dept_id, users.dept_id),
			dept_name = COALESCE(EXCLUDED.dept_name, users.dept_name),
			updated_at = now()`,
		u.EmpNo, u.Name, u.Email, u.Mobile, u.DeptID, u.DeptName)
	return err
}

func (s *Store) GetUser(ctx context.Context, empNo string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT emp_no, name, email, mobile, dept_id, dept_name, perm_ver, disabled
		FROM users WHERE emp_no = $1`, empNo).Scan(
		&u.EmpNo, &u.Name, &u.Email, &u.Mobile, &u.DeptID, &u.DeptName, &u.PermVer, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func blankToNil(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}
