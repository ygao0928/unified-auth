package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// 键名与设计文档 §5.3.1 的代码块一致。
// auth:user:{sub}:sessions 是否按客户端类型再拆开，正文和代码块不一致，这里用代码块里的键。
// auth:revoked:sid 是整个集合一把 TTL；每加一个成员都会刷新这把 TTL。按成员过期的写法尚未决定。
//
// 设计图之外、授权码流程需要的键：
// auth:tx:{id}        授权事务，TTL 由调用方传入
// auth:code:{hash}    一次性授权码，hash 是原始 code 的 SHA-256 十六进制
// auth:rtfam:{family} 同一刷新家族里的 refresh hash
// auth:asfam:{asid}   应用会话当前的 family id
// auth:asmeta:{asid}  签发 access token 要用的 scope、amr、auth_time
// auth:gsmeta:{sid}   这次登录的 amr 与 auth_time，静默授权时复制到新的应用会话
const (
	fieldSub        = "sub"
	fieldIDP        = "idp"
	fieldCreatedAt  = "created_at"
	fieldLastActive = "last_active"
	fieldAbsExp     = "abs_exp"
	fieldIP         = "ip"
	fieldUA         = "ua"
	fieldSID        = "sid"
	fieldClientID   = "client_id"
	fieldClientType = "client_type"
	fieldASID       = "asid"
	fieldFamilyID   = "family_id"
	fieldUsed       = "used"
)

var ErrNotFound = errors.New("not found")

// GlobalSession 对应 auth:gs:{sid}。时间是 Unix 秒。
type GlobalSession struct {
	SID        string
	Sub        string
	IDP        string
	CreatedAt  int64
	LastActive int64
	AbsExp     int64
	IP         string
	UA         string
}

// AppSession 对应 auth:as:{asid}。
type AppSession struct {
	ASID       string
	SID        string
	ClientID   string
	ClientType string
	CreatedAt  int64
	LastActive int64
}

// Refresh 对应 auth:rt:{hash}。TTL 由调用方传入，必须等于该客户端的 refresh_token_ttl。
type Refresh struct {
	Hash     string
	ASID     string
	FamilyID string
	Used     bool
}

// UserSessionRef 是 auth:user:{sub}:sessions 里的一条，score 为 created_at。
type UserSessionRef struct {
	ASID      string
	CreatedAt int64
}

// redisAPI 同时覆盖普通命令和 EVAL。*redis.Client 满足它。
type redisAPI interface {
	redis.Cmdable
	redis.Scripter
}

// Store 读写 §5.3.1 的 Redis 键，以及授权码、刷新轮换要用的辅助键。
// 空闲和绝对时长的判断在令牌端点，不在这里。
type Store struct {
	rdb redisAPI
}

func New(rdb redisAPI) *Store {
	return &Store{rdb: rdb}
}

func GlobalKey(sid string) string           { return "auth:gs:" + sid }
func GlobalAppsKey(sid string) string       { return "auth:gs:" + sid + ":apps" }
func AppKey(asid string) string             { return "auth:as:" + asid }
func UserSessionsKey(sub string) string     { return "auth:user:" + sub + ":sessions" }
func RefreshKey(hash string) string         { return "auth:rt:" + hash }
func RevokedSIDKey() string                 { return "auth:revoked:sid" }
func TxnKey(id string) string               { return "auth:tx:" + id }
func CodeKey(hash string) string            { return "auth:code:" + hash }
func RefreshFamilyKey(family string) string { return "auth:rtfam:" + family }
func AppFamilyKey(asid string) string       { return "auth:asfam:" + asid }
func AuthMetaKey(asid string) string        { return "auth:asmeta:" + asid }
func LoginMetaKey(sid string) string        { return "auth:gsmeta:" + sid }

func (s *Store) PutGlobal(ctx context.Context, gs GlobalSession) error {
	if gs.SID == "" || gs.Sub == "" {
		return errors.New("sid and sub are required")
	}
	return s.rdb.HSet(ctx, GlobalKey(gs.SID), map[string]string{
		fieldSub:        gs.Sub,
		fieldIDP:        gs.IDP,
		fieldCreatedAt:  formatInt(gs.CreatedAt),
		fieldLastActive: formatInt(gs.LastActive),
		fieldAbsExp:     formatInt(gs.AbsExp),
		fieldIP:         gs.IP,
		fieldUA:         gs.UA,
	}).Err()
}

func (s *Store) GetGlobal(ctx context.Context, sid string) (GlobalSession, error) {
	m, err := s.rdb.HGetAll(ctx, GlobalKey(sid)).Result()
	if err != nil {
		return GlobalSession{}, err
	}
	if len(m) == 0 {
		return GlobalSession{}, ErrNotFound
	}
	created, err := parseInt(m[fieldCreatedAt])
	if err != nil {
		return GlobalSession{}, err
	}
	last, err := parseInt(m[fieldLastActive])
	if err != nil {
		return GlobalSession{}, err
	}
	abs, err := parseInt(m[fieldAbsExp])
	if err != nil {
		return GlobalSession{}, err
	}
	return GlobalSession{
		SID: sid, Sub: m[fieldSub], IDP: m[fieldIDP],
		CreatedAt: created, LastActive: last, AbsExp: abs,
		IP: m[fieldIP], UA: m[fieldUA],
	}, nil
}

func (s *Store) PutApp(ctx context.Context, as AppSession) error {
	if as.ASID == "" || as.SID == "" || as.ClientID == "" || as.ClientType == "" {
		return errors.New("asid, sid, client_id, and client_type are required")
	}
	if err := s.rdb.HSet(ctx, AppKey(as.ASID), map[string]string{
		fieldSID:        as.SID,
		fieldClientID:   as.ClientID,
		fieldClientType: as.ClientType,
		fieldCreatedAt:  formatInt(as.CreatedAt),
		fieldLastActive: formatInt(as.LastActive),
	}).Err(); err != nil {
		return err
	}
	return s.rdb.SAdd(ctx, GlobalAppsKey(as.SID), as.ASID).Err()
}

func (s *Store) GetApp(ctx context.Context, asid string) (AppSession, error) {
	m, err := s.rdb.HGetAll(ctx, AppKey(asid)).Result()
	if err != nil {
		return AppSession{}, err
	}
	if len(m) == 0 {
		return AppSession{}, ErrNotFound
	}
	created, err := parseInt(m[fieldCreatedAt])
	if err != nil {
		return AppSession{}, err
	}
	last, err := parseInt(m[fieldLastActive])
	if err != nil {
		return AppSession{}, err
	}
	return AppSession{
		ASID: asid, SID: m[fieldSID], ClientID: m[fieldClientID], ClientType: m[fieldClientType],
		CreatedAt: created, LastActive: last,
	}, nil
}

func (s *Store) ListAppIDs(ctx context.Context, sid string) ([]string, error) {
	return s.rdb.SMembers(ctx, GlobalAppsKey(sid)).Result()
}

func (s *Store) PutUserSession(ctx context.Context, sub, asid string, createdAt int64) error {
	if sub == "" || asid == "" {
		return errors.New("sub and asid are required")
	}
	return s.rdb.ZAdd(ctx, UserSessionsKey(sub), redis.Z{Score: float64(createdAt), Member: asid}).Err()
}

func (s *Store) UserSessions(ctx context.Context, sub string) ([]UserSessionRef, error) {
	rows, err := s.rdb.ZRangeWithScores(ctx, UserSessionsKey(sub), 0, -1).Result()
	if err != nil {
		return nil, err
	}
	out := make([]UserSessionRef, 0, len(rows))
	for _, row := range rows {
		member, ok := row.Member.(string)
		if !ok {
			return nil, fmt.Errorf("user session member %T", row.Member)
		}
		out = append(out, UserSessionRef{ASID: member, CreatedAt: int64(row.Score)})
	}
	return out, nil
}

// PutRefresh 写入 auth:rt:{hash}，并把 TTL 设为 ttl。ttl 必须是该客户端的 refresh_token_ttl。
func (s *Store) PutRefresh(ctx context.Context, rt Refresh, ttl time.Duration) error {
	if rt.Hash == "" || rt.ASID == "" || rt.FamilyID == "" {
		return errors.New("refresh hash, asid, and family_id are required")
	}
	if ttl <= 0 {
		return errors.New("refresh ttl must be > 0")
	}
	key := RefreshKey(rt.Hash)
	used := "0"
	if rt.Used {
		used = "1"
	}
	if err := s.rdb.HSet(ctx, key, map[string]string{
		fieldASID:     rt.ASID,
		fieldFamilyID: rt.FamilyID,
		fieldUsed:     used,
	}).Err(); err != nil {
		return err
	}
	ok, err := s.rdb.Expire(ctx, key, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("refresh key disappeared before expire")
	}
	if err := s.rdb.SAdd(ctx, RefreshFamilyKey(rt.FamilyID), rt.Hash).Err(); err != nil {
		return err
	}
	return s.rdb.Set(ctx, AppFamilyKey(rt.ASID), rt.FamilyID, 0).Err()
}

func (s *Store) GetRefresh(ctx context.Context, hash string) (Refresh, error) {
	m, err := s.rdb.HGetAll(ctx, RefreshKey(hash)).Result()
	if err != nil {
		return Refresh{}, err
	}
	if len(m) == 0 {
		return Refresh{}, ErrNotFound
	}
	return Refresh{Hash: hash, ASID: m[fieldASID], FamilyID: m[fieldFamilyID], Used: m[fieldUsed] == "1"}, nil
}

func (s *Store) RefreshTTL(ctx context.Context, hash string) (time.Duration, error) {
	return s.rdb.TTL(ctx, RefreshKey(hash)).Result()
}

// RememberRevokedSID 把 sid 放进 auth:revoked:sid，并把整个集合的 TTL 设为 ttl。
// ttl 应使用 access_token_ttl_cap + clock_skew。这不是强制下线流程。
func (s *Store) RememberRevokedSID(ctx context.Context, sid string, ttl time.Duration) error {
	if sid == "" {
		return errors.New("sid is required")
	}
	if ttl <= 0 {
		return errors.New("revocation ttl must be > 0")
	}
	if err := s.rdb.SAdd(ctx, RevokedSIDKey(), sid).Err(); err != nil {
		return err
	}
	_, err := s.rdb.Expire(ctx, RevokedSIDKey(), ttl).Result()
	return err
}

func (s *Store) IsSIDRevoked(ctx context.Context, sid string) (bool, error) {
	return s.rdb.SIsMember(ctx, RevokedSIDKey(), sid).Result()
}

// Touch 更新全局会话和应用会话的 last_active，不改其他字段，也不改 refresh TTL。
func (s *Store) Touch(ctx context.Context, sid, asid string, lastActive int64) error {
	if sid == "" || asid == "" {
		return errors.New("sid and asid are required")
	}
	if err := s.rdb.HSet(ctx, GlobalKey(sid), fieldLastActive, formatInt(lastActive)).Err(); err != nil {
		return err
	}
	return s.rdb.HSet(ctx, AppKey(asid), fieldLastActive, formatInt(lastActive)).Err()
}

// ConsumeResult 是刷新令牌原子消费的结果。
type ConsumeResult int

const (
	// ConsumeMissing 表示键不存在或已过期。
	ConsumeMissing ConsumeResult = 0
	// ConsumeOK 表示本次成功把它标成已使用，且没有延长 TTL。
	ConsumeOK ConsumeResult = 1
	// ConsumeReused 表示它已经被使用过。
	ConsumeReused ConsumeResult = 2
)

var consumeRefreshScript = `
local key = KEYS[1]
if redis.call('EXISTS', key) == 0 then
  return {0, '', ''}
end
local used = redis.call('HGET', key, 'used')
local asid = redis.call('HGET', key, 'asid') or ''
local family = redis.call('HGET', key, 'family_id') or ''
if used == '1' then
  return {2, asid, family}
end
redis.call('HSET', key, 'used', '1')
return {1, asid, family}
`

// ConsumeRefresh 原子地把 refresh 标成已使用。不调用 EXPIRE，所以剩余 TTL 保持不变。
func (s *Store) ConsumeRefresh(ctx context.Context, hash string) (ConsumeResult, Refresh, error) {
	if hash == "" {
		return ConsumeMissing, Refresh{}, errors.New("refresh hash is required")
	}
	val, err := s.rdb.Eval(ctx, consumeRefreshScript, []string{RefreshKey(hash)}).Result()
	if err != nil {
		return ConsumeMissing, Refresh{}, err
	}
	items, ok := val.([]any)
	if !ok || len(items) != 3 {
		return ConsumeMissing, Refresh{}, fmt.Errorf("refresh consume returned %T", val)
	}
	code, err := luaInt(items[0])
	if err != nil {
		return ConsumeMissing, Refresh{}, err
	}
	rt := Refresh{Hash: hash, ASID: luaString(items[1]), FamilyID: luaString(items[2]), Used: code != int64(ConsumeOK)}
	return ConsumeResult(code), rt, nil
}

var takeStringScript = `
local v = redis.call('GET', KEYS[1])
if not v then
  return ''
end
redis.call('DEL', KEYS[1])
return v
`

// AuthTxn 是跳到上游之前暂存的授权请求。ID 同时作为上游的 state。
type AuthTxn struct {
	ID            string `json:"-"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
	Nonce         string `json:"nonce,omitempty"`
	CodeChallenge string `json:"code_challenge"`
	Scope         string `json:"scope"`
	IDPID         string `json:"idp_id"`
}

// AuthCode 是一次性授权码里保存的内容。Redis 键是原始 code 的哈希。
type AuthCode struct {
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	CodeChallenge string   `json:"code_challenge"`
	Scope         string   `json:"scope"`
	Nonce         string   `json:"nonce,omitempty"`
	SID           string   `json:"sid"`
	ASID          string   `json:"asid"`
	Sub           string   `json:"sub"`
	AuthTime      int64    `json:"auth_time,omitempty"`
	AMR           []string `json:"amr,omitempty"`
}

// AuthMeta 挂在应用会话上，刷新时还要能填回 access token。
type AuthMeta struct {
	AuthTime int64    `json:"auth_time,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	Scope    string   `json:"scope,omitempty"`
}

// LoginMeta 挂在全局会话上，静默授权时复制到新的应用会话。
type LoginMeta struct {
	AuthTime int64    `json:"auth_time,omitempty"`
	AMR      []string `json:"amr,omitempty"`
}

func (s *Store) PutTxn(ctx context.Context, txn AuthTxn, ttl time.Duration) error {
	if txn.ID == "" || txn.ClientID == "" || txn.RedirectURI == "" {
		return errors.New("txn id, client_id, and redirect_uri are required")
	}
	return s.putJSON(ctx, TxnKey(txn.ID), txn, ttl)
}

func (s *Store) TakeTxn(ctx context.Context, id string) (AuthTxn, error) {
	var txn AuthTxn
	if err := s.takeJSON(ctx, TxnKey(id), &txn); err != nil {
		return AuthTxn{}, err
	}
	txn.ID = id
	return txn, nil
}

func (s *Store) PutCode(ctx context.Context, hash string, code AuthCode, ttl time.Duration) error {
	if hash == "" || code.ClientID == "" || code.SID == "" || code.ASID == "" {
		return errors.New("code hash, client_id, sid, and asid are required")
	}
	return s.putJSON(ctx, CodeKey(hash), code, ttl)
}

func (s *Store) TakeCode(ctx context.Context, hash string) (AuthCode, error) {
	var code AuthCode
	if err := s.takeJSON(ctx, CodeKey(hash), &code); err != nil {
		return AuthCode{}, err
	}
	return code, nil
}

func (s *Store) PutAuthMeta(ctx context.Context, asid string, meta AuthMeta) error {
	if asid == "" {
		return errors.New("asid is required")
	}
	return s.putJSON(ctx, AuthMetaKey(asid), meta, 0)
}

func (s *Store) GetAuthMeta(ctx context.Context, asid string) (AuthMeta, error) {
	var meta AuthMeta
	raw, err := s.rdb.Get(ctx, AuthMetaKey(asid)).Result()
	if errors.Is(err, redis.Nil) {
		return AuthMeta{}, ErrNotFound
	}
	if err != nil {
		return AuthMeta{}, err
	}
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return AuthMeta{}, err
	}
	return meta, nil
}

func (s *Store) PutLoginMeta(ctx context.Context, sid string, meta LoginMeta) error {
	if sid == "" {
		return errors.New("sid is required")
	}
	return s.putJSON(ctx, LoginMetaKey(sid), meta, 0)
}

func (s *Store) GetLoginMeta(ctx context.Context, sid string) (LoginMeta, error) {
	var meta LoginMeta
	raw, err := s.rdb.Get(ctx, LoginMetaKey(sid)).Result()
	if errors.Is(err, redis.Nil) {
		return LoginMeta{}, ErrNotFound
	}
	if err != nil {
		return LoginMeta{}, err
	}
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return LoginMeta{}, err
	}
	return meta, nil
}

// RevokeChain 删掉一个全局会话下的应用会话、刷新家族，并把 sid 记入吊销集合。
func (s *Store) RevokeChain(ctx context.Context, sid string, retention time.Duration) error {
	if sid == "" {
		return errors.New("sid is required")
	}
	gs, err := s.GetGlobal(ctx, sid)
	sub := ""
	if err == nil {
		sub = gs.Sub
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	apps, err := s.ListAppIDs(ctx, sid)
	if err != nil {
		return err
	}
	for _, asid := range apps {
		if err := s.deleteApp(ctx, sub, asid); err != nil {
			return err
		}
	}
	if err := s.rdb.Del(ctx, GlobalKey(sid), GlobalAppsKey(sid), LoginMetaKey(sid)).Err(); err != nil {
		return err
	}
	return s.RememberRevokedSID(ctx, sid, retention)
}

// DeleteFamily 删掉一个刷新家族里的全部 refresh 键。应用会话已经不在时用它收尾。
func (s *Store) DeleteFamily(ctx context.Context, family string) error {
	if family == "" {
		return nil
	}
	hashes, err := s.rdb.SMembers(ctx, RefreshFamilyKey(family)).Result()
	if err != nil {
		return err
	}
	for _, hash := range hashes {
		if err := s.rdb.Del(ctx, RefreshKey(hash)).Err(); err != nil {
			return err
		}
	}
	return s.rdb.Del(ctx, RefreshFamilyKey(family)).Err()
}

func (s *Store) deleteApp(ctx context.Context, sub, asid string) error {
	family, err := s.rdb.Get(ctx, AppFamilyKey(asid)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	if family != "" {
		if err := s.DeleteFamily(ctx, family); err != nil {
			return err
		}
	}
	if sub != "" {
		if err := s.rdb.ZRem(ctx, UserSessionsKey(sub), asid).Err(); err != nil {
			return err
		}
	}
	return s.rdb.Del(ctx, AppKey(asid), AppFamilyKey(asid), AuthMetaKey(asid)).Err()
}

func (s *Store) putJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	if ttl < 0 {
		return errors.New("ttl must be >= 0")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if ttl == 0 {
		return s.rdb.Set(ctx, key, raw, 0).Err()
	}
	return s.rdb.Set(ctx, key, raw, ttl).Err()
}

func (s *Store) takeJSON(ctx context.Context, key string, dst any) error {
	val, err := s.rdb.Eval(ctx, takeStringScript, []string{key}).Result()
	if err != nil {
		return err
	}
	raw := luaString(val)
	if raw == "" {
		return ErrNotFound
	}
	return json.Unmarshal([]byte(raw), dst)
}

func luaString(v any) string {
	switch s := v.(type) {
	case nil:
		return ""
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return fmt.Sprint(s)
	}
}

func luaInt(v any) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case float64:
		return int64(n), nil
	case string:
		return strconv.ParseInt(n, 10, 64)
	default:
		return 0, fmt.Errorf("lua int %T", v)
	}
}

func formatInt(v int64) string { return strconv.FormatInt(v, 10) }

func parseInt(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
