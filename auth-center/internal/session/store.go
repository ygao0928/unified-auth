package session

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// 键名与设计文档 §5.3.1 的代码块一致。
// auth:user:{sub}:sessions 是否按客户端类型再拆开，正文和代码块不一致，这里用代码块里的键。
// auth:revoked:sid 是整个集合一把 TTL；每加一个成员都会刷新这把 TTL。按成员过期的写法尚未决定。
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

// Store 读写 §5.3.1 的 Redis 键。不实现空闲超时、轮换或吊销流程。
type Store struct {
	rdb redis.Cmdable
}

func New(rdb redis.Cmdable) *Store {
	return &Store{rdb: rdb}
}

func GlobalKey(sid string) string       { return "auth:gs:" + sid }
func GlobalAppsKey(sid string) string   { return "auth:gs:" + sid + ":apps" }
func AppKey(asid string) string         { return "auth:as:" + asid }
func UserSessionsKey(sub string) string { return "auth:user:" + sub + ":sessions" }
func RefreshKey(hash string) string     { return "auth:rt:" + hash }
func RevokedSIDKey() string             { return "auth:revoked:sid" }

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
	return nil
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

func formatInt(v int64) string { return strconv.FormatInt(v, 10) }

func parseInt(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
