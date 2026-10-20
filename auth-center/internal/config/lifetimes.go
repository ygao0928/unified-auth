package config

import "fmt"

// 全局默认来自设计文档 §5.2，已定稿。进程配置不能改这张表；
// 客户端只通过 session_policy 覆盖单项，未填的项用这里的值。
const (
	DefaultAccessTokenTTLCap = 1800
	DefaultPreviousKeyBuffer = 60
	DefaultClockSkew         = 60

	DefaultUserAccessTokenTTL = 600
	DefaultM2MAccessTokenTTL  = 1800
	DefaultRefreshTokenTTL    = 600

	DefaultWebIdleTimeout        = 7200
	DefaultWebAbsoluteSessionTTL = 43200
	DefaultAppIdleTimeout        = 604800
	DefaultAppAbsoluteSessionTTL = 2592000
)

const (
	ClientWeb     = "web"
	ClientSSR     = "ssr"
	ClientApp     = "app"
	ClientMiniApp = "miniapp"
	ClientM2M     = "m2m"
)

// SessionPolicy 对应 OpenAPI ClientLifetimes，也是客户端 session_policy 的 JSON 形状。
// 指针为 nil 表示该项没填，解析时用该 client_type 的全局默认。
type SessionPolicy struct {
	AccessTokenTTL     *int `json:"access_token_ttl,omitempty"`
	RefreshTokenTTL    *int `json:"refresh_token_ttl,omitempty"`
	IdleTimeout        *int `json:"idle_timeout,omitempty"`
	AbsoluteSessionTTL *int `json:"absolute_session_ttl,omitempty"`
}

// Lifetimes 是解析并套用 access_token_ttl_cap 之后的有效值，单位秒。
// m2m 的 IssuesRefresh 为 false，其余三项为 0，表示不签发 refresh、也没有会话超时。
type Lifetimes struct {
	AccessTokenTTL     int
	RefreshTokenTTL    int
	IdleTimeout        int
	AbsoluteSessionTTL int
	IssuesRefresh      bool
}

// RetentionSeconds 是吊销记录与旧签名密钥继续发布时使用的秒数：cap + clock_skew。
func RetentionSeconds(accessTokenTTLCap, clockSkew int) int {
	return accessTokenTTLCap + clockSkew
}

// PreviousKeyPublishSeconds 是轮换后上一把密钥继续出现在 JWKS 里的秒数。
func PreviousKeyPublishSeconds(accessTokenTTLCap, previousKeyBuffer int) int {
	return accessTokenTTLCap + previousKeyBuffer
}

// ResolveLifetimes 合并全局默认、客户端覆盖，并把 access token 截断到 cap。
// 截断是设计已经写明的行为，不返回错误。m2m 若填写 refresh、空闲或绝对时长，返回错误。
func ResolveLifetimes(clientType string, policy SessionPolicy, accessTokenTTLCap int) (Lifetimes, error) {
	if accessTokenTTLCap < 1 {
		return Lifetimes{}, fmt.Errorf("access_token_ttl_cap must be >= 1")
	}
	base, err := globalDefault(clientType)
	if err != nil {
		return Lifetimes{}, err
	}
	if !base.IssuesRefresh {
		if policy.RefreshTokenTTL != nil || policy.IdleTimeout != nil || policy.AbsoluteSessionTTL != nil {
			return Lifetimes{}, fmt.Errorf("m2m client cannot set refresh_token_ttl, idle_timeout, or absolute_session_ttl")
		}
	}
	if policy.AccessTokenTTL != nil {
		if err := positive("access_token_ttl", *policy.AccessTokenTTL); err != nil {
			return Lifetimes{}, err
		}
		base.AccessTokenTTL = *policy.AccessTokenTTL
	}
	if policy.RefreshTokenTTL != nil {
		if err := positive("refresh_token_ttl", *policy.RefreshTokenTTL); err != nil {
			return Lifetimes{}, err
		}
		base.RefreshTokenTTL = *policy.RefreshTokenTTL
	}
	if policy.IdleTimeout != nil {
		if err := positive("idle_timeout", *policy.IdleTimeout); err != nil {
			return Lifetimes{}, err
		}
		base.IdleTimeout = *policy.IdleTimeout
	}
	if policy.AbsoluteSessionTTL != nil {
		if err := positive("absolute_session_ttl", *policy.AbsoluteSessionTTL); err != nil {
			return Lifetimes{}, err
		}
		base.AbsoluteSessionTTL = *policy.AbsoluteSessionTTL
	}
	if base.AccessTokenTTL > accessTokenTTLCap {
		base.AccessTokenTTL = accessTokenTTLCap
	}
	return base, nil
}

func globalDefault(clientType string) (Lifetimes, error) {
	switch clientType {
	case ClientWeb, ClientSSR:
		return Lifetimes{
			AccessTokenTTL:     DefaultUserAccessTokenTTL,
			RefreshTokenTTL:    DefaultRefreshTokenTTL,
			IdleTimeout:        DefaultWebIdleTimeout,
			AbsoluteSessionTTL: DefaultWebAbsoluteSessionTTL,
			IssuesRefresh:      true,
		}, nil
	case ClientApp, ClientMiniApp:
		return Lifetimes{
			AccessTokenTTL:     DefaultUserAccessTokenTTL,
			RefreshTokenTTL:    DefaultRefreshTokenTTL,
			IdleTimeout:        DefaultAppIdleTimeout,
			AbsoluteSessionTTL: DefaultAppAbsoluteSessionTTL,
			IssuesRefresh:      true,
		}, nil
	case ClientM2M:
		return Lifetimes{
			AccessTokenTTL: DefaultM2MAccessTokenTTL,
			IssuesRefresh:  false,
		}, nil
	default:
		return Lifetimes{}, fmt.Errorf("unknown client_type %q", clientType)
	}
}

func positive(name string, v int) error {
	if v < 1 {
		return fmt.Errorf("%s must be >= 1", name)
	}
	return nil
}

// KnownClientType 报告 client_type 是否属于设计文档中的五种。
func KnownClientType(clientType string) bool {
	_, err := globalDefault(clientType)
	return err == nil
}
