package config

import "fmt"

// 下面这些常量是设计文档 §5.2 的全局默认。进程启动时把它们填进配置，
// YAML 或环境变量可以覆盖；客户端 session_policy 仍优先于覆盖后的全局值。
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

	// 授权码和授权事务的存活时间不在规范里。这是实现采用的默认秒数。
	DefaultAuthCodeTTL     = 60
	DefaultAuthorizeTxnTTL = 600
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

// LifetimeDefaults 是某一进程当前的全局默认，单位秒。ssr 使用 web 的空闲和绝对时长，miniapp 使用 app 的。
type LifetimeDefaults struct {
	UserAccessTokenTTL    int
	M2MAccessTokenTTL     int
	RefreshTokenTTL       int
	WebIdleTimeout        int
	WebAbsoluteSessionTTL int
	AppIdleTimeout        int
	AppAbsoluteSessionTTL int
}

// BuiltinLifetimeDefaults 返回设计文档 §5.2 的数字。配置文件和环境变量都没写时用它。
func BuiltinLifetimeDefaults() LifetimeDefaults {
	return LifetimeDefaults{
		UserAccessTokenTTL:    DefaultUserAccessTokenTTL,
		M2MAccessTokenTTL:     DefaultM2MAccessTokenTTL,
		RefreshTokenTTL:       DefaultRefreshTokenTTL,
		WebIdleTimeout:        DefaultWebIdleTimeout,
		WebAbsoluteSessionTTL: DefaultWebAbsoluteSessionTTL,
		AppIdleTimeout:        DefaultAppIdleTimeout,
		AppAbsoluteSessionTTL: DefaultAppAbsoluteSessionTTL,
	}
}

// Validate 要求每一项至少 1 秒。access token 是否超过 cap 不在这里判断，解析时截断。
func (d LifetimeDefaults) Validate() error {
	checks := []struct {
		name string
		v    int
	}{
		{"user_access_token_ttl", d.UserAccessTokenTTL},
		{"m2m_access_token_ttl", d.M2MAccessTokenTTL},
		{"refresh_token_ttl", d.RefreshTokenTTL},
		{"web_idle_timeout", d.WebIdleTimeout},
		{"web_absolute_session_ttl", d.WebAbsoluteSessionTTL},
		{"app_idle_timeout", d.AppIdleTimeout},
		{"app_absolute_session_ttl", d.AppAbsoluteSessionTTL},
	}
	for _, c := range checks {
		if err := positive(c.name, c.v); err != nil {
			return err
		}
	}
	return nil
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

// ResolveLifetimes 合并调用方传入的全局默认、客户端覆盖，并把 access token 截断到 cap。
// 截断是设计已经写明的行为，不返回错误。m2m 若填写 refresh、空闲或绝对时长，返回错误。
func ResolveLifetimes(clientType string, policy SessionPolicy, accessTokenTTLCap int, defaults LifetimeDefaults) (Lifetimes, error) {
	if accessTokenTTLCap < 1 {
		return Lifetimes{}, fmt.Errorf("access_token_ttl_cap must be >= 1")
	}
	if err := defaults.Validate(); err != nil {
		return Lifetimes{}, err
	}
	base, err := globalDefault(clientType, defaults)
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

func globalDefault(clientType string, defaults LifetimeDefaults) (Lifetimes, error) {
	switch clientType {
	case ClientWeb, ClientSSR:
		return Lifetimes{
			AccessTokenTTL:     defaults.UserAccessTokenTTL,
			RefreshTokenTTL:    defaults.RefreshTokenTTL,
			IdleTimeout:        defaults.WebIdleTimeout,
			AbsoluteSessionTTL: defaults.WebAbsoluteSessionTTL,
			IssuesRefresh:      true,
		}, nil
	case ClientApp, ClientMiniApp:
		return Lifetimes{
			AccessTokenTTL:     defaults.UserAccessTokenTTL,
			RefreshTokenTTL:    defaults.RefreshTokenTTL,
			IdleTimeout:        defaults.AppIdleTimeout,
			AbsoluteSessionTTL: defaults.AppAbsoluteSessionTTL,
			IssuesRefresh:      true,
		}, nil
	case ClientM2M:
		return Lifetimes{
			AccessTokenTTL: defaults.M2MAccessTokenTTL,
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
	switch clientType {
	case ClientWeb, ClientSSR, ClientApp, ClientMiniApp, ClientM2M:
		return true
	default:
		return false
	}
}
