package downstream

import (
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// codeExchange 与 authorize 是 zitadel/oidc 里将来要挂到 /oauth2/token 和 /oauth2/authorize 的入口。
// 本骨架不注册路由，只保留引用，避免依赖在 go mod tidy 时被丢掉。
var (
	codeExchange = op.CodeExchange
	authorize    = op.Authorize
)

// GrantTypes 是平台要支持的 grant。授权码和 refresh 属于 P1-AC-04；后两项属于 P6。
func GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{
		oidc.GrantTypeCode,
		oidc.GrantTypeRefreshToken,
		oidc.GrantTypeClientCredentials,
		oidc.GrantTypeTokenExchange,
	}
}

// ProviderHandlersWired 在路由接上之前一直是 false。
func ProviderHandlersWired() bool {
	return codeExchange == nil || authorize == nil
}
