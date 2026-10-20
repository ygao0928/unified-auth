package idp

import (
	"context"
	"net/http"
	"time"
)

// Protocol 是上游身份源协议。P1 只实现 OIDC；CAS 与 SAML 在 P6。
type Protocol string

const (
	ProtocolCAS    Protocol = "CAS"
	ProtocolSAML   Protocol = "SAML"
	ProtocolOIDC   Protocol = "OIDC"
	ProtocolCustom Protocol = "CUSTOM"
)

// LogoutHint 是上游登出跳转可能需要的信息。
// 设计文档 §5.1 只给了类型名。字段在确认前只有主体和全局会话 ID。
type LogoutHint struct {
	Subject string
	SID     string
}

// Identity 是归一化后的身份。只有 EmpNo 必填。
type Identity struct {
	EmpNo    string
	Name     *string
	Email    *string
	Mobile   *string
	DeptID   *string
	DeptName *string
	Raw      map[string]any
	Provider string
	AuthTime time.Time
	AMR      []string
}

// IdentityProvider 抽象上游 SSO。新增协议只新增实现。
type IdentityProvider interface {
	ID() string
	Protocol() Protocol
	BuildLoginRedirect(ctx context.Context, state string) (string, error)
	HandleCallback(ctx context.Context, r *http.Request) (*Identity, error)
	// BuildLogoutRedirect 在上游不支持登出时返回 ok=false。
	BuildLogoutRedirect(ctx context.Context, hint LogoutHint) (url string, ok bool)
}
