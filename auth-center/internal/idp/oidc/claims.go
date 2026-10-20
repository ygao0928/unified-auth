package oidc

import (
	"errors"
	"fmt"
	"time"

	"github.com/ygao0928/unified-auth/auth-center/internal/idp"
)

// Mapping 把 Identity 字段映射到上游 claim 名。EmpNo 必填，其余为空表示不读该属性。
type Mapping struct {
	EmpNo    string `json:"emp_no"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Mobile   string `json:"mobile,omitempty"`
	DeptID   string `json:"dept_id,omitempty"`
	DeptName string `json:"dept_name,omitempty"`
}

// ErrEmpNoRequired 表示上游没有给出可用的工号。可选属性缺失不会产生这个错误。
var ErrEmpNoRequired = errors.New("emp_no claim is missing")

// IdentityFromClaims 按映射生成 Identity。可选字符串缺失、空字符串或非字符串都变成 nil，不阻断登录。
// 工号缺失、为空或不是字符串时返回错误。now 在没有合法 auth_time 时作为 AuthTime。
func IdentityFromClaims(provider string, mapping Mapping, claims map[string]any, now time.Time) (*idp.Identity, error) {
	if mapping.EmpNo == "" {
		return nil, errors.New("attribute mapping emp_no is required")
	}
	emp, ok := nonEmptyString(claims[mapping.EmpNo])
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrEmpNoRequired, mapping.EmpNo)
	}
	raw := make(map[string]any, len(claims))
	for k, v := range claims {
		raw[k] = v
	}
	id := &idp.Identity{
		EmpNo:    emp,
		Name:     optionalString(claims, mapping.Name),
		Email:    optionalString(claims, mapping.Email),
		Mobile:   optionalString(claims, mapping.Mobile),
		DeptID:   optionalString(claims, mapping.DeptID),
		DeptName: optionalString(claims, mapping.DeptName),
		Raw:      raw,
		Provider: provider,
		AuthTime: now.UTC(),
		AMR:      amr(claims["amr"]),
	}
	if sec, ok := number(claims["auth_time"]); ok {
		id.AuthTime = time.Unix(sec, 0).UTC()
	}
	return id, nil
}

func optionalString(claims map[string]any, claim string) *string {
	if claim == "" {
		return nil
	}
	s, ok := nonEmptyString(claims[claim])
	if !ok {
		return nil
	}
	return &s
}

func nonEmptyString(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

func amr(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func number(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}
