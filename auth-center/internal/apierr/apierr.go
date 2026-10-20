package apierr

import (
	"encoding/json"
	"net/http"
)

const (
	// CodeDependencyUnavailable 对应 spec/error-codes.yaml。
	CodeDependencyUnavailable = "AUTH_DEPENDENCY_UNAVAILABLE"
	// CodeNotFound 对应 spec/error-codes.yaml。
	CodeNotFound = "NOT_FOUND"
	// CodeInvalidRequest 对应 spec/error-codes.yaml。
	CodeInvalidRequest = "INVALID_REQUEST"
	// CodeLoginRequired 对应 spec/error-codes.yaml。
	CodeLoginRequired = "AUTH_LOGIN_REQUIRED"
	// CodeRefreshReused 对应 spec/error-codes.yaml。
	CodeRefreshReused = "AUTH_REFRESH_REUSED"
	// CodeUpstreamFailed 对应 spec/error-codes.yaml。
	CodeUpstreamFailed = "AUTH_UPSTREAM_FAILED"
	// CodeTokenMissing 对应 spec/error-codes.yaml。
	CodeTokenMissing = "AUTH_TOKEN_MISSING"
	// CodeTokenInvalid 对应 spec/error-codes.yaml。
	CodeTokenInvalid = "AUTH_TOKEN_INVALID"
	// CodeTokenExpired 对应 spec/error-codes.yaml。
	CodeTokenExpired = "AUTH_TOKEN_EXPIRED"
	// CodeSessionRevoked 对应 spec/error-codes.yaml。
	CodeSessionRevoked = "AUTH_SESSION_REVOKED"
)

type body struct {
	Code             string         `json:"code"`
	Message          string         `json:"message"`
	TraceID          string         `json:"trace_id"`
	Details          map[string]any `json:"details,omitempty"`
	Error            string         `json:"error,omitempty"`
	ErrorDescription string         `json:"error_description,omitempty"`
}

// Write 按 spec/schemas/error-response.schema.json 写错误。message 必须是面向开发者的英文，且不能带 token。
func Write(w http.ResponseWriter, status int, code, message, traceID string, details map[string]any) {
	write(w, status, body{Code: code, Message: message, TraceID: fallbackTrace(traceID), Details: details})
}

// WriteOAuth 在统一错误体上附带 RFC 6749 的 error 与 error_description。
func WriteOAuth(w http.ResponseWriter, status int, code, message, traceID, oauthError, description string) {
	write(w, status, body{
		Code: code, Message: message, TraceID: fallbackTrace(traceID),
		Error: oauthError, ErrorDescription: description,
	})
}

func write(w http.ResponseWriter, status int, b body) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(b)
}

func fallbackTrace(traceID string) string {
	if traceID == "" {
		return "unknown"
	}
	return traceID
}
