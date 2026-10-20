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
)

type body struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	TraceID string         `json:"trace_id"`
	Details map[string]any `json:"details,omitempty"`
}

// Write 按 spec/schemas/error-response.schema.json 写错误。message 必须是面向开发者的英文，且不能带 token。
func Write(w http.ResponseWriter, status int, code, message, traceID string, details map[string]any) {
	if traceID == "" {
		traceID = "unknown"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body{Code: code, Message: message, TraceID: traceID, Details: details})
}
