package oauth

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                h.Issuer,
		"authorization_endpoint":                h.Issuer + "/oauth2/authorize",
		"token_endpoint":                        h.Issuer + "/oauth2/token",
		"jwks_uri":                              h.Issuer + "/oauth2/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{h.keys.ActiveAlgorithm()},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}
