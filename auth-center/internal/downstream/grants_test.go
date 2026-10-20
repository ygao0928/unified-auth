package downstream

import "testing"

func TestGrantTypesMatchSpec(t *testing.T) {
	got := GrantTypes()
	want := []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Fatalf("grant %d = %s", i, got[i])
		}
	}
	if ProviderHandlersWired() {
		t.Fatal("handlers must stay unwired in this skeleton")
	}
}
