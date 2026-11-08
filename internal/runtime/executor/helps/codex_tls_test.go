package helps

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexTLSSessionsFollowSelectedCredential(t *testing.T) {
	resumed := make(chan bool, 8)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resumed <- r.TLS.DidResume
		_, _ = io.WriteString(w, "accepted")
	}))
	defer upstream.Close()
	caPath := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_CA_CERTIFICATE", caPath)
	cases := []struct {
		row, account, token string
		resumed             bool
	}{
		{"row-a", "account-a", "access-a", false},
		{"row-a", "account-a", "access-a", true},
		{"row-a", "account-a", "access-refreshed", false},
		{"row-a", "replacement-account", "access-refreshed", false},
		{"row-b", "replacement-account", "access-refreshed", false},
	}
	for _, tc := range cases {
		auth := &cliproxyauth.Auth{ID: tc.row, Provider: "codex", ProxyURL: "direct", Metadata: map[string]any{"account_id": tc.account, "access_token": tc.token}}
		client := NewCodexHTTPClient(t.Context(), nil, auth, 0)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err = resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if got := <-resumed; got != tc.resumed {
			t.Fatalf("TLS resumed=%v want=%v for selected row/account/credential", got, tc.resumed)
		}
	}
}
