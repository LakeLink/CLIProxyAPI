package helps

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"time"

	internalcache "github.com/router-for-me/CLIProxyAPI/v8/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/codextls"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/httptransport"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	"golang.org/x/net/proxy"
)

type codexTransportKey struct {
	account, proxy string
	epoch, version uint64
	identity       [32]byte
}

var codexTransports = internalcache.NewBoundedLRU[codexTransportKey, http.RoundTripper](64, func(_ codexTransportKey, rt http.RoundTripper) {
	if closer, ok := rt.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
})

type codexHTTPTransport struct {
	secure http.RoundTripper
	plain  *http.Transport
}

func (t *codexHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		return t.plain.RoundTrip(req)
	}
	return t.secure.RoundTrip(req)
}
func (t *codexHTTPTransport) CloseIdleConnections() {
	t.plain.CloseIdleConnections()
	if closer, ok := t.secure.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type failedCodexTransport struct{ err error }

func (t failedCodexTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

// NewCodexHTTPClient applies the pinned rustls profile to every Codex HTTPS
// destination, including configured API hosts. Injected host transports retain
// ownership of proxy routing and the final TLS connection.
func NewCodexHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	proxyURL := effectiveProxyURL(ctx, cfg, auth)
	var transport http.RoundTripper
	if proxyURL == "" && ctx != nil {
		transport, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}
	if transport == nil {
		key := codexTransportScope(auth, proxyURL)
		transport = codexTransports.GetOrAdd(key, func() http.RoundTripper {
			raw, _, err := proxyutil.BuildDialer(proxyURL)
			if err != nil {
				return failedCodexTransport{fmt.Errorf("codex tls: configure proxy: %w", err)}
			}
			if raw == nil {
				raw = proxy.Direct
			}
			plain, _, err := proxyutil.BuildHTTPTransport(proxyURL)
			if err != nil {
				return failedCodexTransport{fmt.Errorf("codex transport: configure HTTP proxy: %w", err)}
			}
			if plain == nil {
				plain = proxyutil.NewDirectTransport()
				plain.Proxy = http.ProxyFromEnvironment
			}
			return &codexHTTPTransport{secure: codextls.NewHTTPTransport(raw, nil), plain: plain}
		})
	}
	client := httptransport.Decorate(ctx, &http.Client{Transport: transport, Timeout: timeout})
	if cfg != nil && cfg.TLSHandshakeTimeout() > 0 {
		client.Transport = &tlsHandshakeTimeoutRoundTripper{base: client.Transport, timeout: cfg.TLSHandshakeTimeout()}
	}
	return client
}

func codexTransportScope(auth *cliproxyauth.Auth, proxyURL string) codexTransportKey {
	key := codexTransportKey{proxy: proxyURL}
	if auth == nil {
		return key
	}
	key.account = auth.ID
	key.epoch = auth.RegistrationEpoch
	key.version = auth.CredentialVersion
	digest := sha256.New()
	for _, value := range []any{auth.Metadata["account_id"], auth.Metadata["access_token"], auth.Attributes["api_key"]} {
		text, _ := value.(string)
		_, _ = io.WriteString(digest, text)
		_, _ = digest.Write([]byte{0})
	}
	copy(key.identity[:], digest.Sum(nil))
	return key
}
