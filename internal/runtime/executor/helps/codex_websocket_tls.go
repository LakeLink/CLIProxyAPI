package helps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	internalcache "github.com/router-for-me/CLIProxyAPI/v8/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/codextls"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	"golang.org/x/net/proxy"
)

var codexWebsocketTLS = internalcache.NewBoundedLRU[codexTransportKey, *codextls.Dialer](64, nil)

// NewCodexWebsocketDialer resolves the selected route before performing target
// TLS. Gorilla receives an already verified connection and performs the normal
// HTTP/1.1 Upgrade without adding another TLS handshake or proxy wrapper.
func NewCodexWebsocketDialer(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, target *url.URL, resolveProxy func(*http.Request) (*url.URL, error)) (*websocket.Dialer, error) {
	if target == nil {
		return nil, errors.New("codex websocket: target required")
	}
	proxyTarget := *target
	switch proxyTarget.Scheme {
	case "ws":
		proxyTarget.Scheme = "http"
	case "wss":
		proxyTarget.Scheme = "https"
	default:
		return nil, errors.New("codex websocket: invalid target scheme")
	}
	proxyURL := effectiveProxyURL(ctx, cfg, auth)
	if proxyURL == "" {
		if resolveProxy == nil {
			return nil, errors.New("codex websocket: environment proxy resolver required")
		}
		selected, err := resolveProxy(&http.Request{Method: http.MethodGet, URL: &proxyTarget})
		if err != nil {
			return nil, fmt.Errorf("codex websocket: resolve proxy: %w", err)
		}
		proxyURL = "direct"
		if selected != nil {
			proxyURL = selected.String()
		}
	}
	raw, _, err := proxyutil.BuildDialer(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("codex websocket: configure proxy: %w", err)
	}
	if raw == nil {
		return nil, errors.New("codex websocket: unresolved proxy route")
	}
	contextDialer, ok := raw.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("codex websocket: proxy requires context cancellation")
	}
	key := codexTransportScope(auth, proxyURL)
	secure := codexWebsocketTLS.GetOrAdd(key, func() *codextls.Dialer { return codextls.NewDialer(raw, codextls.WebSocket, nil) })
	return &websocket.Dialer{NetDialContext: contextDialer.DialContext, NetDialTLSContext: secure.DialTLSContext}, nil
}
