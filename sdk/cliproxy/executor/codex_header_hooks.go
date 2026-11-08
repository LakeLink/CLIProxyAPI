package executor

import (
	"context"
	"net/http"
	"net/url"
)

// CodexHeaderHooks let an embedding host apply its frozen account routing state
// at the final HTTP or WebSocket boundary, after generic header overrides.
// Prepare owns only the request's headers. Observe receives an independent
// response header copy before downstream filtering, including failed handshakes.
type CodexHeaderHooks struct {
	Prepare func(*http.Request) error
	Observe func(*url.URL, http.Header)
}

type codexHeaderHooksKey struct{}

func WithCodexHeaderHooks(ctx context.Context, hooks CodexHeaderHooks) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, codexHeaderHooksKey{}, hooks)
}

func CodexHeaderHooksFromContext(ctx context.Context) CodexHeaderHooks {
	if ctx == nil {
		return CodexHeaderHooks{}
	}
	hooks, _ := ctx.Value(codexHeaderHooksKey{}).(CodexHeaderHooks)
	return hooks
}
