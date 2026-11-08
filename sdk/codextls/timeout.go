package codextls

import (
	"context"
	"time"
)

type handshakeTimeoutKey struct{}

// WithHandshakeTimeout carries a TLS establishment limit without placing a
// deadline on the established connection or the response stream.
func WithHandshakeTimeout(ctx context.Context, timeout time.Duration) context.Context {
	if ctx == nil || timeout <= 0 {
		return ctx
	}
	return context.WithValue(ctx, handshakeTimeoutKey{}, timeout)
}

// HandshakeTimeout returns the configured TLS establishment limit, or zero.
func HandshakeTimeout(ctx context.Context) time.Duration {
	if ctx == nil {
		return 0
	}
	timeout, _ := ctx.Value(handshakeTimeoutKey{}).(time.Duration)
	if timeout < 0 {
		return 0
	}
	return timeout
}
