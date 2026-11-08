package codextls

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// Transport uses the HTTP rustls profile and selects HTTP/SSE framing from ALPN.
// Connections live through response-body closure; the session cache is bounded.
type Transport struct {
	dialer *Dialer
	plain  *http.Transport
}

func NewHTTPTransport(raw proxy.Dialer, roots *x509.CertPool) *Transport {
	dialer := NewDialer(raw, HTTP, roots)
	plain := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		contextDialer, ok := dialer.raw.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("codex transport: dialer requires context cancellation")
		}
		return contextDialer.DialContext(ctx, network, addr)
	}}
	return &Transport{dialer: dialer, plain: plain}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		return t.plain.RoundTrip(req)
	}
	if req.URL.Scheme != "https" {
		return nil, errors.New("codex tls: HTTPS target required")
	}
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	raw, err := t.dialer.DialTLSContext(req.Context(), "tcp", net.JoinHostPort(req.URL.Hostname(), port))
	if err != nil {
		return nil, err
	}
	conn := raw.(*tls.UConn)
	closeConnection := func() error { return closedConnectionError(conn.Close()) }

	var resp *http.Response
	switch protocol := conn.ConnectionState().NegotiatedProtocol; protocol {
	case "h2":
		h2, errNew := (&http2.Transport{}).NewClientConn(conn)
		if errNew != nil {
			err = fmt.Errorf("codex tls: initialize HTTP/2: %w", errNew)
			break
		}
		closeConnection = h2.Close
		resp, err = h2.RoundTrip(req)
	case "", "http/1.1":
		transport := &http.Transport{DisableKeepAlives: true, DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}
		resp, err = transport.RoundTrip(req)
		transport.CloseIdleConnections()
	default:
		err = fmt.Errorf("codex tls: unsupported ALPN %q", protocol)
	}
	if err != nil {
		_ = closeConnection()
		return nil, err
	}
	if resp == nil {
		_ = closeConnection()
		return nil, errors.New("codex tls: empty response")
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Body = &connectionBody{ReadCloser: resp.Body, close: closeConnection}
	return resp, nil
}

type connectionBody struct {
	io.ReadCloser
	close func() error
	once  sync.Once
	err   error
}

func (b *connectionBody) Close() error {
	b.once.Do(func() {
		b.err = errors.Join(closedConnectionError(b.ReadCloser.Close()), closedConnectionError(b.close()))
	})
	return b.err
}

// CloseIdleConnections retires the plain HTTP pool. TLS requests each own a
// dedicated connection through response-body closure, so there are no idle TLS
// sockets to retire and active responses remain usable after cache eviction.
func (t *Transport) CloseIdleConnections() { t.plain.CloseIdleConnections() }

func closedConnectionError(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return nil
	}
	return err
}
