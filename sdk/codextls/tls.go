// Package codextls implements the rustls/AWS-LC ClientHello used by Codex 0.166.0.
package codextls

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync/atomic"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v8/internal/cache"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"golang.org/x/net/proxy"
)

// Protocol selects the ALPN behavior of the official HTTP or WebSocket client.
type Protocol uint8

const (
	HTTP Protocol = iota
	WebSocket
)

// Dialer establishes target-side TLS, including inside CONNECT and SOCKS tunnels.
// Each dialer owns its session cache so callers can scope resumption to an account.
type Dialer struct {
	raw      proxy.Dialer
	protocol Protocol
	roots    *x509.CertPool
	sessions tls.ClientSessionCache
	hints    *internalcache.BoundedLRU[string, *atomic.Uint32]
}

func NewDialer(raw proxy.Dialer, protocol Protocol, roots *x509.CertPool) *Dialer {
	if raw == nil {
		raw = proxy.Direct
	}
	return &Dialer{raw: raw, protocol: protocol, roots: roots, sessions: tls.NewLRUClientSessionCache(32), hints: internalcache.NewBoundedLRU[string, *atomic.Uint32](32, nil)}
}

func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, ok := d.raw.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("codex tls: dialer requires context cancellation")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("codex tls: split target: %w", err)
	}
	conn, err := raw.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("codex tls: dial target: %w", err)
	}
	return d.Handshake(ctx, conn, host)
}

// Handshake verifies the target certificate and closes raw on every failure.
func (d *Dialer) Handshake(ctx context.Context, raw net.Conn, serverName string) (*tls.UConn, error) {
	roots := d.roots
	if roots == nil {
		var err error
		roots, err = rootCertificates()
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	hint := d.hints.GetOrAdd(serverName, func() *atomic.Uint32 { return new(atomic.Uint32) })
	spec, err := clientHelloSpec(d.protocol, tls.CurveID(hint.Load()))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn := tls.UClient(raw, &tls.Config{
		ServerName: serverName, RootCAs: roots, ClientSessionCache: d.sessions,
		OmitEmptyPsk: true, PreferSkipResumptionOnNilExtension: true,
	}, tls.HelloCustom)
	for i, ext := range spec.Extensions {
		if ticket, ok := ext.(*tls.SessionTicketExtension); ok {
			spec.Extensions[i] = &rustlsSessionTicket{SessionTicketExtension: ticket, hasPSK: func() bool {
				for _, ext := range conn.Extensions {
					if psk, ok := ext.(tls.PreSharedKeyExtension); ok {
						return psk.IsInitialized()
					}
				}
				return false
			}}
		}
	}
	if err = conn.ApplyPreset(spec); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("codex tls: apply rustls ClientHello: %w", err)
	}
	handshakeCtx := ctx
	cancel := func() {}
	if timeout := HandshakeTimeout(ctx); timeout > 0 {
		handshakeCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	if err = conn.HandshakeContext(handshakeCtx); err != nil {
		if ctx.Err() == nil && errors.Is(handshakeCtx.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded) {
			err = cliproxyexecutor.NewConfiguredTLSHandshakeTimeoutError(err)
		}
		_ = conn.Close()
		return nil, fmt.Errorf("codex tls: handshake target: %w", err)
	}
	if state := conn.ConnectionState(); state.Version == tls.VersionTLS13 {
		hint.Store(uint32(state.CurveID))
	}
	return conn, nil
}

func rootCertificates() (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("codex tls: load system certificates: %w", err)
	}
	if path := os.Getenv("CODEX_CA_CERTIFICATE"); path != "" {
		pem, errRead := os.ReadFile(path)
		if errRead != nil {
			return nil, fmt.Errorf("codex tls: read configured certificates: %w", errRead)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("codex tls: configured certificate bundle contains no certificates")
		}
	}
	return roots, nil
}

func clientHelloSpec(protocol Protocol, preferred tls.CurveID) (*tls.ClientHelloSpec, error) {
	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("codex tls: extension order entropy: %w", err)
	}
	if preferred == 0 {
		preferred = tls.X25519
	}
	shares := []tls.KeyShare{{Group: preferred}}
	if preferred == tls.X25519MLKEM768 {
		shares = tls.ReuseHybridAndClassicalKeyShares(tls.KeyShare{Group: preferred}, tls.KeyShare{Group: tls.X25519})
	}
	exts := []struct {
		id    uint16
		value tls.TLSExtension
	}{
		{0, &tls.SNIExtension{}},
		{5, &tls.StatusRequestExtension{}},
		{10, &tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.X25519MLKEM768}}},
		{11, &tls.SupportedPointsExtension{SupportedPoints: []uint8{0}}},
		{13, &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{0x0503, 0x0403, 0x0603, 0x0807, 0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401, 0x0904, 0x0905, 0x0906}}},
		{23, &tls.ExtendedMasterSecretExtension{}},
		{35, &tls.SessionTicketExtension{}},
		{43, &tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}}},
		{45, &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}}},
		{51, &tls.KeyShareExtension{KeyShares: shares}},
	}
	switch protocol {
	case HTTP:
		exts = append(exts, struct {
			id    uint16
			value tls.TLSExtension
		}{16, &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}})
	case WebSocket:
	default:
		return nil, errors.New("codex tls: unknown protocol")
	}
	orderSeed := uint32(binary.BigEndian.Uint16(seed[:])) << 16
	// rustls 0.23.46 uses this seeded integer hash rather than a uniform shuffle.
	sort.SliceStable(exts, func(i, j int) bool {
		return extensionOrderHash(orderSeed|uint32(exts[i].id)) < extensionOrderHash(orderSeed|uint32(exts[j].id))
	})
	ordered := make([]tls.TLSExtension, 0, len(exts)+1)
	for _, ext := range exts {
		ordered = append(ordered, ext.value)
	}
	// RFC 8446 requires pre_shared_key last. OmitEmptyPsk suppresses it initially.
	ordered = append(ordered, &tls.UtlsPreSharedKeyExtension{})
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS12, TLSVersMax: tls.VersionTLS13,
		CipherSuites:       []uint16{0x1302, 0x1301, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0x00ff},
		CompressionMethods: []uint8{0}, Extensions: ordered,
	}, nil
}

func extensionOrderHash(x uint32) uint32 {
	x = x + 0x7ed55d16 + (x << 12)
	x = (x ^ 0xc761c23c) ^ (x >> 19)
	x = x + 0x165667b1 + (x << 5)
	x = (x + 0xd3a2646c) ^ (x << 9)
	x = x + 0xfd7046c5 + (x << 3)
	return (x ^ 0xb55a4f09) ^ (x >> 16)
}

// rustls omits the TLS1.2 session-ticket request when offering a TLS1.3 PSK.
// Decide after uTLS validates and loads the cached session, including expiry.
type rustlsSessionTicket struct {
	*tls.SessionTicketExtension
	hasPSK func() bool
}

func (e *rustlsSessionTicket) Len() int {
	if e.hasPSK() {
		return 0
	}
	return e.SessionTicketExtension.Len()
}
func (e *rustlsSessionTicket) Read(b []byte) (int, error) {
	if e.Len() == 0 {
		return 0, io.EOF
	}
	return e.SessionTicketExtension.Read(b)
}
