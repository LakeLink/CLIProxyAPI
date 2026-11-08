package codextls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/codextls/testutil"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	"golang.org/x/net/proxy"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type helloConn struct {
	net.Conn
	data     []byte
	captures chan<- []byte
	hellos   int
}

func (c *helloConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.hellos >= 2 {
		return n, err
	}
	c.data = append(c.data, p[:n]...)
	for len(c.data) >= 5 {
		size := 5 + int(binary.BigEndian.Uint16(c.data[3:5]))
		if len(c.data) < size {
			break
		}
		if c.data[0] == 22 && c.data[5] == 1 {
			c.captures <- bytes.Clone(c.data[:size])
			c.hellos++
		}
		c.data = c.data[size:]
	}
	return n, err
}

type helloListener struct {
	net.Listener
	captures chan<- []byte
}

func (l helloListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &helloConn{Conn: c, captures: l.captures}, nil
}

type routedDialer struct{ target string }

func (d routedDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}
func (d routedDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

type normalizedHello = testutil.NormalizedHello

var normalizeHello = testutil.NormalizeClientHello

func TestTransportMatchesRustlsReference(t *testing.T) {
	for _, route := range []string{"direct", "connect", "socks5", "https-connect"} {
		for _, protocol := range []string{"h2", "http/1.1", ""} {
			t.Run(route+"/"+protocol, func(t *testing.T) { testTransportMatchesRustlsReference(t, route, protocol) })
		}
	}
}
func testTransportMatchesRustlsReference(t *testing.T, route, protocol string) {

	captures := make(chan []byte, 8)
	resumed := make(chan bool, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resumed <- r.TLS.DidResume
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: accepted\n\n")
	}))
	server.EnableHTTP2 = protocol == "h2"
	server.Listener = helloListener{Listener: server.Listener, captures: captures}
	server.TLS = &stdtls.Config{NextProtos: []string{}}
	if protocol != "" {
		server.TLS.NextProtos = []string{protocol}
	}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	target, _ := url.Parse(server.URL)
	transport := NewHTTPTransport(testRoute(t, route, target.Host), roots)
	for attempt := 0; attempt < 2; attempt++ {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/stream", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err = resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if string(body) != "data: accepted\n\n" {
			t.Fatalf("SSE changed: %q", body)
		}
		got, err := normalizeHello(<-captures)
		if err != nil {
			t.Fatal(err)
		}
		isResumed := <-resumed

		if attempt == 0 {
			second, errSecond := normalizeHello(<-captures)
			if errSecond != nil {
				t.Fatal(errSecond)
			}
			reference, errRead := os.ReadFile("testutil/testdata/rustls-0.23.46/http-hrr.bin")
			if errRead != nil {
				t.Fatal(errRead)
			}
			wantSecond, errNormalize := normalizeHello(reference)
			if errNormalize != nil {
				t.Fatal(errNormalize)
			}
			if !reflect.DeepEqual(second, wantSecond) {
				t.Fatalf("hybrid HRR ClientHello differs: got %#v want %#v", second, wantSecond)
			}
		}
		if attempt == 0 {
			for reference := 0; reference < 3; reference++ {
				raw, errRead := os.ReadFile(fmt.Sprintf("testutil/testdata/rustls-0.23.46/http-%d.bin", reference))
				if errRead != nil {
					t.Fatal(errRead)
				}
				want, errNormalize := normalizeHello(raw)
				if errNormalize != nil {
					t.Fatal(errNormalize)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("wire ClientHello differs from native rustls\ngot: %#v\nwant:%#v", got, want)
				}
			}
			if isResumed {
				t.Fatal("first connection resumed")
			}
		} else {
			if !isResumed {
				t.Fatal("reconnect did not resume")
			}
			reference, errRead := os.ReadFile("testutil/testdata/rustls-0.23.46/http-resumption-1.bin")
			if errRead != nil {
				t.Fatal(errRead)
			}
			wantResume, errNormalize := normalizeHello(reference)
			if errNormalize != nil {
				t.Fatal(errNormalize)
			}
			if !reflect.DeepEqual(got, wantResume) {
				t.Fatalf("resumed ClientHello differs from rustls: got %#v want %#v", got, wantResume)
			}
		}
	}
}

func TestTLSValidationAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, tc := range []struct {
		name, host string
		roots      *x509.CertPool
	}{{"untrusted", "example.com", x509.NewCertPool()}, {"hostname", "wrong.invalid", roots}} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDialer(routedDialer{u.Host}, HTTP, tc.roots)
			_, err := d.DialTLSContext(t.Context(), "tcp", tc.host+":443")
			if err == nil {
				t.Fatal("invalid certificate accepted")
			}
		})
	}
	t.Run("configured-bound", func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		ctx := WithHandshakeTimeout(t.Context(), time.Millisecond)
		_, err := NewDialer(nil, HTTP, roots).Handshake(ctx, client, "example.com")
		if !cliproxyexecutor.IsConfiguredTLSHandshakeTimeoutError(err) {
			t.Fatalf("configured TLS deadline classification = %v", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		ctx, cancel := context.WithCancel(t.Context())
		started := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			close(started)
			_, err := NewDialer(nil, HTTP, roots).Handshake(ctx, client, "example.com")
			done <- err
		}()
		<-started
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation = %v", err)
		}
	})
}

func TestWebsocketHelloMatchesReference(t *testing.T) {
	raw, _ := os.ReadFile("testutil/testdata/rustls-0.23.46/websocket-0.bin")
	want, err := normalizeHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		_, errHandshake := NewDialer(nil, WebSocket, x509.NewCertPool()).Handshake(t.Context(), client, "chatgpt.com")
		done <- errHandshake
	}()
	record := make([]byte, 5)
	if _, err = io.ReadFull(server, record); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(record[3:5])))
	if _, err = io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	got, err := normalizeHello(append(record, body...))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WebSocket ClientHello differs: got %#v want %#v", got, want)
	}
	_ = server.Close()
	<-done
}

func testRoute(t *testing.T, route, target string) proxy.Dialer {
	t.Helper()
	if route == "direct" {
		return routedDialer{target}
	}
	var setting string
	if route == "connect" || route == "https-connect" {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Host != "example.com:443" {
				t.Errorf("CONNECT target = %s %s", r.Method, r.Host)
				http.Error(w, "invalid target", 400)
				return
			}
			upstream, err := net.Dial("tcp", target)
			if err != nil {
				t.Error(err)
				return
			}
			client, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				_ = upstream.Close()
				t.Error(err)
				return
			}
			_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
			relay(client, upstream)
		})
		var server *httptest.Server
		if route == "https-connect" {
			server = httptest.NewTLSServer(handler)
			certFile := filepath.Join(t.TempDir(), "proxy.pem")
			if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SSL_CERT_FILE", certFile)
		} else {
			server = httptest.NewServer(handler)
		}
		t.Cleanup(server.Close)
		setting = server.URL
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				client, errAccept := listener.Accept()
				if errAccept != nil {
					return
				}
				go func() {
					reader := bufio.NewReader(client)
					greeting := make([]byte, 2)
					if _, err := io.ReadFull(reader, greeting); err != nil {
						_ = client.Close()
						return
					}
					methods := make([]byte, int(greeting[1]))
					if _, err := io.ReadFull(reader, methods); err != nil {
						_ = client.Close()
						return
					}
					_, _ = client.Write([]byte{5, 0})
					request := make([]byte, 5)
					if _, err := io.ReadFull(reader, request); err != nil {
						_ = client.Close()
						return
					}
					if request[0] != 5 || request[1] != 1 || request[3] != 3 {
						t.Errorf("SOCKS request %v", request)
						_ = client.Close()
						return
					}
					address := make([]byte, int(request[4])+2)
					if _, err := io.ReadFull(reader, address); err != nil {
						_ = client.Close()
						return
					}
					if string(address[:len(address)-2]) != "example.com" {
						t.Errorf("SOCKS target %q", address)
					}
					upstream, err := net.Dial("tcp", target)
					if err != nil {
						t.Error(err)
						_ = client.Close()
						return
					}
					_, _ = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
					relay(client, upstream)
				}()
			}
		}()
		setting = "socks5://" + listener.Addr().String()
	}
	dialer, _, err := proxyutil.BuildDialer(setting)
	if err != nil {
		t.Fatal(err)
	}
	return dialer
}
func relay(client, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	<-done
}

func TestAdvertisedMLDSASignaturesAuthenticate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params mldsa.Parameters
	}{
		{"MLDSA44", mldsa.MLDSA44()}, {"MLDSA65", mldsa.MLDSA65()}, {"MLDSA87", mldsa.MLDSA87()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := mldsa.GenerateKey(tc.params)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: time.Unix(0, 0), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "authenticated") }))
			upstream.TLS = &stdtls.Config{MinVersion: stdtls.VersionTLS13, Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: certificate}}}
			upstream.StartTLS()
			defer upstream.Close()
			roots := x509.NewCertPool()
			roots.AddCert(certificate)
			target, _ := url.Parse(upstream.URL)
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", nil)
			resp, err := NewHTTPTransport(routedDialer{target.Host}, roots).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err = resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if string(body) != "authenticated" {
				t.Fatalf("ML-DSA authenticated response=%q", body)
			}
		})
	}
}
