package executor

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
)

type decodedHTTPObserverBody struct {
	io.ReadCloser
	observed bytes.Buffer
	calls    int
	closed   bool
}

func (b *decodedHTTPObserverBody) ObserveDecodedHTTPResponseBody(decoded io.ReadCloser) io.ReadCloser {
	b.calls++
	return &decodedHTTPObservedBody{Reader: io.TeeReader(decoded, &b.observed), Closer: decoded}
}

func (b *decodedHTTPObserverBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}

type decodedHTTPObservedBody struct {
	io.Reader
	io.Closer
}

func TestCodexDecodedHTTPObserverSurvivesUsageTracking(t *testing.T) {
	for _, encoding := range []string{"gzip", "", "invalid"} {
		t.Run(encoding, func(t *testing.T) {
			plain := []byte("data: {\"type\":\"response.completed\"}\n\n")
			// Headerless compressed responses exercise CPA's deferred sniffing path.
			body := &decodedHTTPObserverBody{ReadCloser: io.NopCloser(bytes.NewReader(codexCompressedResponse(t, "gzip", plain)))}
			resp := &http.Response{Body: body, Header: http.Header{"Content-Encoding": {encoding}}}
			reporter := &helps.UsageReporter{}
			reporter.ObserveResponse(resp)
			errDecode := decodeCodexUpstreamResponse(resp)
			if encoding == "invalid" {
				if errDecode == nil || body.calls != 0 || !body.closed {
					t.Fatalf("decoder failure: err=%v observer calls=%d closed=%v", errDecode, body.calls, body.closed)
				}
				return
			}
			if errDecode != nil {
				t.Fatal(errDecode)
			}
			got, errRead := io.ReadAll(resp.Body)
			if errClose := resp.Body.Close(); errClose != nil {
				t.Fatal(errClose)
			}
			if errRead != nil || !bytes.Equal(got, plain) || !bytes.Equal(body.observed.Bytes(), plain) || body.calls != 1 || !body.closed {
				t.Fatalf("decoded=%q observed=%q err=%v calls=%d closed=%v", got, body.observed.Bytes(), errRead, body.calls, body.closed)
			}
		})
	}
}

type codexTransportObservation struct {
	kind    string
	conn    net.Conn
	msgType int
	payload string
	err     error
	active  bool
}

type codexTransportObserver struct {
	events chan codexTransportObservation
}

func (o *codexTransportObserver) BeginWebSocketWrite(conn net.Conn, msgType int, payload []byte) func(error) {
	o.events <- codexTransportObservation{kind: "write", conn: conn, msgType: msgType, payload: string(payload)}
	return func(err error) { o.events <- codexTransportObservation{kind: "complete", conn: conn, err: err} }
}

func (o *codexTransportObserver) ObserveWebSocketRead(conn net.Conn, msgType int, payload []byte, err error, active bool) {
	o.events <- codexTransportObservation{kind: "read", conn: conn, msgType: msgType, payload: string(payload), err: err, active: active}
}

func (o *codexTransportObserver) EndWebSocketConnection(conn net.Conn) {
	o.events <- codexTransportObservation{kind: "end", conn: conn}
}

func TestCodexWebsocketTransportObserver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Error(errUpgrade)
			return
		}
		defer func() {
			if errClose := conn.Close(); errClose != nil {
				t.Error(errClose)
			}
		}()
		for i := 0; i < 2; i++ {
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				t.Error(errRead)
				return
			}
		}
		for _, frame := range []struct {
			kind int
			body string
		}{{websocket.TextMessage, " \n{\"type\":\"idle\"} \n"}, {websocket.BinaryMessage, "binary"}} {
			if errWrite := conn.WriteMessage(frame.kind, []byte(frame.body)); errWrite != nil {
				t.Error(errWrite)
				return
			}
		}
	}))
	defer server.Close()
	conn, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			t.Log(errClose)
		}
	}()
	observer := &codexTransportObserver{events: make(chan codexTransportObservation, 16)}
	sess := &codexWebsocketSession{conn: conn, connCloser: newWebsocketConnectionCloser(conn), transportObserver: observer}
	for _, payload := range []string{"create", strings.Repeat("x", codexWebsocketWriteChunkSize+1)} {
		if errWrite := sess.writeMessage(conn, websocket.TextMessage, []byte(payload)); errWrite != nil {
			t.Fatal(errWrite)
		}
		start, complete := <-observer.events, <-observer.events
		if start.kind != "write" || start.conn != conn.UnderlyingConn() || start.msgType != websocket.TextMessage || start.payload != payload || complete.kind != "complete" || complete.err != nil {
			t.Fatalf("write observation: start=%+v complete=%+v", start, complete)
		}
	}
	executor := NewCodexWebsocketsExecutor(nil)
	go executor.readUpstreamLoop(sess, conn)
	for i, want := range []struct {
		kind string
		body string
	}{{"read", " \n{\"type\":\"idle\"} \n"}, {"read", "binary"}, {"end", ""}} {
		select {
		case got := <-observer.events:
			if got.kind != want.kind || got.payload != want.body || got.conn != conn.UnderlyingConn() || got.active || got.err != nil {
				t.Fatalf("event %d = %+v, want %+v on the idle connection", i, got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("transport observation timed out")
		}
	}
	// Binary rejection closes the connection; completion still reports local write failure.
	errWrite := sess.writeMessage(conn, websocket.TextMessage, []byte("interrupt"))
	start, complete := <-observer.events, <-observer.events
	if errWrite == nil || start.kind != "write" || complete.kind != "complete" || complete.err != errWrite {
		t.Fatalf("failed write: err=%v start=%+v complete=%+v", errWrite, start, complete)
	}
}
