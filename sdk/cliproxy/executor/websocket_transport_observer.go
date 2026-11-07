package executor

import "net"

// WebSocketTransportObserver is an optional ExecutionLifecycle capability for
// observing application messages at the upstream transport boundary. Callbacks
// must return promptly. Payloads are borrowed for the duration of the callback;
// a write payload remains valid until its completion callback returns.
// The connection identifies the actual transport, including replacement dials.
type WebSocketTransportObserver interface {
	// BeginWebSocketWrite runs after serialization and write serialization, before
	// handing the complete payload to the websocket library. Its optional result
	// runs once after the library returns, with the local write result.
	BeginWebSocketWrite(net.Conn, int, []byte) func(error)
	// ObserveWebSocketRead runs immediately after ReadMessage, before trimming,
	// parsing, filtering, or translation. Active reports a current execution read
	// channel; idle connection messages have no established request ownership.
	ObserveWebSocketRead(net.Conn, int, []byte, error, bool)
	// EndWebSocketConnection runs when the upstream reader exits, after its last
	// observation, including exits caused by application protocol rejection.
	EndWebSocketConnection(net.Conn)
}
