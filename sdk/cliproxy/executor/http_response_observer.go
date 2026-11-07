package executor

import "io"

// HTTPResponseBodyObserver is implemented by a transport's response body to
// observe decoded bytes before Codex parsing and translation. The returned body
// must preserve decoded reads, errors and closure of the original response.
type HTTPResponseBodyObserver interface {
	ObserveDecodedHTTPResponseBody(decoded io.ReadCloser) io.ReadCloser
}
