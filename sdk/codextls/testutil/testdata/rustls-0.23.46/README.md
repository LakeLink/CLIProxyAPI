# Codex rustls reference ClientHello

Generated 2026-11-09 on Linux x86_64 with rustc 1.99.1. These are native
rustls outputs from the minimal constructors in `main.rs`, reproducing the
pinned official constructors; an installed CLI binary was not executed.

Official Codex: `rust-v0.166.0`, commit
`6ff1e1ca3b30fc8b914720681fcf5fe62e95f856`.

* HTTP constructor: [Codex client builder](https://github.com/openai/codex/blob/6ff1e1ca3b30fc8b914720681fcf5fe62e95f856/codex-rs/http-client/src/client_builder.rs),
  [custom CA selection](https://github.com/openai/codex/blob/6ff1e1ca3b30fc8b914720681fcf5fe62e95f856/codex-rs/http-client/src/custom_ca.rs),
  reqwest 0.12.28 `use_rustls_tls()` default HTTP version preference
  (`h2`, `http/1.1`). The minimal generator directly constructs the same
  rustls client configuration. Ordinary CLI HTTP without CA configuration uses
  platform native-tls; setting CODEX_CA_CERTIFICATE or SSL_CERT_FILE explicitly
  selects the official rustls HTTP path modeled here.
* WebSocket constructor: the same official custom_ca.rs rustls client builder,
  with no ALPN configured; Codex websocket-client passes that config to its
  tokio-tungstenite connector.
* TLS dependencies match the official Cargo.lock: rustls 0.23.46, aws-lc-rs
  1.18.1, aws-lc-sys 0.45.0, rustls-webpki 0.103.16, reqwest 0.12.28,
  tokio-rustls 0.26.4 and hyper-rustls 0.27.7. Cargo.lock pins the generator's
  complete resolution. `features.txt` records the active rustls feature graph.
  AWS-LC is explicitly installed as the process provider. TLS1.2 is enabled;
  prefer-post-quantum, FIPS and certificate compression are disabled.

`http-{0,1,2}.bin` and `websocket-{0,1,2}.bin` contain three independently
randomized initial TLS records for SNI chatgpt.com. CA roots are empty and no
CA environment variables are read in this emission-only constructor. Root
trust does not contribute a certificate-authorities extension here.

`*-hrr.bin` contains the second ClientHello after an RFC8446 synthetic
HelloRetryRequest selecting X25519MLKEM768 (including the preceding compatibility
CCS record). Initial supported groups are X25519, P256, P384, X25519MLKEM768;
initial key_share is X25519 alone. HRR key_share is the 1216-byte hybrid share.

`*-resumption-{0,1}.bin` captures first and resumed ClientHello from actual
native rustls TLS exchanges against `server.go` (Go 1.27.3). Generate a fresh
self-signed RSA leaf with SAN chatgpt.com and basicConstraints CA:FALSE, exporting
cert.pem, key.pem and cert.der into this directory. The generator explicitly
trusts cert.der; CODEX_CA_CERTIFICATE and SSL_CERT_FILE are unset. Start the Go
server, then run `TLS_REF_ADDR=<printed-address> cargo run --locked`. It reads a
synthetic HTTP response to consume session tickets before reconnecting. Only
ClientHello records are retained. The peer negotiates hybrid KX through HRR on
first connect. Rustls then remembers that origin's group: the resumed hello
contains hybrid and X25519 shares using identical X25519 public key material,
and omits the TLS1.2 session-ticket request when offering a TLS1.3 PSK.

To regenerate emission and HRR fixtures without a network peer, run
`cargo run --locked` in this directory. For local storage constraints, set
CARGO_HOME, RUSTUP_HOME, CARGO_TARGET_DIR and TMPDIR to the designated workspace.

## Comparison rules

Tests compare record and ClientHello versions, random/session lengths, ordered
cipher suites including SCSV, compression, every extension's encoded content,
ordered groups, keyshare groups/lengths, signature algorithms, versions and ALPN.
Random bytes, session IDs, public key material, PSK ticket bytes/age and binder
bytes are normalized by structure. SNI is checked against the configured target
and normalized between the fixture and local test names. Hybrid and classical
shares must reuse the same X25519 public bytes when both are present.

Extension order is validated against rustls's exact 16-bit seeded integer-hash
ordering algorithm from rustls 0.23.46 `msgs/handshake.rs`; only that documented
randomization is normalized for cross-capture comparison. PSK remains last.
Tests exercise full TLS/SSE operation against a validating TLS peer, including
hybrid HRR and resumption, directly and inside HTTP CONNECT, HTTPS CONNECT and SOCKS5 tunnels.
JA3/JA4 are unnecessary for these stronger full-field comparisons.

uTLS 1.8.2 rejected a valid hybrid HelloRetryRequest and lacked authentication
for the native profile's advertised ML-DSA signature schemes. The implementation
pins upstream commit `a13c59ffe98bb01b2ca14143eb2e887664b1f138`
(`v1.8.3-0.20261108164504-a13c59ffe98b`). Its Go 1.27 implementation supports
hybrid HRR, PSK binder reprocessing, shared hybrid/classical key material, and
ML-DSA44/65/87 authentication (0x0904/0x0905/0x0906). CPA and its embedded bridge
therefore require Go 1.27.0; their build/release toolchains are aligned to 1.27.
`TestAdvertisedMLDSASignaturesAuthenticate` verifies each ML-DSA scheme with a
real validating TLS server certificate. TLS profile failures propagate directly.

The dependency's current Chrome auto alias is 155. Existing generic provider
transport explicitly selects its prior Chrome 133 preset, whose source is
unchanged across the dependency update. Claude's explicit profile is retained.
The existing provider transport suite runs with the new pin.

These fixtures establish ClientHello equivalence for the selected rustls
configuration. HTTP/2 framing, server-selected certificates and TLS-terminating
outbound proxies remain deployment-specific observations.
