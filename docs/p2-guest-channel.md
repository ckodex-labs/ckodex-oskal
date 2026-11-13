# Bind telemetry to its actual connection

Each endpoint derives its own TLS channel binding before the guest requests a quote.

`internal/adapters/guesttransport` uses RFC 9266 `tls-exporter`: the label
`EXPORTER-Channel-Binding`, empty context, and 32 output bytes. Only a completed
TLS 1.3 handshake is accepted. The server reads gRPC's authenticated peer state.
The client installs one `ClientBinding` with `grpc.PerRPCCredentials` for its
stream; gRPC supplies the connection's authentication state before creating the
RPC. `Exporter()` fails before that state exists. Reusing the observer on a
different connection fails. Callers must disable transparent RPC retries and
create a new observer and attested session on reconnect.

The adapter sends no exporter header. A producer-provided or echoed binding is
not substituted for either endpoint's local calculation. The application includes
this binding in the quote qualification along with its verifier nonce, session,
policy, and export-public-key hash. This adapter does not verify that quote,
authorize a producer, establish physical co-residence, or run a sensor.

Primary versions checked on 2026-11-13:

- [gRPC Go v1.85.0](https://github.com/grpc/grpc-go/releases/tag/v1.85.0),
  already selected by `go.mod`; its `credentials.RequestInfoFromContext` supplies
  actual per-RPC connection authentication.
- [Protobuf Go v1.36.12](https://github.com/protocolbuffers/protobuf-go/releases/tag/v1.36.12).
- [protoc v36.2](https://github.com/protocolbuffers/protobuf/releases/tag/v36.2).
- [protoc-gen-go-grpc v1.6.2](https://github.com/grpc/grpc-go/releases/tag/cmd/protoc-gen-go-grpc/v1.6.2).
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html#section-2).

The actual test runs a real gRPC health service over mutually authenticated TLS
with freshly generated certificates and keys. Client and server independently
derive equal bindings; a second real TLS connection yields a different value;
attempting to reuse the first connection's observer is rejected; a real TLS 1.2
connection is refused. No authentication or transport is substituted.

Observed command: `go test -count=1 -race -v ./internal/adapters/guesttransport`,
exit 0, package time 1.294s. Focused `golangci-lint` reported `0 issues.` with exit
0. This is transport-binding proof, not the deployed attested-stream or flood demo.
