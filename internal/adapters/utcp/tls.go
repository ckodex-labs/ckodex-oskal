package utcp

import (
	"context"
	"crypto/tls"
	"net/http"
)

type transportTLSStateKey struct{}

// TLSStateFromContext reads only the HTTP adapter's transport-owned TLS state.
// Header values and request argument identities are never inspected.
func TLSStateFromContext(ctx context.Context) (tls.ConnectionState, bool) {
	state, ok := ctx.Value(transportTLSStateKey{}).(tls.ConnectionState)
	return state, ok
}

func withTransportTLS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.TLS != nil {
			request = request.WithContext(context.WithValue(request.Context(), transportTLSStateKey{}, *request.TLS))
		}
		handler.ServeHTTP(w, request)
	})
}
