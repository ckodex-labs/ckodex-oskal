package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/service"
	servicesv1 "github.com/ckodex-labs/ckodex-oskal/proto/assurance/services/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

const maxTLSFileBytes = 1 << 20

func trustedCAPool(path string) (*x509.CertPool, error) {
	raw, err := readBoundedFile(path, maxTLSFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read TLS trust bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("TLS trust bundle contains no usable CA certificates")
	}
	return roots, nil
}

func tlsKeyPair(certFile, keyFile string, usage x509.ExtKeyUsage) (tls.Certificate, error) {
	cert, err := readBoundedFile(certFile, maxTLSFileBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read TLS certificate: %w", err)
	}
	key, err := readBoundedFile(keyFile, maxTLSFileBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read TLS private key: %w", err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("TLS certificate/key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return tls.Certificate{}, fmt.Errorf("TLS certificate is outside its validity interval")
	}
	validUsage := len(leaf.ExtKeyUsage) == 0
	for _, allowed := range leaf.ExtKeyUsage {
		if allowed == x509.ExtKeyUsageAny || allowed == usage {
			validUsage = true
		}
	}
	if !validUsage {
		return tls.Certificate{}, fmt.Errorf("TLS certificate does not permit the required endpoint role")
	}
	pair.Leaf = leaf
	return pair, nil
}

func grpcClientTLSConfig() (*tls.Config, error) {
	if tlsCAFile == "" || tlsServerName == "" {
		return nil, fmt.Errorf("gRPC requires --tls-ca-file and --tls-server-name (exact expected DNS/IP SAN); plaintext is not supported")
	}
	if len(tlsServerName) > 253 || strings.TrimSpace(tlsServerName) != tlsServerName || (net.ParseIP(tlsServerName) == nil && strings.ContainsAny(tlsServerName, "* /\\:@?#\r\n\t")) {
		return nil, fmt.Errorf("--tls-server-name must be one exact DNS name or IP SAN, not a URI or wildcard")
	}
	if (tlsClientCertFile == "") != (tlsClientKeyFile == "") {
		return nil, fmt.Errorf("--tls-client-cert-file and --tls-client-key-file must be supplied together")
	}
	roots, err := trustedCAPool(tlsCAFile)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: tlsServerName}
	if tlsClientCertFile != "" {
		identity, err := tlsKeyPair(tlsClientCertFile, tlsClientKeyFile, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{identity}
	}
	return config, nil
}

func getGRPCClient(ctx context.Context, addr string) (servicesv1.AssuranceServiceClient, *grpc.ClientConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	config, err := grpcClientTLSConfig()
	if err != nil {
		return nil, nil, err
	}
	connection, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		return nil, nil, fmt.Errorf("configure verified gRPC connection: %w", err)
	}
	return servicesv1.NewAssuranceServiceClient(connection), connection, nil
}

func grpcServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("serve requires --tls-cert-file and --tls-key-file before binding a network listener; plaintext is not supported")
	}
	identity, err := tlsKeyPair(certFile, keyFile, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}}
	if clientCAFile != "" {
		roots, err := trustedCAPool(clientCAFile)
		if err != nil {
			return nil, err
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = roots
	}
	return config, nil
}

func newGRPCServeCommand() *cobra.Command {
	var port int
	var certificate, key, clientCA string
	command := &cobra.Command{Use: "serve", Short: "Start the TLS gRPC service with unconfigured UNKNOWN assessment", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if port < 0 || port > 65535 {
			return fmt.Errorf("--port must be between 0 and 65535")
		}
		tlsConfig, err := grpcServerTLSConfig(certificate, key, clientCA)
		if err != nil {
			return err
		}
		var repo ports.EvidenceRepository
		if evidenceDir != "" {
			repo, err = storage.OpenFilesystemEvidenceRepository(evidenceDir)
			if err != nil {
				return fmt.Errorf("open evidence archive: %w", err)
			}
		}
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return err
		}
		limited := newLimitedListener(listener, 64)
		defer func() { _ = limited.Close() }()
		server := grpc.NewServer(grpc.UnaryInterceptor(recoverUnaryRPC), grpc.StreamInterceptor(recoverStreamRPC), grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.MaxRecvMsgSize(service.MaxRequestBytes), grpc.MaxSendMsgSize(16<<20), grpc.MaxConcurrentStreams(64), grpc.ConnectionTimeout(5*time.Second), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 5 * time.Minute, Time: 2 * time.Minute, Timeout: 20 * time.Second}))
		defer server.Stop()
		servicesv1.RegisterAssuranceServiceServer(server, service.NewServer(nil, repo))
		healthServer := health.NewServer()
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		healthServer.SetServingStatus(servicesv1.AssuranceService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
		grpc_health_v1.RegisterHealthServer(server, healthServer)
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "OSKAL TLS gRPC listening on %s; live assessment not configured: UNKNOWN\n", listener.Addr()); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ended := make(chan struct{})
		defer close(ended)
		go func() {
			select {
			case <-ended:
				return
			case <-ctx.Done():
			}
			healthServer.Shutdown()
			drained := make(chan struct{})
			go func() { server.GracefulStop(); close(drained) }()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-drained:
			case <-timer.C:
				server.Stop()
			}
		}()
		if err := server.Serve(limited); err != nil && err != grpc.ErrServerStopped {
			return err
		}
		return nil
	}}
	command.Flags().IntVar(&port, "port", 9090, "TLS gRPC port (0 selects an available port)")
	command.Flags().StringVar(&certificate, "tls-cert-file", "", "Required server certificate chain PEM")
	command.Flags().StringVar(&key, "tls-key-file", "", "Required private key matching the server certificate")
	command.Flags().StringVar(&clientCA, "tls-client-ca-file", "", "Require mutual TLS with client certificates verified by this CA bundle")
	return command
}

// Preserve the daemon's existing recovery boundary without returning private
// panic values to network peers.
func recoverUnaryRPC(ctx context.Context, request any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (response any, err error) {
	defer func() {
		if recover() != nil {
			err = status.Error(codes.Internal, "request processing failed")
		}
	}()
	return handler(ctx, request)
}
func recoverStreamRPC(server any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if recover() != nil {
			err = status.Error(codes.Internal, "stream processing failed")
		}
	}()
	return handler(server, stream)
}
