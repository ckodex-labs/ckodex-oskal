package guestproducer

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/guesttransport"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/quoteissuer"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonsampler"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Run owns actual source I/O. No read grant, TPM credential, missing sample or
// successful quote is synthesized here. The host owns broker and enrollment.
func Run(ctx context.Context, config Config) (guesttransport.ClientStatus, error) {
	var empty guesttransport.ClientStatus
	if ctx == nil {
		return empty, fmt.Errorf("source requires a cancellable runtime context")
	}
	if err := config.Validate(); err != nil {
		return empty, err
	}
	keyText, err := readRegular(config.ExportKeyFile, 130, true)
	if err != nil {
		return empty, err
	}
	private, err := hex.DecodeString(strings.TrimSpace(string(keyText)))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return empty, fmt.Errorf("restore the outside-registered 64-byte Ed25519 export key")
	}
	if _, err := signedrecords.NewSigner(private); err != nil {
		return empty, err
	}
	transportTLS, err := loadTLS(config.TransportTLS)
	if err != nil {
		return empty, err
	}
	brokerTLS, err := loadTLS(config.BrokerTLS)
	if err != nil {
		return empty, err
	}
	grantKey, err := publicKey(config.GrantKey)
	if err != nil {
		return empty, err
	}
	receiptKey, err := publicKey(config.ReceiptKey)
	if err != nil {
		return empty, err
	}
	if err := DropCapabilities(); err != nil {
		return empty, fmt.Errorf("drop source capabilities before collection; use the supported static Linux build: %w", err)
	}
	// This is a local, enrolled Unix socket with explicit DAC validation by the
	// sampler, never an unauthenticated remote gRPC connection.
	connection, err := grpc.NewClient("unix://"+config.TetragonSocket, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry())
	if err != nil {
		return empty, err
	}
	defer func() { _ = connection.Close() }()
	sampler, err := tetragonsampler.New(tetragonsampler.Config{Connection: connection, Metrics: tetragonhealth.MetricsReader{Endpoint: config.MetricsEndpoint, Timeout: config.ReadTimeout, Limits: tetragonhealth.DefaultLimits()}, Native: config.Native, GrantPath: config.GrantFile, GrantKey: grantKey, SourceInstance: config.Enrollment.SourceInstance, Namespace: config.Namespace, ReadTimeout: config.ReadTimeout, SocketOwnerUID: config.SocketOwnerUID, SocketOwnerGID: config.SocketOwnerGID})
	if err != nil {
		return empty, err
	}
	if err := sampler.Start(ctx); err != nil {
		return empty, err
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sampler.Close(stop)
	}()
	attester, err := quoteissuer.NewClient(quoteissuer.ClientConfig{Address: config.BrokerTarget, TLS: brokerTLS, ExportPrivateKey: private})
	if err != nil {
		return empty, err
	}
	defer func() { _ = attester.Close() }()
	client, err := guesttransport.NewClient(guesttransport.ClientConfig{Target: config.Target, TLS: transportTLS, EnrollmentID: config.EnrollmentID, Enrollment: config.Enrollment, Receipt: guesttransport.ReceiptScope{Key: receiptKey, Authority: config.ReceiptAuthority, Subject: config.Subject, Control: config.Control, Epoch: config.Epoch}, ExportKey: private, Attester: attester, Sampler: sampler, Limits: config.TransportLimits})
	if err != nil {
		return empty, err
	}
	err = client.Run(ctx)
	return client.Status(), err
}
