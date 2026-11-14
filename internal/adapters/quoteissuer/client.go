package quoteissuer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	pb "github.com/ckodex-labs/ckodex-oskal/proto/assurance/attestation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ClientConfig struct {
	Address          string
	TLS              *tls.Config
	ExportPrivateKey ed25519.PrivateKey
}
type Client struct {
	conn    *grpc.ClientConn
	rpc     pb.QuoteIssuerClient
	signer  *signedrecords.Signer
	keyHash [32]byte
}

var _ ports.AttestationProvider = (*Client)(nil)

func NewClient(c ClientConfig) (*Client, error) {
	if c.Address == "" || c.TLS == nil || c.TLS.InsecureSkipVerify || c.TLS.RootCAs == nil || c.TLS.ServerName == "" || len(c.TLS.Certificates) == 0 {
		return nil, fmt.Errorf("explicit address, verified server name/CA and mTLS client certificate required")
	}
	signer, err := signedrecords.NewSigner(c.ExportPrivateKey)
	if err != nil {
		return nil, err
	}
	secured := c.TLS.Clone()
	secured.MinVersion = tls.VersionTLS13
	conn, err := grpc.NewClient(c.Address, grpc.WithTransportCredentials(credentials.NewTLS(secured)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxWireBytes), grpc.MaxCallSendMsgSize(maxWireBytes)), grpc.WithDisableRetry())
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, rpc: pb.NewQuoteIssuerClient(conn), signer: signer, keyHash: sha256.Sum256(c.ExportPrivateKey.Public().(ed25519.PublicKey))}, nil
}
func (c *Client) Close() error { return c.conn.Close() }
func (c *Client) Attest(ctx context.Context, qualification [64]byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	challenge, err := c.rpc.Challenge(ctx, &pb.ChallengeRequest{})
	if err != nil {
		return nil, err
	}
	if len(challenge.Nonce) != 32 || challenge.IssuedUnixNano <= 0 {
		return nil, fmt.Errorf("broker returned malformed challenge")
	}
	payload, err := json.Marshal(proof{Qualification: qualification[:], Nonce: challenge.Nonce, IssuedUnixNano: challenge.IssuedUnixNano, ExportKeyHash: c.keyHash[:]})
	if err != nil {
		return nil, err
	}
	signed, err := c.signer.Sign(ctx, proofType, payload)
	if err != nil {
		return nil, err
	}
	response, err := c.rpc.Issue(ctx, &pb.IssueRequest{SignedProof: signed})
	if err != nil {
		return nil, err
	}
	if response.RootLabel != SoftwareRootLabel || response.Limitations != SoftwareLimitations {
		return nil, fmt.Errorf("broker omitted software-root limitations")
	}
	if len(response.AttestationReport) == 0 || len(response.AttestationReport) > 4096 {
		return nil, fmt.Errorf("broker returned invalid report length")
	}
	return bytes.Clone(response.AttestationReport), nil
}
