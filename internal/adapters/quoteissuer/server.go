package quoteissuer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	pb "github.com/ckodex-labs/ckodex-oskal/proto/assurance/attestation/v1"
	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// SoftwareLimitations accompanies every broker response. The TPM report also
// preserves its exact software-root label for downstream attestation verification.
const SoftwareLimitations = "Outside-owned ELF file measurement only; does not prove runtime memory integrity, key non-extractability, co-residence, or resistance to guest or host root."
const SoftwareRootLabel = "software TPM root — not hardware-backed"

const proofType = "application/vnd.oskal.quote-authorization.v1+json"
const maxWireBytes = 8192
const maxProofBytes = 1024

// Config is outside-owned enrollment. No request can replace the client pin,
// export public key, inspector, or TPM provider. A restart invalidates nonces.
type Config struct {
	Provider                       ports.AttestationProvider
	Inspector                      Inspector
	AllowedClientCertificateDigest [32]byte
	ExportPublicKey                ed25519.PublicKey
	TLS                            *tls.Config
	ProofTTL                       time.Duration
	Capacity                       int
}
type proof struct {
	Qualification  []byte `json:"qualification"`
	Nonce          []byte `json:"nonce"`
	IssuedUnixNano int64  `json:"issuedUnixNano"`
	ExportKeyHash  []byte `json:"exportKeyHash"`
}
type Server struct {
	pb.UnimplementedQuoteIssuerServer
	config     Config
	grpc       *grpc.Server
	mu         sync.Mutex
	challenges map[[32]byte]time.Time
	gate       chan struct{}
}

func NewServer(c Config) (*Server, error) {
	if c.Provider == nil || c.Inspector == nil || len(c.ExportPublicKey) != ed25519.PublicKeySize || c.AllowedClientCertificateDigest == ([32]byte{}) {
		return nil, fmt.Errorf("provider, outside inspector, client leaf pin and export public key are required")
	}
	if c.TLS == nil || len(c.TLS.Certificates) == 0 || c.TLS.ClientCAs == nil || c.TLS.GetConfigForClient != nil {
		return nil, fmt.Errorf("fixed server TLS certificate and client CA required")
	}
	if c.ProofTTL <= 0 || c.ProofTTL > time.Minute || c.Capacity <= 0 || c.Capacity > 1024 {
		return nil, fmt.Errorf("proof TTL must be 0..1 minute and capacity 1..1024")
	}
	c.ExportPublicKey = bytes.Clone(c.ExportPublicKey)
	secured := c.TLS.Clone()
	secured.MinVersion = tls.VersionTLS13
	secured.ClientAuth = tls.RequireAndVerifyClientCert
	s := &Server{config: c, challenges: make(map[[32]byte]time.Time), gate: make(chan struct{}, 8)}
	s.grpc = grpc.NewServer(grpc.Creds(credentials.NewTLS(secured)), grpc.MaxRecvMsgSize(maxWireBytes), grpc.MaxSendMsgSize(maxWireBytes), grpc.MaxConcurrentStreams(8), grpc.ConnectionTimeout(5*time.Second), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: time.Minute, MaxConnectionAge: 5 * time.Minute, MaxConnectionAgeGrace: 5 * time.Second}), grpc.UnaryInterceptor(s.authorize))
	pb.RegisterQuoteIssuerServer(s.grpc, s)
	return s, nil
}

// Serve owns the listener until cancellation; at most 16 TCP connections and
// eight active RPCs are admitted. There are no automatic quote retries.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, s.grpc.Stop)
	defer stop()
	err := s.grpc.Serve(netutil.LimitListener(l, 16))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
func (s *Server) authorize(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "verified TLS peer required")
	}
	secured, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || secured.State.Version != tls.VersionTLS13 || len(secured.State.VerifiedChains) == 0 || len(secured.State.PeerCertificates) == 0 || sha256.Sum256(secured.State.PeerCertificates[0].Raw) != s.config.AllowedClientCertificateDigest {
		return nil, status.Error(codes.PermissionDenied, "client certificate is not enrolled")
	}
	now := time.Now()
	for _, certificate := range secured.State.VerifiedChains[0] {
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, status.Error(codes.Unauthenticated, "client certificate chain expired")
		}
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	default:
		return nil, status.Error(codes.ResourceExhausted, "quote broker concurrency exhausted")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	return next(ctx, req)
}
func (s *Server) Challenge(ctx context.Context, _ *pb.ChallengeRequest) (*pb.ChallengeResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for nonce, issued := range s.challenges {
		if now.Sub(issued) >= s.config.ProofTTL {
			delete(s.challenges, nonce)
		}
	}
	if len(s.challenges) >= s.config.Capacity {
		return nil, status.Error(codes.ResourceExhausted, "proof challenge capacity exhausted")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, status.Error(codes.Internal, "challenge entropy unavailable")
	}
	if _, exists := s.challenges[nonce]; exists {
		return nil, status.Error(codes.Internal, "challenge collision")
	}
	s.challenges[nonce] = now
	return &pb.ChallengeResponse{Nonce: nonce[:], IssuedUnixNano: now.UnixNano()}, nil
}
func (s *Server) Issue(ctx context.Context, req *pb.IssueRequest) (*pb.IssueResponse, error) {
	payload, err := signedrecords.Verify(ctx, req.GetSignedProof(), proofType, s.config.ExportPublicKey, maxProofBytes)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "export key proof rejected")
	}
	var claim proof
	if err := signedrecords.DecodeJSON(payload, &claim, maxProofBytes); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid proof schema")
	}
	keyHash := sha256.Sum256(s.config.ExportPublicKey)
	if len(claim.Qualification) != 64 || len(claim.Nonce) != 32 || !bytes.Equal(claim.ExportKeyHash, keyHash[:]) {
		return nil, status.Error(codes.PermissionDenied, "proof binding rejected")
	}
	nonce := [32]byte(claim.Nonce)
	s.mu.Lock()
	issued, ok := s.challenges[nonce]
	delete(s.challenges, nonce)
	s.mu.Unlock()
	if !ok || issued.UnixNano() != claim.IssuedUnixNano || time.Since(issued) >= s.config.ProofTTL {
		return nil, status.Error(codes.PermissionDenied, "proof nonce unknown, consumed, or expired")
	}
	if err := s.config.Inspector.Verify(ctx); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "outside measurement rejected")
	}
	report, err := s.config.Provider.Attest(ctx, [64]byte(claim.Qualification))
	if err != nil {
		return nil, status.Error(codes.Unavailable, "TPM quote unavailable")
	}
	if err := s.config.Inspector.Verify(ctx); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "outside measurement changed during quote")
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if time.Since(issued) >= s.config.ProofTTL {
		return nil, status.Error(codes.PermissionDenied, "proof expired during quote")
	}
	if len(report) == 0 || len(report) > 4096 {
		return nil, status.Error(codes.Internal, "TPM report exceeded bounds")
	}
	return &pb.IssueResponse{AttestationReport: report, RootLabel: SoftwareRootLabel, Limitations: SoftwareLimitations}, nil
}
