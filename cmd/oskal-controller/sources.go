package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	observerapi "github.com/cilium/cilium/api/v1/observer"
	tetragonapi "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/cilium"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragon"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/ingestion"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/apimachinery/pkg/util/validation"
)

type sourceTLS struct {
	CAFile     string `json:"ca_file"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	ServerName string `json:"server_name"`
}

type sourceSpec struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Namespace string    `json:"namespace"`
	Endpoint  string    `json:"endpoint"`
	TLS       sourceTLS `json:"tls"`
}

type sourceConfiguration struct {
	Sources []sourceSpec `json:"sources"`
}

func boundedFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte limit", maxBytes)
	}
	return raw, nil
}

func readSourceConfiguration(path string) (sourceConfiguration, error) {
	var config sourceConfiguration
	if path == "" {
		return config, nil
	}
	raw, err := boundedFile(path, 1<<20)
	if err != nil {
		return config, fmt.Errorf("read sources configuration: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("decode sources configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return config, fmt.Errorf("sources configuration must contain exactly one JSON object")
	}
	if len(config.Sources) == 0 || len(config.Sources) > collection.MaxSources {
		return config, fmt.Errorf("sources configuration requires 1..%d sources", collection.MaxSources)
	}
	seen := make(map[string]bool)
	for _, source := range config.Sources {
		if len(validation.IsDNS1123Label(source.ID)) != 0 || len(validation.IsDNS1123Label(source.Namespace)) != 0 || seen[source.ID] {
			return config, fmt.Errorf("source IDs must be unique DNS labels and each namespace must be explicit")
		}
		seen[source.ID] = true
		if source.Kind != "tetragon" && source.Kind != "hubble" {
			return config, fmt.Errorf("unsupported runtime source kind %q", source.Kind)
		}
		if host, _, err := net.SplitHostPort(source.Endpoint); err != nil || host == "" || strings.ContainsAny(source.Endpoint, " /@\r\n") {
			return config, fmt.Errorf("source %s requires an explicit host:port endpoint", source.ID)
		}
	}
	sort.Slice(config.Sources, func(i, j int) bool { return config.Sources[i].ID < config.Sources[j].ID })
	return config, nil
}

func sourceTransport(config sourceTLS) (*tls.Config, string, string, error) {
	if config.CAFile == "" || config.CertFile == "" || config.KeyFile == "" || config.ServerName == "" {
		return nil, "", "", fmt.Errorf("explicit CA, client certificate, client key and exact server name are required")
	}
	if len(validation.IsDNS1123Subdomain(config.ServerName)) != 0 && net.ParseIP(config.ServerName) == nil {
		return nil, "", "", fmt.Errorf("source server name must be a concrete DNS name or IP address, never a wildcard")
	}
	ca, err := boundedFile(config.CAFile, 1<<20)
	if err != nil {
		return nil, "", "", fmt.Errorf("read source CA: %w", err)
	}
	cert, err := boundedFile(config.CertFile, 1<<20)
	if err != nil {
		return nil, "", "", fmt.Errorf("read source client certificate: %w", err)
	}
	key, err := boundedFile(config.KeyFile, 1<<20)
	if err != nil {
		return nil, "", "", fmt.Errorf("read source client key: %w", err)
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, "", "", fmt.Errorf("source client certificate/key do not form an identity: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, "", "", fmt.Errorf("source CA file contains no usable certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}, ServerName: config.ServerName}, assurance.ComputeDigest(ca), assurance.ComputeDigest(cert), nil
}

type identitySigner struct {
	*receipts.ReceiptManager
	workload *spire.WorkloadClient
}

func (s *identitySigner) check(ctx context.Context) error {
	if s.workload == nil {
		return nil // Explicit local-key authority; no SPIFFE identity is claimed.
	}
	_, err := s.workload.Identity(ctx)
	return err
}

func (s *identitySigner) SignEvidence(ctx context.Context, envelope assurance.EvidenceEnvelope) (assurance.EvidenceEnvelope, error) {
	if err := s.check(ctx); err != nil {
		return assurance.EvidenceEnvelope{}, fmt.Errorf("signing identity unavailable: %w", err)
	}
	return s.ReceiptManager.SignEvidence(ctx, envelope)
}

func (s *identitySigner) SignReceipt(ctx context.Context, receipt assurance.ControlReceipt) (assurance.ControlReceipt, error) {
	if err := s.check(ctx); err != nil {
		return assurance.ControlReceipt{}, fmt.Errorf("receipt identity unavailable: %w", err)
	}
	return s.ReceiptManager.SignReceipt(ctx, receipt)
}

type preparedSource struct {
	spec sourceSpec
	tls  *tls.Config
}

type sourceGroup struct {
	sources           []preparedSource
	candidates        *collection.Candidates
	resolver          *binding.Resolver
	producer          assurance.AuthorityRef
	window            time.Duration
	clockAhead        time.Duration
	authoritySnapshot []byte
}

func prepareSources(config sourceConfiguration, archive ports.EvidenceRepository, signer *identitySigner, producer assurance.AuthorityRef, resolver *binding.Resolver, window, clockAhead time.Duration) (*sourceGroup, *verifier.DefaultEvidenceVerifier, string, error) {
	if window < time.Second || window > 5*time.Minute || clockAhead < 0 || clockAhead > time.Second {
		return nil, nil, "", fmt.Errorf("source session window must be 1s..5m and explicit clock allowance 0..1s")
	}
	var descriptors []struct{ ID, Kind, Namespace, Endpoint, ServerName, CADigest, ClientCertificateDigest string }
	var prepared []preparedSource
	var candidates []collection.SourceConfig
	for _, spec := range config.Sources {
		transport, ca, cert, err := sourceTransport(spec.TLS)
		if err != nil {
			return nil, nil, "", fmt.Errorf("source %s: %w", spec.ID, err)
		}
		prepared = append(prepared, preparedSource{spec: spec, tls: transport})
		descriptors = append(descriptors, struct{ ID, Kind, Namespace, Endpoint, ServerName, CADigest, ClientCertificateDigest string }{spec.ID, spec.Kind, spec.Namespace, spec.Endpoint, spec.TLS.ServerName, ca, cert})
		candidates = append(candidates, collection.SourceConfig{ID: spec.ID, Producer: producer, Signer: signer})
	}
	registry, err := collection.NewCandidates(archive, candidates, 4096)
	if err != nil {
		return nil, nil, "", err
	}
	raw, err := json.Marshal(struct {
		Producer  string
		PublicKey string
		Sources   any
	}{producer.Canonical(), signer.PublicKey(), struct {
		Sources                   any
		SessionWindow, ClockAhead string
	}{descriptors, window.String(), clockAhead.String()}})
	if err != nil {
		return nil, nil, "", err
	}
	digest := sha256.Sum256(raw)
	authorityDigest := "sha256:" + hex.EncodeToString(digest[:])
	bound, err := resolver.WithAuthorityDigest(authorityDigest)
	if err != nil {
		return nil, nil, "", err
	}
	publicKey, err := hex.DecodeString(signer.PublicKey())
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, "", fmt.Errorf("producer public key is invalid")
	}
	verification := verifier.NewDefaultEvidenceVerifier()
	verification.RegisterPublicKey(producer.Canonical(), ed25519.PublicKey(publicKey))
	return &sourceGroup{sources: prepared, candidates: registry, resolver: bound, producer: producer, window: window, clockAhead: clockAhead, authoritySnapshot: raw}, verification, authorityDigest, nil
}

// Start keeps the controller alive while individual sources fail closed. Each
// stream has one retry owner and at most three consecutive failed sessions.
func (g *sourceGroup) Start(ctx context.Context) error {
	var workers sync.WaitGroup
	for _, source := range g.sources {
		workers.Add(1)
		go func() { defer workers.Done(); g.follow(ctx, source) }()
	}
	<-ctx.Done()
	workers.Wait()
	return nil
}

func (g *sourceGroup) NeedLeaderElection() bool { return true }

func (g *sourceGroup) follow(ctx context.Context, source preparedSource) {
	failures := 0
	for failures < 3 && ctx.Err() == nil {
		session, err := g.candidates.BeginSession(source.spec.ID)
		if err != nil {
			setupLog.Error(err, "cannot start evidence source", "source", source.spec.ID)
			return
		}
		streamCtx, cancel := context.WithTimeout(ctx, g.window)
		connection, err := grpc.NewClient(source.spec.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(source.tls)))
		if err == nil {
			repository := &boundEvidenceRepository{EvidenceRepository: session.Repository(), resolver: g.resolver}
			writer := &ingestion.Writer{Repository: repository, Resolver: g.resolver, MaxClockAhead: g.clockAhead}
			if source.spec.Kind == "tetragon" {
				err = (&tetragon.Collector{Connection: connection, Producer: g.producer, Writer: writer, Namespace: source.spec.Namespace}).Run(streamCtx)
			} else {
				err = (&cilium.Collector{Connection: connection, Producer: g.producer, Writer: writer, Namespace: source.spec.Namespace}).Run(streamCtx)
			}
		}
		windowEnded := errors.Is(streamCtx.Err(), context.DeadlineExceeded)
		cancel()
		reason := "source stream ended"
		if err != nil {
			reason = err.Error()
		}
		_ = session.End(reason)
		// A responsive management API permits another observation window even
		// when the workload is quiet. It never creates eligible workload evidence.
		renew := false
		if windowEnded && ctx.Err() == nil && connection != nil {
			probeCtx, probeCancel := context.WithTimeout(ctx, 3*time.Second)
			if source.spec.Kind == "tetragon" {
				response, probeErr := tetragonapi.NewFineGuidanceSensorsClient(connection).GetVersion(probeCtx, &tetragonapi.GetVersionRequest{})
				renew = probeErr == nil && response != nil && response.Version != ""
			} else {
				response, probeErr := observerapi.NewObserverClient(connection).ServerStatus(probeCtx, &observerapi.ServerStatusRequest{})
				renew = probeErr == nil && response != nil
			}
			probeCancel()
		}
		if connection != nil {
			_ = connection.Close()
		}
		if ctx.Err() != nil || errors.Is(err, collection.ErrSaturated) {
			return
		}
		if renew {
			failures = 0
		} else {
			failures++
			setupLog.Error(err, "source unavailable; eligible evidence invalidated", "source", source.spec.ID, "failedSessions", failures)
		}
		if failures == 3 {
			_ = session.End("three failed source sessions; inspect endpoint, certificates and source health before restarting the controller")
			return
		}
		timer := time.NewTimer(time.Duration(failures+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type boundEvidenceRepository struct {
	ports.EvidenceRepository
	resolver *binding.Resolver
}

func (r *boundEvidenceRepository) Put(ctx context.Context, envelope assurance.EvidenceEnvelope, payload io.Reader) (assurance.EvidenceRef, error) {
	resolved, err := r.resolver.ContextForSubject(ctx, envelope.Subject)
	if err != nil {
		return assurance.EvidenceRef{}, err
	}
	if envelope.Epoch != resolved.Epoch {
		return assurance.EvidenceRef{}, fmt.Errorf("binding or workload epoch changed before evidence persistence")
	}
	envelope.ControlRefs = nil
	for _, requirement := range resolved.Contract.Requirements {
		if requirement.EvidenceType != envelope.ObservationType {
			continue
		}
		for _, producer := range requirement.AcceptedProducers {
			if producer == envelope.Producer.Canonical() {
				envelope.ControlRefs = resolved.Controls
				return r.EvidenceRepository.Put(ctx, envelope, payload)
			}
		}
	}
	// Unmapped source facts remain archived, with no invented control standing.
	return r.EvidenceRepository.Put(ctx, envelope, payload)
}
