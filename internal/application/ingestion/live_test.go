package ingestion_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	observerapi "github.com/cilium/cilium/api/v1/observer"
	tetragonapi "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/cilium"
	kubeadapter "github.com/ckodex-labs/ckodex-oskal/internal/adapters/kubernetes"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragon"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/ingestion"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// TestLiveRuntimeCapture requires real sources and a caller-managed non-root Pod
// generating process executions and outbound network flows. No server is faked.
// Both source APIs require explicit mTLS, including loopback port-forwards.
func TestLiveRuntimeCapture(t *testing.T) {
	kubeconfig := os.Getenv("OSKAL_LIVE_KUBECONFIG")
	if kubeconfig == "" {
		for _, variable := range os.Environ() {
			key, value, _ := strings.Cut(variable, "=")
			if strings.HasPrefix(key, "OSKAL_LIVE_") && value != "" {
				t.Fatal("partially configured live capture requires OSKAL_LIVE_KUBECONFIG")
			}
		}
		t.Skip("live Kubernetes, Hubble and Tetragon endpoints were not configured")
	}
	namespace, podName := os.Getenv("OSKAL_LIVE_NAMESPACE"), os.Getenv("OSKAL_LIVE_POD")
	if namespace == "" || podName == "" {
		t.Fatal("OSKAL_LIVE_NAMESPACE and OSKAL_LIVE_POD are required")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubeclient.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	resolver := ports.CaptureResolverFunc(func(ctx context.Context, event ports.CapturedEvent) (assurance.SubjectRef, assurance.AssuranceEpoch, error) {
		observed := event.Subject
		pod, err := client.CoreV1().Pods(observed.Attributes["namespace"]).Get(ctx, observed.Attributes["name"], metav1.GetOptions{})
		if err != nil {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
		}
		if uid := observed.Attributes["uid"]; uid != "" && uid != string(pod.UID) {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("captured pod UID differs from live pod UID")
		}
		if event.CapturedAt.Before(pod.CreationTimestamp.Time) {
			return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("captured event predates live pod creation")
		}
		subject := kubeadapter.BuildPodSubjectRef(pod)
		return subject, assurance.AssuranceEpoch{SubjectDigest: kubeadapter.ComputePodDigest(pod)}, nil
	})
	for _, source := range []string{"tetragon", "hubble"} {
		t.Run(source, func(t *testing.T) {
			endpoint := os.Getenv("OSKAL_LIVE_" + map[string]string{"tetragon": "TETRAGON", "hubble": "HUBBLE"}[source] + "_ENDPOINT")
			if endpoint == "" {
				t.Fatal("live source endpoint is required")
			}
			tlsConfig := liveSourceTLSConfig(t, source)
			verifyLiveSourceTLSRejection(t, source, endpoint, tlsConfig)
			transport := credentials.NewTLS(tlsConfig)
			conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(transport))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Errorf("close live connection: %v", err)
				}
			}()
			dir := os.Getenv("OSKAL_LIVE_EVIDENCE_DIR")
			if dir == "" {
				dir = t.TempDir()
			}
			repo, err := storage.NewFilesystemEvidenceRepository(filepath.Join(dir, source))
			if err != nil {
				t.Fatal(err)
			}
			writer := &ingestion.Writer{Repository: repo, Resolver: resolver, MaxClockAhead: time.Second}
			producer := assurance.AuthorityRef{Scheme: "local-test", Subject: source}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			var run func(context.Context) error
			expected := "network.flow.observed"
			if source == "hubble" {
				run = (&cilium.Collector{Connection: conn, Namespace: namespace, Producer: producer, Writer: writer}).Run
			} else {
				run = (&tetragon.Collector{Connection: conn, Namespace: namespace, Producer: producer, Writer: writer}).Run
				expected = "workload.runtime.process.euid.nonroot"
			}
			result := make(chan error, 1)
			started := time.Now()
			go func() { result <- run(ctx) }()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-result:
					t.Fatalf("live source stopped before eligible evidence: %v", err)
				case <-ctx.Done():
					t.Fatal("no eligible runtime evidence received before deadline")
				case <-ticker.C:
					envelopes, err := repo.ListBySubject(ctx, assurance.SubjectRef{Scheme: "k8s", ID: namespace + "/Pod/" + podName})
					if err != nil {
						t.Fatal(err)
					}
					for _, envelope := range envelopes {
						if envelope.ObservationType != expected || envelope.CapturedAt.Before(started) {
							continue
						}
						if ok, err := repo.Verify(ctx, envelope.Artifact); err != nil || !ok {
							t.Fatalf("stored real event does not verify: %v", err)
						}
						contract := assurance.EvidenceContract{Requirements: []assurance.EvidenceRequirement{{ID: "isolation", EvidenceType: "network.flow.isolation", Required: true}}}
						if result := contract.Evaluate(envelopes, envelope.Epoch, time.Now()); result.State != assurance.AssuranceStateUnknown {
							t.Fatalf("observed facts cannot prove isolation: state=%s", result.State)
						}
						cancel()
						if err := <-result; err != nil && !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
							t.Fatalf("live source did not stop through cancellation: %v", err)
						}
						t.Logf("captured real %s subject=%s artifact=%s", envelope.ObservationType, envelope.Subject.URI(), envelope.Artifact.Digest)
						return
					}
				}
			}
		})
	}
}

func liveSourceTLSConfig(t *testing.T, source string) *tls.Config {
	t.Helper()
	prefix := "OSKAL_LIVE_" + strings.ToUpper(source) + "_"
	for _, setting := range []string{"CA", "CERT", "KEY", "SERVER_NAME"} {
		if os.Getenv(prefix+setting) == "" {
			t.Fatalf("%s%s is required for authenticated live capture", prefix, setting)
		}
	}
	ca, err := os.ReadFile(os.Getenv(prefix + "CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("live source CA certificate is invalid")
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv(prefix+"CERT"), os.Getenv(prefix+"KEY"))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert},
		ServerName: os.Getenv(prefix + "SERVER_NAME"),
	}
}

func verifyLiveSourceTLSRejection(t *testing.T, source, endpoint string, config *tls.Config) {
	t.Helper()
	for _, test := range []string{"missing-client-certificate", "wrong-server-name"} {
		t.Run(test, func(t *testing.T) {
			denied := config.Clone()
			if test == "missing-client-certificate" {
				denied.Certificates = nil
			} else {
				denied.ServerName = "untrusted.invalid"
			}
			conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(denied)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Errorf("close denied live connection: %v", err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if source == "hubble" {
				_, err = observerapi.NewObserverClient(conn).ServerStatus(ctx, &observerapi.ServerStatusRequest{})
			} else {
				_, err = tetragonapi.NewFineGuidanceSensorsClient(conn).GetVersion(ctx, &tetragonapi.GetVersionRequest{})
			}
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("live source did not reject invalid TLS identity: %v", err)
			}
			t.Logf("real %s rejected %s: %v", source, test, err)
		})
	}
}
