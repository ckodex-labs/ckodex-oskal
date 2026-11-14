//go:build integration

package tetragonsampler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type nativeInput struct {
	Native    tetragonhealth.Enrollment `json:"native"`
	GrantPath string                    `json:"grantPath"`
	GrantKey  ed25519.PublicKey         `json:"grantKey"`
}

// The HOST operator invokes this explicitly for the already-authorized test
// scope. Never run this issuer on the measured node or copy its private key there.
func TestIssueOperatorReadGrant(t *testing.T) {
	input := os.Getenv("OSKAL_OPERATOR_INPUT")
	directory := os.Getenv("OSKAL_OPERATOR_OUTPUT")
	if input == "" || directory == "" {
		t.Fatal("explicit host operator inventory/output required; no self-grant default")
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Enrollment tetragonhealth.Enrollment `json:"enrollment"`
		Grant      tetragonhealth.RoleGrant  `json:"grant"`
	}
	if err := signedrecords.DecodeJSON(raw, &fixture, 64<<10); err != nil {
		t.Fatal(err)
	}
	if fixture.Grant.Credentials.EffectiveUID != 0 || fixture.Grant.Credentials.FilesystemUID != 0 || fixture.Grant.Credentials.EffectiveCaps != 0 {
		t.Fatal("outside authorized fixture is root UID with no effective capabilities")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signedrecords.NewSigner(private)
	if err != nil {
		t.Fatal(err)
	}
	grant := fixture.Grant
	grant.Role = "tetragon.health.read"
	grant.Digest = ""
	grant.EnrollmentDigest = fixture.Enrollment.Digest
	grant.ValidUntil = time.Now().UTC().Add(3 * time.Minute)
	payload, err := json.Marshal(ReadGrant{RoleGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(t.Context(), ReadGrantPayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(nativeInput{Native: fixture.Enrollment, GrantPath: "/oskal-sampler-grant.dsse", GrantKey: public})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"issuer.private": private, "issuer.public": public, "grant.dsse": signed, "native-input.json": manifest} {
		temp, err := os.CreateTemp(directory, ".issue-")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := temp.Write(data); err != nil {
			_ = temp.Close()
			t.Fatal(err)
		}
		if err := temp.Sync(); err != nil {
			_ = temp.Close()
			t.Fatal(err)
		}
		if err := temp.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temp.Name(), filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("outside HOST issuer signed exact enrollment %s, root UID/caps0 credentials, expires %s; private key remains only in protected host output", fixture.Enrollment.Digest, grant.ValidUntil.Format(time.RFC3339))
}

// Requires the actual enrolled Linux node and operator-signed input. No test
// sensor, metrics handler, native map reader or stream implementation is supplied.
func TestNativeSampler(t *testing.T) {
	path := os.Getenv("OSKAL_SAMPLER_INPUT")
	if path == "" {
		t.Fatal("actual outside-enrolled native input required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input nativeInput
	if err := signedrecords.DecodeJSON(raw, &input, 64<<10); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	connection, err := grpc.NewClient("unix:///var/run/tetragon/tetragon.sock", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	sampler, err := New(Config{Connection: connection, Metrics: tetragonhealth.MetricsReader{Endpoint: "http://127.0.0.1:2112/metrics", Timeout: time.Second, Limits: tetragonhealth.DefaultLimits()}, Native: input.Native, GrantPath: input.GrantPath, GrantKey: input.GrantKey, SourceInstance: input.Native.Digest, Namespace: "oskal-p2-native", ReadTimeout: 3 * time.Second, SocketOwnerUID: 0, SocketOwnerGID: 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := sampler.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := sampler.Close(closeCtx); err != nil {
			t.Error(err)
		}
	}()
	for sequence := range 2 {
		sample, err := sampler.Sample(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(sample.HealthEvidence) != 1 || len(sample.Counters) != len(RequiredSignals()) {
			t.Fatal("incomplete actual signed sample input")
		}
		var health HealthEvidence
		if err := json.Unmarshal(sample.HealthEvidence[0].Payload, &health); err != nil {
			t.Fatal(err)
		}
		grantRaw, err := os.ReadFile(input.GrantPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(grantRaw, health.SignedReadGrant) || health.Kernel.GrantDigest != assurance.ComputeDigest(grantRaw) || health.Kernel.Availability != tetragonhealth.Observed {
			t.Fatal("actual grant/native witness provenance lost")
		}
		unknown := 0
		for _, counter := range sample.Counters {
			if counter.Status == assurance.TelemetrySignalUnknown {
				unknown++
			}
		}
		data, err := json.MarshalIndent(sample, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		output := os.Getenv("OSKAL_SAMPLER_OUTPUT")
		if output != "" {
			if err := os.WriteFile(output, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("sample=%d API=%s source=%s metricsBytes=%d nativeCells=%d counters=%d unknown=%d events=%d healthBytes=%d fullSampleBytes=%d", sequence, health.APIVersion, sample.SourceInstance, health.Metrics.Bytes, len(health.Kernel.Loss), len(sample.Counters), unknown, len(sample.Observations), len(sample.HealthEvidence[0].Payload), len(data))
		for _, family := range health.Metrics.Families {
			t.Logf("family=%s kind=%s availability=%s series=%d", family.Name, family.Kind, family.Availability, len(family.Series))
		}
		time.Sleep(150 * time.Millisecond)
	}
}
