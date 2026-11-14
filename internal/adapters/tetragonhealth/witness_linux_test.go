//go:build linux

package tetragonhealth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"testing"
	"time"
)

// This acceptance gate requires an actual running Tetragon sensor and externally
// enrolled identity/role documents. There is deliberately no fake map reader.
func TestWitnessNativeTetragon(t *testing.T) {
	path := os.Getenv("OSKAL_TETRAGON_HEALTH_NATIVE_INPUT")
	if path == "" {
		t.Skip("actual Linux Tetragon sensor, authenticated enrollment and read grant were not supplied")
	}
	raw, err := readBoundedFile(path, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Enrollment Enrollment `json:"enrollment"`
		Grant      RoleGrant  `json:"grant"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("native input contains trailing data")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	witness, err := ReadWitness(ctx, input.Enrollment, input.Grant)
	if err != nil {
		t.Fatal(err)
	}
	if len(witness.Loss) != 256*7 || witness.PossibleCPUs < 1 || len(witness.Maps) != len(input.Enrollment.Maps) {
		t.Fatalf("actual native read omitted ABI facts: %+v", witness)
	}
	for _, m := range witness.Maps {
		if (m.Name == "execve_map" || m.Name == "tg_execve_joined_info_map") && m.Stats == nil {
			t.Fatalf("actual native map statistics missing: %+v", m)
		}
	}
	if !input.Enrollment.ThrottleEnabled && (witness.Availability != Unknown || witness.Throttle.Availability != Unknown) {
		t.Fatal("unmeasured disabled configuration was promoted to complete visibility")
	}
	if os.Getenv("OSKAL_TETRAGON_HEALTH_EXPECT_ZERO") == "1" {
		for _, failure := range witness.Loss {
			if failure.Value != 0 {
				t.Fatalf("actual native baseline has kernel loss: %+v", failure)
			}
		}
	}
	raw, err = json.Marshal(witness)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Actual native witness: %s", raw)
}

func TestOperationTimeGrantAgainstActualCredentials(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	credentials, err := CurrentCredentials()
	if err != nil {
		t.Fatal(err)
	}
	enrollment := Enrollment{Digest: digest([]byte("actual-credential-read-test"))}
	grant := RoleGrant{Role: readRole, Digest: digest([]byte("test-local-role-policy")), EnrollmentDigest: enrollment.Digest, ValidUntil: time.Now().Add(time.Minute), Credentials: credentials}
	r := nativeRead{grant: grant, enrollment: enrollment}
	if err := r.check(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.grant.ValidUntil = time.Now().Add(-time.Second)
	if err := r.check(t.Context()); err == nil {
		t.Fatal("expired role accepted")
	}
	r.grant = grant
	r.grant.Credentials.EffectiveUID ^= 1
	if err := r.check(t.Context()); err == nil {
		t.Fatal("actual effective UID mismatch accepted")
	}
	r.grant = grant
	r.grant.EnrollmentDigest = digest([]byte("different-enrollment"))
	if err := r.check(t.Context()); err == nil {
		t.Fatal("grant from another enrollment accepted")
	}
}
