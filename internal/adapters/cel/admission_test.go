package cel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func TestSuppliedPolicyDigestBindsFullSpecAndIdentity(t *testing.T) {
	raw := []byte(`{"metadata":{"name":"authored-definition","uid":"declared-uid","generation":1},"spec":{"failurePolicy":"Fail","validations":[{"expression":"true","message":"authored example only"}]}}`)
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policy admissionregistrationv1.ValidatingAdmissionPolicy
	if err := json.Unmarshal(actual, &policy); err != nil {
		t.Fatal(err)
	}
	first, err := ComputePolicyDigest(&policy)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ComputePolicyDigest(policy.DeepCopy())
	if err != nil || repeated != first {
		t.Fatal("same supplied definition changed digest")
	}
	altered := policy.DeepCopy()
	ignore := admissionregistrationv1.Ignore
	altered.Spec.FailurePolicy = &ignore
	changed, err := ComputePolicyDigest(altered)
	if err != nil || changed == first {
		t.Fatal("failure policy was omitted from definition digest")
	}
	altered = policy.DeepCopy()
	altered.UID = "different-declared-uid"
	changed, err = ComputePolicyDigest(altered)
	if err != nil || changed == first {
		t.Fatal("policy identity was omitted")
	}
	if _, err := ComputePolicyDigest(nil); err == nil {
		t.Fatal("missing policy acquired a digest")
	}
}
