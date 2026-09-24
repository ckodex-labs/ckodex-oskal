package assurance

import (
	"testing"
)

func TestAssuranceEpochMatchesAndComposite(t *testing.T) {
	epochA := AssuranceEpoch{
		SubjectDigest:        "sha256:1111",
		ImplementationDigest: "sha256:2222",
		PolicyDigest:         "sha256:3333",
		AuthorityDigest:      "sha256:4444",
		EnvironmentDigest:    "sha256:5555",
	}

	epochB := AssuranceEpoch{
		SubjectDigest:        "sha256:1111",
		ImplementationDigest: "sha256:2222",
		PolicyDigest:         "sha256:3333",
		AuthorityDigest:      "sha256:4444",
		EnvironmentDigest:    "sha256:5555",
	}

	if !epochA.Matches(epochB) {
		t.Fatalf("expected epochA to match epochB")
	}

	if epochA.CompositeDigest() != epochB.CompositeDigest() {
		t.Fatalf("expected composite digests to match: %s vs %s", epochA.CompositeDigest(), epochB.CompositeDigest())
	}

	// Change one dimension
	epochC := epochB
	epochC.PolicyDigest = "sha256:9999"

	if epochA.Matches(epochC) {
		t.Fatalf("expected epochA not to match epochC")
	}

	diffs := epochA.Diff(epochC)
	if len(diffs) != 1 || diffs[0] != DriftPolicy {
		t.Fatalf("expected DriftPolicy, got %v", diffs)
	}

	if epochA.CompositeDigest() == epochC.CompositeDigest() {
		t.Fatalf("expected different composite digest after policy change")
	}
}

func TestCanonicalDigestListDeterminism(t *testing.T) {
	listA := []string{"sha256:bbb", "sha256:aaa", "sha256:ccc"}
	listB := []string{"sha256:ccc", "sha256:aaa", "sha256:bbb"}

	rootA := CanonicalDigestList(listA)
	rootB := CanonicalDigestList(listB)

	if rootA != rootB {
		t.Fatalf("expected CanonicalDigestList to be deterministic regardless of slice order: %s vs %s", rootA, rootB)
	}
}

func TestComputeMapDigestDeterminism(t *testing.T) {
	mapA := map[string]string{"foo": "1", "bar": "2", "baz": "3"}
	mapB := map[string]string{"baz": "3", "foo": "1", "bar": "2"}

	digestA := ComputeMapDigest(mapA)
	digestB := ComputeMapDigest(mapB)

	if digestA != digestB {
		t.Fatalf("expected ComputeMapDigest to be order-independent: %s vs %s", digestA, digestB)
	}
}
