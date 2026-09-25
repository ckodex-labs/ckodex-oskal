package assurance

import (
	"testing"
)

func TestAssuranceEpochMatchesAndComposite(t *testing.T) {
	epochA := AssuranceEpoch{
		SubjectDigest:        ComputeStringDigest("sub-01"),
		ImplementationDigest: ComputeStringDigest("imp-01"),
		PolicyDigest:         ComputeStringDigest("pol-01"),
		AuthorityDigest:      ComputeStringDigest("auth-01"),
		EnvironmentDigest:    ComputeStringDigest("env-01"),
	}

	epochB := AssuranceEpoch{
		SubjectDigest:        ComputeStringDigest("sub-01"),
		ImplementationDigest: ComputeStringDigest("imp-01"),
		PolicyDigest:         ComputeStringDigest("pol-01"),
		AuthorityDigest:      ComputeStringDigest("auth-01"),
		EnvironmentDigest:    ComputeStringDigest("env-01"),
	}

	if !epochA.Matches(epochB) {
		t.Fatalf("expected epochA to match epochB")
	}

	if epochA.CompositeDigest() != epochB.CompositeDigest() {
		t.Fatalf("expected composite digests to match: %s vs %s", epochA.CompositeDigest(), epochB.CompositeDigest())
	}

	// Change one dimension
	epochC := epochB
	epochC.PolicyDigest = ComputeStringDigest("pol-02")

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
	d1 := ComputeStringDigest("item-1")
	d2 := ComputeStringDigest("item-2")
	d3 := ComputeStringDigest("item-3")
	listA := []string{d2, d1, d3}
	listB := []string{d3, d1, d2}

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
