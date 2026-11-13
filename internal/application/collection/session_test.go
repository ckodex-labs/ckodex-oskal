package collection_test

import (
	"errors"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestSafeHoldIsGenerationFencedAndPreservesFirstReason(t *testing.T) {
	archive, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "session-transition-test"}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "source", Producer: producer, Signer: signer}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	old, err := candidates.BeginSession("source")
	if err != nil {
		t.Fatal(err)
	}
	current, err := candidates.BeginSession("source")
	if err != nil {
		t.Fatal(err)
	}
	if err := old.SafeHold("superseded"); !errors.Is(err, collection.ErrSessionClosed) {
		t.Fatalf("stale generation quarantined current source: %v", err)
	}
	if err := current.SafeHold("actual bounded source failure"); err != nil {
		t.Fatal(err)
	}
	before := candidates.Snapshot()[0]
	revision := candidates.Revision()
	if err := current.End("source shutdown"); err != nil {
		t.Fatal(err)
	}
	if err := current.SafeHold("replacement reason"); err != nil {
		t.Fatal(err)
	}
	after := candidates.Snapshot()[0]
	if after.Lifecycle != collection.SourceSafeHold || after.Reason != before.Reason || after.Eligible != 0 || candidates.Revision() != revision {
		t.Fatalf("hold lineage was rewritten: before=%+v after=%+v", before, after)
	}
}
