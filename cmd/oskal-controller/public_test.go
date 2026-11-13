package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

func TestPublicFactRetainsHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority-snapshot.json")
	for _, data := range []string{`{"authority":"first"}`, `{"authority":"second"}`, `{"authority":"first"}`} {
		if err := writePublicFact(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		latest, err := os.ReadFile(path)
		if err != nil || string(latest) != data {
			t.Fatalf("latest=%q err=%v", latest, err)
		}
	}
	for _, data := range []string{`{"authority":"first"}`, `{"authority":"second"}`} {
		snapshot, err := os.ReadFile(filepath.Join(path+".d", fmt.Sprintf("%x.json", sha256.Sum256([]byte(data)))))
		if err != nil || string(snapshot) != data {
			t.Fatalf("history=%q err=%v", snapshot, err)
		}
	}
}

func TestReadinessReflectsConfiguredSource(t *testing.T) {
	archive, err := storage.NewFilesystemEvidenceRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "readiness"}
	signer, err := receipts.NewReceiptManager(producer)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := collection.NewCandidates(archive, []collection.SourceConfig{{ID: "source", Producer: producer, Signer: signer}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	group := &sourceGroup{candidates: candidates}
	if err := group.Ready(nil); err == nil {
		t.Fatal("unavailable source reported ready")
	}
	session, err := candidates.BeginSession("source")
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Ready(nil); err == nil {
		t.Fatal("starting source reported ready")
	}
	if err := session.End("source unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := group.Ready(nil); err == nil {
		t.Fatal("ended source reported ready")
	}
}
