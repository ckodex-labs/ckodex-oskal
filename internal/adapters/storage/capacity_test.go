package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
)

func capacityEnvelope(id string, payload []byte) assurance.EvidenceEnvelope {
	digest := assurance.ComputeDigest(payload)
	return assurance.EvidenceEnvelope{Schema: "assurance.ckodex.io/evidence/v1alpha1", ID: id, Subject: assurance.SubjectRef{Scheme: "file", ID: "quota-fixture", Attributes: map[string]string{"source": "actual-file-test"}}, ObservationType: "file.read", CapturedAt: time.Now().UTC(), Artifact: assurance.EvidenceRef{URI: "cas://sha256/" + strings.TrimPrefix(digest, "sha256:"), Digest: digest, MediaType: "text/plain"}, IntegrityDigest: digest}
}
func requireCapacity(t *testing.T, err error) {
	t.Helper()
	var capacity *CapacityError
	if !errors.Is(err, ports.ErrEvidenceCapacity) || !errors.As(err, &capacity) {
		t.Fatalf("expected typed capacity refusal, got %v", err)
	}
	t.Logf("bounded refusal: %s", capacity)
}
func readArchiveBytes(t *testing.T, repo *ContentAddressedEvidenceRepository, ref assurance.EvidenceRef) []byte {
	t.Helper()
	reader, err := repo.Get(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return data
}
func managedFiles(t *testing.T, path string) (int, int64) {
	t.Helper()
	count := 0
	var size int64
	err := filepath.WalkDir(path, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		count++
		size += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return count, size
}

func TestArchiveExactByteQuotaDeduplicatesAndReopens(t *testing.T) {
	payload := []byte("actual persisted quota-bound payload")
	envelope := capacityEnvelope("first", payload)
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	limit := ArchiveLimits{MaxBytes: int64(len(encoded) + len(payload)), MaxEntries: 8}
	directory := t.TempDir()
	repo, err := NewFilesystemEvidenceRepositoryWithLimits(directory, limit)
	if err != nil {
		t.Fatal(err)
	}
	first, err := repo.Put(t.Context(), envelope, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	before := repo.Usage()
	again, err := repo.Put(t.Context(), envelope, bytes.NewReader(payload))
	if err != nil || again != first {
		t.Fatalf("full archive rejected duplicate: %v", err)
	}
	if repo.Usage() != before {
		t.Fatal("duplicate consumed additional quota")
	}
	rejected := capacityEnvelope("second", []byte("different bytes"))
	_, err = repo.Put(t.Context(), rejected, bytes.NewReader([]byte("different bytes")))
	requireCapacity(t, err)
	if repo.Usage() != before {
		t.Fatal("refused admission changed reservations")
	}
	if count, size := managedFiles(t, directory); count != 2 || size != limit.MaxBytes {
		t.Fatalf("quota refusal wrote files: %d %d", count, size)
	}
	if !bytes.Equal(readArchiveBytes(t, repo, envelope.Artifact), payload) {
		t.Fatal("prior payload changed")
	}
	if !bytes.Equal(readArchiveBytes(t, repo, first), encoded) {
		t.Fatal("prior envelope changed")
	}
	if _, err := OpenFilesystemEvidenceRepositoryWithLimits(directory, ArchiveLimits{MaxBytes: limit.MaxBytes - 1, MaxEntries: 2}); err == nil {
		t.Fatal("restore accepted insufficient byte budget")
	} else {
		requireCapacity(t, err)
	}
	reopened, err := OpenFilesystemEvidenceRepositoryWithLimits(directory, limit)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readArchiveBytes(t, reopened, envelope.Artifact), payload) {
		t.Fatal("reopened history differs")
	}
	reviewed, err := OpenFilesystemEvidenceRepositoryWithLimits(directory, ArchiveLimits{MaxBytes: 1 << 20, MaxEntries: 8})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reviewed.Put(t.Context(), rejected, bytes.NewReader([]byte("different bytes"))); err != nil {
		t.Fatal(err)
	}
	t.Logf("exact quota %d bytes, 2 retained files; prior bytes verified after refusal and reopen", limit.MaxBytes)
}

func TestArchiveReceiptQuotaAndConcurrentAdmission(t *testing.T) {
	directory := t.TempDir()
	limits := ArchiveLimits{MaxBytes: 1 << 20, MaxEntries: 5}
	repo, err := NewFilesystemEvidenceRepositoryWithLimits(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, receipt := receiptFixture(t)
	first, err := repo.PutReceipt(t.Context(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	before := repo.Usage()
	if _, err := repo.PutReceipt(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	if repo.Usage() != before {
		t.Fatal("duplicate receipt consumed quota")
	}
	changed := receipt
	changed.EvidenceRoot = assurance.ComputeStringDigest("another receipt root")
	changed = signStoredTestReceipt(t, changed)
	if _, err := repo.PutReceipt(t.Context(), changed); err == nil {
		t.Fatal("receipt exceeded file count")
	} else {
		requireCapacity(t, err)
	}
	restored, err := OpenFilesystemEvidenceRepositoryWithLimits(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restored.GetReceipt(t.Context(), first); err != nil || got.Signature != receipt.Signature {
		t.Fatalf("prior immutable receipt lost: %v", err)
	}
	directory = t.TempDir()
	limits.MaxEntries = 7
	shared, err := NewFilesystemEvidenceRepositoryWithLimits(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	failures := make(chan error, 32)
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			payload := []byte(fmt.Sprintf("payload-%d", i))
			envelope := capacityEnvelope(fmt.Sprintf("event-%d", i), payload)
			_, err := shared.Put(t.Context(), envelope, bytes.NewReader(payload))
			if err != nil && !errors.Is(err, ports.ErrEvidenceCapacity) {
				failures <- err
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, err := shared.PutReceipt(t.Context(), receipt)
		if err != nil && !errors.Is(err, ports.ErrEvidenceCapacity) {
			failures <- err
		}
	}()
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	usage := shared.Usage()
	count, size := managedFiles(t, directory)
	if count > limits.MaxEntries || size > limits.MaxBytes || usage.DiskEntries > limits.MaxEntries || usage.ResidentEntries > limits.MaxEntries {
		t.Fatalf("concurrent writers crossed quota: %+v files=%d bytes=%d", usage, count, size)
	}
	if _, err := OpenFilesystemEvidenceRepositoryWithLimits(directory, limits); err != nil {
		t.Fatal(err)
	}
	t.Logf("concurrent envelope/receipt admission remained within %d files; reopen passed", limits.MaxEntries)
}

func TestArchiveRestoreAndMetadataAllocationBounds(t *testing.T) {
	t.Run("legacy-array", func(t *testing.T) {
		directory := t.TempDir()
		if _, err := NewFilesystemEvidenceRepository(directory); err != nil {
			t.Fatal(err)
		}
		var entries []assurance.EvidenceEnvelope
		for i := 0; i < 9; i++ {
			entries = append(entries, capacityEnvelope(fmt.Sprint(i), nil))
		}
		data, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "legacy.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = OpenFilesystemEvidenceRepositoryWithLimits(directory, ArchiveLimits{MaxBytes: 1 << 20, MaxEntries: 8})
		requireCapacity(t, err)
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(data, got) {
			t.Fatal("restore failure changed legacy history")
		}
	})
	t.Run("large-file-before-decode", func(t *testing.T) {
		directory := t.TempDir()
		if _, err := NewFilesystemEvidenceRepository(directory); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "blobs", "sha256", strings.Repeat("a", 64)+".json")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(MaxMetadataBytes + 1); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = OpenFilesystemEvidenceRepository(directory)
		requireCapacity(t, err)
		if info, err := os.Stat(path); err != nil || info.Size() != MaxMetadataBytes+1 {
			t.Fatal("restore changed oversized object")
		}
	})
	t.Run("directory-enumeration", func(t *testing.T) {
		directory := t.TempDir()
		if _, err := NewFilesystemEvidenceRepository(directory); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("unrelated-%d.txt", i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := OpenFilesystemEvidenceRepositoryWithLimits(directory, ArchiveLimits{MaxBytes: 1 << 20, MaxEntries: 1})
		requireCapacity(t, err)
	})
	t.Run("metadata-and-copy-ownership", func(t *testing.T) {
		directory := t.TempDir()
		repo, err := NewFilesystemEvidenceRepository(directory)
		if err != nil {
			t.Fatal(err)
		}
		bad := capacityEnvelope("oversized", nil)
		bad.Subject.Attributes = map[string]string{"oversized": strings.Repeat("x", MaxMetadataBytes+1)}
		_, err = repo.Put(t.Context(), bad, nil)
		requireCapacity(t, err)
		if count, _ := managedFiles(t, directory); count != 0 {
			t.Fatal("oversized metadata wrote bytes")
		}
		envelope := capacityEnvelope("owned", nil)
		if _, err := repo.Put(t.Context(), envelope, nil); err != nil {
			t.Fatal(err)
		}
		envelope.Subject.Attributes["source"] = "caller mutation"
		got, err := repo.ListAll(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Subject.Attributes["source"] != "actual-file-test" {
			t.Fatal("input map mutated index after admission")
		}
		got[0].Subject.Attributes["source"] = "reader mutation"
		again, err := repo.ListAll(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if again[0].Subject.Attributes["source"] != "actual-file-test" {
			t.Fatal("returned map aliases resident index")
		}
	})
}

func TestArchiveImmutableWritesPreserveCorruptHistory(t *testing.T) {
	directory := t.TempDir()
	repo, err := NewFilesystemEvidenceRepository(directory)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("original bytes")
	envelope := capacityEnvelope("immutable", payload)
	if _, err := repo.Put(context.Background(), envelope, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "blobs", "sha256", strings.TrimPrefix(envelope.Artifact.Digest, "sha256:")+".bin")
	corrupt := []byte("retained corrupt fixture")
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Put(t.Context(), envelope, bytes.NewReader(payload)); err == nil {
		t.Fatal("corrupt immutable blob silently replaced")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, corrupt) {
		t.Fatal("retry destroyed forensic bytes")
	}
}
