package main

import "github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"

var archiveMaxBytes = storage.DefaultArchiveBytes
var archiveMaxEntries = storage.DefaultArchiveEntries

func configuredArchiveLimits() storage.ArchiveLimits {
	return storage.ArchiveLimits{MaxBytes: archiveMaxBytes, MaxEntries: archiveMaxEntries}
}
func openCLIArchive(path string) (*storage.ContentAddressedEvidenceRepository, error) {
	return storage.OpenFilesystemEvidenceRepositoryWithLimits(path, configuredArchiveLimits())
}
func newCLIArchive(path string) (*storage.ContentAddressedEvidenceRepository, error) {
	return storage.NewFilesystemEvidenceRepositoryWithLimits(path, configuredArchiveLimits())
}
