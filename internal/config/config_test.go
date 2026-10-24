package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	cfg, _, err := LoadConfig("")
	if err != nil {
		t.Fatalf("unexpected error loading default config: %v", err)
	}
	if cfg.Namespace != "default" {
		t.Fatalf("expected namespace 'default', got %s", cfg.Namespace)
	}
	if cfg.Profile != "nist-sp-800-53" {
		t.Fatalf("expected profile 'nist-sp-800-53', got %s", cfg.Profile)
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	_ = os.Setenv("OSKAL_SERVER", "grpc.internal:9090")
	_ = os.Setenv("OSKAL_EVIDENCE_DIR", "/var/evidence")
	_ = os.Setenv("OSKAL_NAMESPACE", "production")
	defer func() {
		_ = os.Unsetenv("OSKAL_SERVER")
		_ = os.Unsetenv("OSKAL_EVIDENCE_DIR")
		_ = os.Unsetenv("OSKAL_NAMESPACE")
	}()

	cfg, _, err := LoadConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server != "grpc.internal:9090" {
		t.Fatalf("expected server 'grpc.internal:9090', got %s", cfg.Server)
	}
	if cfg.EvidenceDir != "/var/evidence" {
		t.Fatalf("expected evidenceDir '/var/evidence', got %s", cfg.EvidenceDir)
	}
	if cfg.Namespace != "production" {
		t.Fatalf("expected namespace 'production', got %s", cfg.Namespace)
	}
}

func TestSaveAndLoadConfigYAML(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "oskal-cfg-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cfgPath := filepath.Join(tmpDir, ".oskal.yaml")
	sampleCfg := Config{
		Server:      "cluster.local:9090",
		EvidenceDir: "/tmp/evidence",
		Namespace:   "finance",
		Output:      "json",
		Profile:     "pci-dss",
	}

	if err := SaveConfig(sampleCfg, cfgPath); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, path, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if path != cfgPath {
		t.Fatalf("expected path %s, got %s", cfgPath, path)
	}
	if loaded.Server != sampleCfg.Server || loaded.Profile != sampleCfg.Profile {
		t.Fatalf("loaded config does not match saved config: %+v", loaded)
	}
}
