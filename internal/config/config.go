package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

// Config represents persistent OSKAL CLI and runtime configuration.
type Config struct {
	Server      string `json:"server,omitempty" yaml:"server,omitempty"`
	EvidenceDir string `json:"evidence_dir,omitempty" yaml:"evidence_dir,omitempty"`
	Namespace   string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Output      string `json:"output,omitempty" yaml:"output,omitempty"`
	Profile     string `json:"profile,omitempty" yaml:"profile,omitempty"`
}

// DefaultConfig returns baseline configuration with smart defaults.
func DefaultConfig() Config {
	evDir := ""
	if _, err := os.Stat("evidence"); err == nil {
		evDir = "evidence"
	}

	return Config{
		Server:      "",
		EvidenceDir: evDir,
		Namespace:   "default",
		Output:      "table",
		Profile:     "nist-sp-800-53",
	}
}

// FindConfigFile searches for .oskal.yaml or config.yaml in standard locations.
func FindConfigFile() string {
	// 1. Current directory: .oskal.yaml or .oskal.json
	for _, name := range []string{".oskal.yaml", ".oskal.yml", ".oskal.json"} {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}

	// 2. User home directory: ~/.oskal/config.yaml
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".oskal", "config.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// LoadConfig loads configuration with precedence:
// Environment variables > Config file > Smart defaults.
func LoadConfig(explicitFilePath string) (Config, string, error) {
	cfg := DefaultConfig()
	configFile := explicitFilePath
	if configFile == "" {
		configFile = FindConfigFile()
	}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return cfg, configFile, fmt.Errorf("failed to read config file %s: %w", configFile, err)
		}
		if strings.HasSuffix(configFile, ".json") {
			if err := json.Unmarshal(data, &cfg); err != nil {
				return cfg, configFile, fmt.Errorf("failed to parse JSON config: %w", err)
			}
		} else {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return cfg, configFile, fmt.Errorf("failed to parse YAML config: %w", err)
			}
		}
	}

	// Environment variable overrides (OSKAL_*)
	if envServer := os.Getenv("OSKAL_SERVER"); envServer != "" {
		cfg.Server = envServer
	}
	if envEvDir := os.Getenv("OSKAL_EVIDENCE_DIR"); envEvDir != "" {
		cfg.EvidenceDir = envEvDir
	}
	if envNs := os.Getenv("OSKAL_NAMESPACE"); envNs != "" {
		cfg.Namespace = envNs
	}
	if envOut := os.Getenv("OSKAL_OUTPUT"); envOut != "" {
		cfg.Output = envOut
	}
	if envProf := os.Getenv("OSKAL_PROFILE"); envProf != "" {
		cfg.Profile = envProf
	}

	return cfg, configFile, nil
}

// SaveConfig writes the configuration to the specified file path as YAML.
func SaveConfig(cfg Config, path string) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory %s: %w", dir, err)
		}
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	header := "# OSKAL Configuration File (CKODEX Continuous Kubernetes Assurance)\n"
	return os.WriteFile(path, append([]byte(header), data...), 0644)
}
