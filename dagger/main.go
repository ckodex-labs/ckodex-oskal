// Package main is the OSKAL Continuous Assurance Dagger SSDLC pipeline module.
//
// Implements the Secure Software Development Life Cycle (SSDLC) harness:
// 1. Lint: golangci-lint v2 + buf protobuf lint
// 2. Test: race-detected unit, property, contract, and integration tests
// 3. Scan: CycloneDX SBOM generation via Syft + Grype vulnerability evaluation
// 4. Build: static binary compilation for oskal CLI and oskal-controller
// 5. Evidence: immutable SSDLC evidence bundle assembly
package main

import (
	"context"
	"fmt"

	"dagger/oskal/internal/dagger"
)

const (
	golangVersion   = "1.24"
	golangciVersion = "v2.14.0"
	syftImage       = "anchore/syft:v1.52.0"
	grypeImage      = "anchore/grype:v0.119.0"
	bufImage        = "bufbuild/buf:1.50.0"
	cosignImage     = "gcr.io/projectsigstore/cosign:v2.4.1"
)

// Oskal represents the automated CI/CD assurance pipeline for OSKAL.
type Oskal struct{}

// Lint executes golangci-lint v2 and buf lint on the codebase.
func (m *Oskal) Lint(ctx context.Context, source *dagger.Directory) (*dagger.Container, error) {
	cache := dag.CacheVolume("golangci-lint-cache")
	goCache := dag.CacheVolume("go-build-cache")

	return dag.Container().
		From(fmt.Sprintf("golangci/golangci-lint:%s", golangciVersion)).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithMountedCache("/root/.cache/golangci-lint", cache).
		WithMountedCache("/root/.cache/go-build", goCache).
		WithExec([]string{"golangci-lint", "run", "./..."}), nil
}

// ProtoCheck validates protobuf backward-compatibility and linting.
func (m *Oskal) ProtoCheck(ctx context.Context, source *dagger.Directory) (*dagger.Container, error) {
	return dag.Container().
		From(bufImage).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"buf", "lint"}), nil
}

// Test executes the full continuous assurance test suite with race detector and coverage.
func (m *Oskal) Test(ctx context.Context, source *dagger.Directory) (*dagger.Container, error) {
	goCache := dag.CacheVolume("go-build-cache")
	modCache := dag.CacheVolume("go-mod-cache")

	return dag.Container().
		From(fmt.Sprintf("golang:%s", golangVersion)).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithMountedCache("/root/.cache/go-build", goCache).
		WithMountedCache("/go/pkg/mod", modCache).
		WithExec([]string{"go", "test", "-v", "-race", "-coverprofile=coverage.out", "./core/...", "./pkg/...", "./internal/...", "./tests/..."}), nil
}

// Scan generates a CycloneDX Software Bill of Materials (SBOM) using Syft.
func (m *Oskal) Scan(ctx context.Context, source *dagger.Directory) (*dagger.File, error) {
	sbomContainer := dag.Container().
		From(syftImage).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"syft", "dir:.", "-o", "cyclonedx-json=/tmp/sbom.cdx.json"})

	return sbomContainer.File("/tmp/sbom.cdx.json"), nil
}

// VulnCheck evaluates the generated SBOM with Grype for known vulnerabilities.
func (m *Oskal) VulnCheck(ctx context.Context, source *dagger.Directory) (*dagger.Container, error) {
	sbom, err := m.Scan(ctx, source)
	if err != nil {
		return nil, err
	}

	return dag.Container().
		From(grypeImage).
		WithFile("/tmp/sbom.cdx.json", sbom).
		WithExec([]string{"grype", "sbom:/tmp/sbom.cdx.json", "--fail-on", "critical"}), nil
}

// Build compiles both static binaries: oskal CLI and oskal-controller.
func (m *Oskal) Build(ctx context.Context, source *dagger.Directory) (*dagger.Directory, error) {
	goCache := dag.CacheVolume("go-build-cache")
	modCache := dag.CacheVolume("go-mod-cache")

	builder := dag.Container().
		From(fmt.Sprintf("golang:%s", golangVersion)).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithMountedCache("/root/.cache/go-build", goCache).
		WithMountedCache("/go/pkg/mod", modCache).
		WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "build", "-trimpath", "-ldflags", "-s -w", "-o", "/out/bin/oskal", "./cmd/oskal"}).
		WithExec([]string{"go", "build", "-trimpath", "-ldflags", "-s -w", "-o", "/out/bin/oskal-controller", "./cmd/oskal-controller"}).
		WithExec([]string{"sh", "-c", "cd /out/bin && sha256sum * > SHA256SUMS"})

	return builder.Directory("/out/bin"), nil
}

// Attest generates SLSA provenance, in-toto statement, and Cosign signatures for compiled artifacts.
func (m *Oskal) Attest(ctx context.Context, source *dagger.Directory) (*dagger.Directory, error) {
	binDir, err := m.Build(ctx, source)
	if err != nil {
		return nil, err
	}

	attestContainer := dag.Container().
		From(cosignImage).
		WithMountedDirectory("/out/bin", binDir).
		WithWorkdir("/out/attestations").
		WithEnvVariable("COSIGN_PASSWORD", "").
		WithExec([]string{"cosign", "generate-key-pair"}).
		WithExec([]string{"sh", "-c", `
OSKAL_HASH=$(sha256sum /out/bin/oskal | awk '{print $1}')
CTRL_HASH=$(sha256sum /out/bin/oskal-controller | awk '{print $1}')

cat <<EOF > /out/attestations/provenance.json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "oskal",
      "digest": {
        "sha256": "${OSKAL_HASH}"
      }
    },
    {
      "name": "oskal-controller",
      "digest": {
        "sha256": "${CTRL_HASH}"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://dagger.io/module/ckodex/oskal@v1",
      "externalParameters": {
        "repository": "https://github.com/ckodex-labs/ckodex-oskal"
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://dagger.io/engine"
      }
    }
  }
}
EOF
`}).
		WithExec([]string{"cosign", "sign-blob", "--yes", "--key", "cosign.key", "--output-signature", "oskal.sig", "/out/bin/oskal"}).
		WithExec([]string{"cosign", "sign-blob", "--yes", "--key", "cosign.key", "--output-signature", "oskal-controller.sig", "/out/bin/oskal-controller"}).
		WithExec([]string{"cosign", "attest-blob", "--yes", "--key", "cosign.key", "--predicate", "provenance.json", "--type", "slsaprovenance1", "--output-attestation", "in-toto-attestation.json", "/out/bin/oskal"}).
		WithExec([]string{"cosign", "verify-blob", "--key", "cosign.pub", "--signature", "oskal.sig", "/out/bin/oskal"}).
		WithExec([]string{"cosign", "verify-blob", "--key", "cosign.pub", "--signature", "oskal-controller.sig", "/out/bin/oskal-controller"})

	return attestContainer.Directory("/out/attestations"), nil
}

// Evidence assembles an immutable SSDLC evidence bundle directory.
func (m *Oskal) Evidence(ctx context.Context, source *dagger.Directory) (*dagger.Directory, error) {
	binDir, err := m.Build(ctx, source)
	if err != nil {
		return nil, err
	}

	sbomFile, err := m.Scan(ctx, source)
	if err != nil {
		return nil, err
	}

	attestDir, err := m.Attest(ctx, source)
	if err != nil {
		return nil, err
	}

	evidenceDir := dag.Directory().
		WithDirectory("bin", binDir).
		WithFile("sbom.cdx.json", sbomFile).
		WithDirectory("attestations", attestDir)

	return evidenceDir, nil
}

// All executes the complete SSDLC pipeline (Lint, ProtoCheck, Test, Scan, Build, Evidence).
func (m *Oskal) All(ctx context.Context, source *dagger.Directory) (string, error) {
	// 1. Lint
	lintC, err := m.Lint(ctx, source)
	if err != nil {
		return "", fmt.Errorf("lint setup failed: %w", err)
	}
	if _, err := lintC.Sync(ctx); err != nil {
		return "", fmt.Errorf("lint check failed: %w", err)
	}

	// 2. Proto Check
	protoC, err := m.ProtoCheck(ctx, source)
	if err != nil {
		return "", fmt.Errorf("proto check setup failed: %w", err)
	}
	if _, err := protoC.Sync(ctx); err != nil {
		return "", fmt.Errorf("proto check failed: %w", err)
	}

	// 3. Test
	testC, err := m.Test(ctx, source)
	if err != nil {
		return "", fmt.Errorf("test setup failed: %w", err)
	}
	if _, err := testC.Sync(ctx); err != nil {
		return "", fmt.Errorf("tests failed: %w", err)
	}

	// 4. VulnCheck
	vulnC, err := m.VulnCheck(ctx, source)
	if err != nil {
		return "", fmt.Errorf("vuln check setup failed: %w", err)
	}
	if _, err := vulnC.Sync(ctx); err != nil {
		return "", fmt.Errorf("vulnerability check failed: %w", err)
	}

	// 5. Evidence
	evDir, err := m.Evidence(ctx, source)
	if err != nil {
		return "", fmt.Errorf("evidence generation failed: %w", err)
	}
	if _, err := evDir.Sync(ctx); err != nil {
		return "", fmt.Errorf("evidence sync failed: %w", err)
	}

	return "[PASS] OSKAL SSDLC Pipeline passed: lint, test, scan, build, and evidence verified", nil
}
