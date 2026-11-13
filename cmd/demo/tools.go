package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func prepare(source, artifacts string) (*demo, error) {
	for _, tool := range []string{"go", "git", "docker", "kind", "kubectl", "helm"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("required tool %s: %w", tool, err)
		}
	}
	root, err := filepath.Abs(source)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(root, "cmd/oskal-controller/main.go")); err != nil {
		return nil, fmt.Errorf("source must be the OSKAL checkout root: %w", err)
	}
	dir := ""
	if artifacts == "" {
		dir, err = os.MkdirTemp("", "oskal-deployed-demo-")
	} else {
		dir, err = filepath.Abs(artifacts)
		if err == nil {
			rel, relErr := filepath.Rel(root, dir)
			if relErr != nil || rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("artifacts containing private test keys must be outside the source checkout")
			}
			err = os.Mkdir(dir, 0700)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("choose a new artifact directory: %w", err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("artifact directory must resolve outside the source checkout before creating private keys")
	}
	name := fmt.Sprintf("oskal-deployed-%d", time.Now().UnixNano())
	return &demo{source: root, dir: dir, name: name, kubeconfig: filepath.Join(dir, "kubeconfig")}, nil
}

func (d *demo) exec(parent context.Context, label string, timeout time.Duration, args ...string) ([]byte, error) {
	return d.execEnv(parent, label, timeout, nil, args...)
}

type boundedOutput struct {
	mutex     sync.Mutex
	raw       []byte
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	remaining := (8 << 20) - len(b.raw)
	if len(p) > remaining {
		b.raw = append(b.raw, p[:remaining]...)
		b.truncated = true
	} else {
		b.raw = append(b.raw, p...)
	}
	return len(p), nil
}

func (d *demo) execEnv(parent context.Context, label string, timeout time.Duration, extra []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Dir = d.source
	command.Env = append(os.Environ(), "KUBECONFIG="+d.kubeconfig, "HELM_REPOSITORY_CONFIG="+filepath.Join(d.dir, "helm-repositories.yaml"), "HELM_REPOSITORY_CACHE="+filepath.Join(d.dir, "helm-cache"))
	command.Env = append(command.Env, extra...)
	command.WaitDelay = 2 * time.Second
	output := &boundedOutput{}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	raw := output.raw
	if writeErr := os.WriteFile(filepath.Join(d.dir, label+".log"), raw, 0600); writeErr != nil {
		return nil, writeErr
	}
	if err != nil {
		return raw, fmt.Errorf("%s failed (see %s): %w", label, filepath.Join(d.dir, label+".log"), err)
	}
	if output.truncated {
		return nil, fmt.Errorf("%s exceeded the 8 MiB output bound; inspect retained log", label)
	}
	return raw, nil
}

func (d *demo) saveJSON(name string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.dir, name), append(raw, '\n'), 0600)
}

func (d *demo) provenance(ctx context.Context) error {
	sha, err := d.exec(ctx, "source-commit", 10*time.Second, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	status, err := d.exec(ctx, "source-status", 10*time.Second, "git", "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return err
	}
	diffCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(diffCtx, "git", "diff", "--binary", "--no-ext-diff", "HEAD")
	command.Dir = d.source
	hash := sha256.New()
	command.Stdout = hash
	if err := command.Run(); err != nil {
		return fmt.Errorf("hash source diff: %w", err)
	}
	return d.saveJSON("source.json", map[string]any{"checkout": d.source, "commit": strings.TrimSpace(string(sha)), "dirty": len(status) != 0, "trackedDiffSHA256": hex.EncodeToString(hash.Sum(nil)), "statusFile": "source-status.log"})
}

func (d *demo) build(ctx context.Context) error {
	buildDir := filepath.Join(d.dir, "image-context")
	if err := os.Mkdir(buildDir, 0700); err != nil {
		return err
	}
	for _, binary := range []string{"oskal", "oskal-controller"} {
		if _, err := d.execEnv(ctx, "build-linux-"+binary, 3*time.Minute, []string{"GOOS=linux", "GOARCH=" + d.architecture, "CGO_ENABLED=0", "GOMAXPROCS=2"}, "go", "build", "-p=2", "-trimpath", "-buildvcs=false", "-o", filepath.Join(buildDir, binary), "./cmd/"+binary); err != nil {
			return fmt.Errorf("cross-build actual %s: %w", binary, err)
		}
	}
	d.hostCLI = filepath.Join(d.dir, "oskal-verify")
	if _, err := d.exec(ctx, "build-host-cli", 2*time.Minute, "go", "build", "-p=2", "-trimpath", "-buildvcs=false", "-o", d.hostCLI, "./cmd/oskal"); err != nil {
		return err
	}
	platform := "linux/" + d.architecture
	const base = "gcr.io/distroless/static:nonroot"
	if _, err := d.exec(ctx, "pull-runtime-base", 2*time.Minute, "docker", "pull", "--platform", platform, base); err != nil {
		return err
	}
	raw, err := d.exec(ctx, "runtime-base-digest", 15*time.Second, "docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", base)
	if err != nil {
		return err
	}
	digest := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(digest, "gcr.io/distroless/static@sha256:") {
		return fmt.Errorf("runtime registry did not return the expected immutable distroless digest")
	}
	dockerfile := "FROM " + digest + "\nCOPY oskal /oskal\nCOPY oskal-controller /oskal-controller\nUSER 65532:65532\nENTRYPOINT [\"/oskal-controller\"]\n"
	if err := os.WriteFile(filepath.Join(buildDir, "Dockerfile"), []byte(dockerfile), 0600); err != nil {
		return err
	}
	tag := "oskal-deployed-demo:" + d.name
	if _, err := d.exec(ctx, "build-image", time.Minute, "docker", "build", "--platform", platform, "--tag", tag, buildDir); err != nil {
		return err
	}
	builtRaw, err := d.exec(ctx, "image-inspect", 15*time.Second, "docker", "image", "inspect", tag)
	if err != nil {
		return err
	}
	var built []struct {
		ID           string `json:"Id"`
		Architecture string `json:"Architecture"`
		OS           string `json:"Os"`
	}
	if err := json.Unmarshal(builtRaw, &built); err != nil {
		return err
	}
	if len(built) != 1 || built[0].Architecture != d.architecture || built[0].OS != "linux" || !digestReference.MatchString(built[0].ID) {
		return fmt.Errorf("built image does not match the observed Linux node architecture and identity")
	}
	help, err := d.exec(ctx, "controller-flags", 20*time.Second, "docker", "run", "--rm", "--entrypoint", "/oskal-controller", tag, "--help")
	if err != nil {
		return err
	}
	for _, name := range []string{"-sources ", "-namespace ", "-evaluation-interval ", "-source-session-window ", "-source-clock-ahead "} {
		if !strings.Contains(string(help), name) {
			return fmt.Errorf("actual controller lacks required flag %s; build a checkout containing the completed source pipeline", name)
		}
	}
	archive := filepath.Join(d.dir, "controller-image.tar")
	if _, err := d.exec(ctx, "export-controller-image", time.Minute, "docker", "image", "save", "--platform", platform, "--output", archive, tag); err != nil {
		return err
	}
	if err := os.Chmod(archive, 0600); err != nil {
		return err
	}
	identity, err := exportedIdentity(ctx, archive, built[0].ID, d.architecture)
	if err != nil {
		return fmt.Errorf("verify actual exported controller image: %w", err)
	}
	if _, err := d.exec(ctx, "kind-load-controller", time.Minute, "kind", "load", "image-archive", archive, "--name", d.name); err != nil {
		return err
	}
	// CRI may report a synthetic import repository name that is not a usable
	// kubelet lookup. Register our own fully qualified immutable reference.
	d.image = "docker.io/library/oskal-deployed-demo@" + identity.Manifest
	if _, err := d.exec(ctx, "kind-pin-controller", 15*time.Second, "docker", "exec", d.node, "ctr", "--namespace", "k8s.io", "images", "tag", "docker.io/library/"+tag, d.image); err != nil {
		return err
	}
	loaded, err := d.exec(ctx, "loaded-controller-image", 15*time.Second, "docker", "exec", d.node, "crictl", "inspecti", d.image)
	if err != nil {
		return err
	}
	var info struct {
		Status struct {
			ID          string   `json:"id"`
			RepoDigests []string `json:"repoDigests"`
		} `json:"status"`
	}
	if err := json.Unmarshal(loaded, &info); err != nil {
		return err
	}
	if info.Status.ID != identity.Config {
		return fmt.Errorf("kind imported a different image configuration than the actual built artifact")
	}
	found := false
	for _, reference := range info.Status.RepoDigests {
		found = found || reference == d.image
	}
	if !found {
		return fmt.Errorf("kind runtime did not resolve the explicit immutable image alias; inspect loaded-controller-image.log")
	}
	d.imageConfig = info.Status.ID
	d.imageIndex = identity.Index
	_, manifest, ok := strings.Cut(d.image, "@")
	if !ok || !digestReference.MatchString(manifest) || !digestReference.MatchString(d.imageConfig) {
		return fmt.Errorf("loaded image identity is missing canonical manifest/config digests")
	}
	if manifest != identity.Index && manifest != identity.Manifest {
		return fmt.Errorf("kind's immutable image reference is absent from the verified exported OCI graph")
	}
	archiveHash, err := fileDigest(archive)
	if err != nil {
		return err
	}
	binaries := map[string]any{"base": digest, "image": d.image, "imageConfig": d.imageConfig, "dockerImageID": built[0].ID, "exportSHA256": archiveHash, "exportedOCI": identity}
	for _, name := range []string{"oskal", "oskal-controller"} {
		hash, err := fileDigest(filepath.Join(buildDir, name))
		if err != nil {
			return err
		}
		binaries[name+"SHA256"] = hash
	}
	if err := d.saveJSON("built-image-identity.json", binaries); err != nil {
		return err
	}
	return nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
