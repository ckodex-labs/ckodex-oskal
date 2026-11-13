package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestChartMountsSourcesAndExplicitlyDisablesAdmission(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm binary required for actual chart rendering")
	}
	base := []string{"template", "capture", "../../deploy/helm/ckodex-oskal", "--namespace", "capture"}
	command := exec.CommandContext(t.Context(), helm, base...)
	if output, err := command.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("enforcing admission requires sources.configMapName")) {
		t.Fatalf("unconfigured enforcing chart did not fail before install: %v %s", err, output)
	}
	args := append(slices.Clone(base), "--set", "webhook.enabled=false", "--set", "reconcileNamespace=capture", "--set", "sources.configMapName=capture-sources", "--set", "sources.tlsSecrets[0]=opa-ingress", "--set", "sources.publicCAConfigMaps[0]=opa-roots", "--set", "policyCapture.opaListeners[0].name=opa", "--set", "policyCapture.opaListeners[0].port=9444")
	command = exec.CommandContext(t.Context(), helm, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("capture chart render failed: %v %s", err, output)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	var deployment appsv1.Deployment
	var service corev1.Service
	for {
		// Each document is decoded independently so validation examines the
		// actual Kubernetes wire manifests, including volume and port mapping.
		var raw map[string]any
		if err := decoder.Decode(&raw); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		switch raw["kind"] {
		case "Deployment":
			if err := json.Unmarshal(data, &deployment); err != nil {
				t.Fatal(err)
			}
		case "Service":
			var candidate corev1.Service
			if err := json.Unmarshal(data, &candidate); err != nil {
				t.Fatal(err)
			}
			if candidate.Name == "capture-ckodex-oskal-policy" {
				service = candidate
			}
		case "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration":
			t.Fatal("capture-only chart installed admission authority")
		}
	}
	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		t.Fatal("missing controller deployment")
	}
	container := deployment.Spec.Template.Spec.Containers[0]
	if !slices.Contains(container.Args, "--enable-webhook=false") || !slices.Contains(container.Args, "--sources=/etc/oskal/sources/sources.json") || !slices.Contains(container.Args, "--namespace=capture") {
		t.Fatalf("source/admission CLI contract missing: %v", container.Args)
	}
	volumes := deployment.Spec.Template.Spec.Volumes
	foundConfig, foundSecret, foundCA := false, false, false
	for _, volume := range volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == "capture-sources" {
			foundConfig = len(volume.ConfigMap.Items) == 1 && volume.ConfigMap.Items[0].Key == "sources.json" && volume.ConfigMap.Items[0].Path == "sources.json"
		}
		if volume.Secret != nil && volume.Secret.SecretName == "opa-ingress" {
			foundSecret = volume.Secret.DefaultMode != nil && *volume.Secret.DefaultMode == 0440
		}
		if volume.ConfigMap != nil && volume.ConfigMap.Name == "opa-roots" {
			foundCA = true
		}
	}
	if !foundConfig || !foundSecret || !foundCA || deployment.Spec.Template.Spec.SecurityContext.FSGroup == nil {
		t.Fatal("source configuration or readable restricted credential mounts missing")
	}
	for _, mount := range container.VolumeMounts {
		if (mount.Name == "sources" || mount.Name == "source-tls-0" || mount.Name == "source-ca-0") && !mount.ReadOnly {
			t.Fatal("source inputs must be read-only")
		}
	}
	if len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 9444 || service.Spec.Ports[0].TargetPort.StrVal != "opa" {
		t.Fatalf("OPA service does not route selected listener: %+v", service.Spec.Ports)
	}
	for _, extra := range [][]string{
		{"--set", "policyCapture.opaListeners[0].port=8081"},
		{"--set", "policyCapture.opaListeners[0].name=probes"},
		{"--set", "sources.configMapKey=../sources"},
		{"--set", "sources.tlsSecrets[0]=../secret"},
		{"--set", "sources.configMapName=bad..name"},
		{"--set", "sources.tlsSecrets[0]=bad..name"},
		{"--set", "sources.publicCAConfigMaps[0]=ca..roots"},
		{"--set", "sources.configMapKey=..data"},
		{"--set", "sources.configMapKey=.."},
		{"--set", "sources.configMapKey=."},
		{"--set", "policyCapture.opaListeners[1].name=opa", "--set", "policyCapture.opaListeners[1].port=9445"},
	} {
		command = exec.CommandContext(t.Context(), helm, append(slices.Clone(args), extra...)...)
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("invalid chart input admitted: %v %s", extra, output)
		}
	}
}
