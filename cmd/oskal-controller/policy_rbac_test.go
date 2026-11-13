package main

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestPolicyRBACRendersOnlyExplicitResourceGrants(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm binary required for actual chart rendering")
	}
	render := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(t.Context(), helm, append([]string{"template", "policy-check", "../../deploy/helm/ckodex-oskal", "--namespace", "controller", "--set", "webhook.enabled=false"}, args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("actual helm rendering: %v %s", err, output)
		}
		return output
	}
	defaults := render()
	if bytes.Contains(defaults, []byte("gatekeeper-capture")) || bytes.Contains(defaults, []byte("policy-report-")) || bytes.Contains(defaults, []byte("configmap-metadata-")) {
		t.Fatal("default chart added unselected policy read authority")
	}
	selected := render("--set", "policyCapture.reportSources[0].group=openreports.io", "--set", "policyCapture.reportSources[0].resource=reports", "--set", "policyCapture.reportSources[0].namespace=observed", "--set", "policyCapture.gatekeeperResources[0]=oskalrequiredlabels", "--set", "policyCapture.configMapMetadataNamespaces[0]=metadata-only")
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(selected), 4096)
	seen := map[string]bool{}
	for {
		var object struct {
			Kind     string              `json:"kind"`
			Metadata metav1.ObjectMeta   `json:"metadata"`
			Rules    []rbacv1.PolicyRule `json:"rules"`
		}
		if err := decoder.Decode(&object); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if len(object.Rules) == 0 {
			continue
		}
		name := object.Metadata.Name
		switch {
		case strings.Contains(name, "policy-report-"):
			if object.Kind != "Role" || object.Metadata.Namespace != "observed" {
				t.Fatal("namespaced report grant escaped selected namespace")
			}
			seen["report"] = true
		case strings.Contains(name, "gatekeeper-capture"):
			if object.Kind != "ClusterRole" {
				t.Fatal("constraint grant scope incorrect")
			}
			seen["gatekeeper"] = true
		case strings.Contains(name, "configmap-metadata-"):
			if object.Kind != "Role" || object.Metadata.Namespace != "metadata-only" {
				t.Fatal("ConfigMap capability escaped selected namespace")
			}
			seen["configmap"] = true
		default:
			continue
		}
		for _, rule := range object.Rules {
			for _, resource := range rule.Resources {
				if resource == "*" || resource == "secrets" || strings.Contains(resource, "/") {
					t.Fatal("policy chart broadened resource authority")
				}
			}
			for _, verb := range rule.Verbs {
				if verb != "get" && verb != "list" {
					t.Fatal("capture grant permits mutation")
				}
			}
		}
	}
	if len(seen) != 3 {
		t.Fatalf("selected policy resources did not render all three grants: %+v", seen)
	}
	rejected := exec.CommandContext(t.Context(), helm, "template", "policy-check", "../../deploy/helm/ckodex-oskal", "--set", "webhook.enabled=false", "--set", "policyCapture.gatekeeperResources[0]=*")
	if output, err := rejected.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("Gatekeeper resources must be exact")) {
		t.Fatalf("wildcard resource did not fail: %v %s", err, output)
	}
}
