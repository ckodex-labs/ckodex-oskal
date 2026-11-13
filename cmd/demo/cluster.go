package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	api "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

func until(ctx context.Context, timeout time.Duration, check func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		ok, err := check(ctx)
		if ok && err == nil {
			return nil
		}
		if err != nil {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("bounded readiness check expired: %v: %w", last, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (d *demo) waitNetwork(ctx context.Context) error {
	return until(ctx, 45*time.Second, func(ctx context.Context) (bool, error) {
		proxy, err := d.kube.AppsV1().DaemonSets("kube-system").Get(ctx, "kube-proxy", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if proxy.Status.DesiredNumberScheduled != 1 || proxy.Status.NumberReady != 1 {
			return false, nil
		}
		pods, err := d.kube.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{LabelSelector: "k8s-app=kube-dns", Limit: 4})
		if err != nil {
			return false, err
		}
		for _, pod := range pods.Items {
			if !podReady(pod) {
				return false, nil
			}
		}
		return len(pods.Items) > 0, nil
	})
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (d *demo) namespacesAndSecrets(ctx context.Context, keys keyMaterial) error {
	for _, name := range []string{systemNamespace, workloadNamespace} {
		if _, err := d.kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{}); err != nil {
			return err
		}
	}
	for name, data := range map[string]map[string][]byte{"tetragon-demo-server": {"tls.crt": keys.serverCert, "tls.key": keys.serverKey, "ca.crt": keys.ca}, "oskal-source-client": {"client.crt": keys.clientCert, "client.key": keys.clientKey, "ca.crt": keys.ca}, "oskal-receipt-signing": {"receipt-signing.key": keys.receiptPrivate, "receipt-signing.pub": keys.receiptPublic}} {
		if _, err := d.kube.CoreV1().Secrets(systemNamespace).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}, Data: data}, metav1.CreateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

func (d *demo) sensor(ctx context.Context, chart string) error {
	if chart == "" {
		if _, err := d.exec(ctx, "fetch-tetragon-chart", time.Minute, "helm", "pull", "tetragon", "--repo", "https://helm.cilium.io", "--version", tetragonVersion, "--destination", d.dir); err != nil {
			return err
		}
		chart = filepath.Join(d.dir, "tetragon-"+tetragonVersion+".tgz")
	}
	chart, err := filepath.Abs(chart)
	if err != nil {
		return err
	}
	raw, err := d.exec(ctx, "tetragon-chart", 15*time.Second, "helm", "show", "chart", chart)
	if err != nil {
		return err
	}
	var metadata struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		AppVersion string `json:"appVersion"`
	}
	if err := yaml.Unmarshal(raw, &metadata); err != nil {
		return err
	}
	if metadata.Name != "tetragon" || metadata.Version != tetragonVersion || metadata.AppVersion != tetragonVersion {
		return fmt.Errorf("only the verified official Tetragon %s chart is supported", tetragonVersion)
	}
	hash, err := fileDigest(chart)
	if err != nil {
		return err
	}
	if err := d.saveJSON("tetragon-chart-identity.json", map[string]string{"path": chart, "sha256": hash, "version": metadata.Version}); err != nil {
		return err
	}
	if _, err := d.exec(ctx, "install-tetragon", 2*time.Minute, "helm", "install", "tetragon", chart, "--kubeconfig", d.kubeconfig, "--namespace", systemNamespace, "--set", "tetragon.grpc.address=0.0.0.0:54321", "--set", "tetragon.grpc.tls.enabled=true", "--set", "tetragon.grpc.tls.requireClientCert=true", "--set", "tetragon.grpc.tls.auto.enabled=false", "--set", "tetragon.grpc.tls.server.existingSecret=tetragon-demo-server", "--wait", "--timeout", "90s"); err != nil {
		return err
	}
	ds, err := d.kube.AppsV1().DaemonSets(systemNamespace).Get(ctx, "tetragon", metav1.GetOptions{})
	if err != nil {
		return err
	}
	if ds.Status.NumberReady != 1 {
		return fmt.Errorf("tetragon daemonset is not actually ready")
	}
	if err := d.saveJSON("sensor-running.json", ds); err != nil {
		return err
	}
	_, err = d.kube.CoreV1().Services(systemNamespace).Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "oskal-tetragon"}, Spec: corev1.ServiceSpec{Selector: ds.Spec.Selector.MatchLabels, Ports: []corev1.ServicePort{{Name: "grpc", Port: 54321, TargetPort: intstr.FromInt32(54321)}}}}, metav1.CreateOptions{})
	return err
}

func (d *demo) objects(ctx context.Context) error {
	no := false
	uid := int64(1000)
	pod, err := d.kube.CoreV1().Pods(workloadNamespace).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: workloadName}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &no, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true), RunAsUser: &uid}, Containers: []corev1.Container{{Name: "workload", Image: "docker.io/library/busybox@sha256:365a051f12e05767b598e643676f14a450fb678a75ccf2beb0052c95d5c73b83", Command: []string{"/bin/sh", "-c", "while true; do /bin/true; sleep 1; done"}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}}}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	d.workloadUID = string(pod.UID)
	policy := &api.AssurancePolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "assurance.ckodex.io/v1alpha1", Kind: "AssurancePolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "current-runtime-observation", Namespace: workloadNamespace},
		Spec: api.AssurancePolicySpec{
			RequiredState: "Assured",
			Evidence:      api.PolicyEvidenceConfig{RequireFresh: true},
			Behavior:      api.PolicyBehaviorConfig{FailOnConfirmedViolation: true, UnknownIsViolation: false},
			Freshness:     api.PolicyFreshnessConfig{MaxEvaluationAge: metav1.Duration{Duration: 15 * time.Second}},
			Enforcement:   api.PolicyEnforcementConfig{Admission: api.AdmissionEnforcementConfig{Enabled: false}},
		},
	}
	contract := &api.EvidenceContract{TypeMeta: metav1.TypeMeta{APIVersion: "assurance.ckodex.io/v1alpha1", Kind: "EvidenceContract"}, ObjectMeta: metav1.ObjectMeta{Name: "observed-effective-uid", Namespace: workloadNamespace}, Spec: api.EvidenceContractSpec{Requirements: []api.ContractRequirement{{ID: "observed-nonroot-euid", Type: "workload.runtime.process.euid.nonroot", Required: true, Freshness: metav1.Duration{Duration: 15 * time.Second}, AcceptedProducers: []string{"local://oskal-controller"}}}, OnMissingRequiredEvidence: api.MissingEvidencePolicy{State: "Unknown"}}}
	bind := &api.ControlBinding{TypeMeta: metav1.TypeMeta{APIVersion: "assurance.ckodex.io/v1alpha1", Kind: "ControlBinding"}, ObjectMeta: metav1.ObjectMeta{Name: bindingName, Namespace: workloadNamespace}, Spec: api.ControlBindingSpec{Controls: []api.ControlBindingItem{{Canonical: api.CanonicalControlRef{Namespace: "ckodex", ID: "runtime.process-uid"}}}, Subjects: api.SubjectSelector{Kinds: []string{"Pod"}}, Requirements: []api.RequirementBinding{{ID: "observed-nonroot-euid", EvidenceContract: contract.Name, Implementations: []api.ImplementationBindingRef{}}}}}
	for _, item := range []struct {
		resource string
		value    any
	}{{"assurancepolicies", policy}, {"evidencecontracts", contract}, {"controlbindings", bind}} {
		raw, err := json.Marshal(item.value)
		if err != nil {
			return err
		}
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		created, err := d.createObject(ctx, item.resource, object)
		if err != nil {
			return err
		}
		if item.resource == "controlbindings" {
			d.bindingUID = string(created.GetUID())
		}
		if err := d.saveJSON(item.resource+".json", created.Object); err != nil {
			return err
		}
	}
	return until(ctx, 45*time.Second, func(ctx context.Context) (bool, error) {
		pod, err := d.kube.CoreV1().Pods(workloadNamespace).Get(ctx, workloadName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return podReady(*pod), nil
	})
}

func boolPtr(value bool) *bool { return &value }

func (d *demo) controller(ctx context.Context) (*corev1.Pod, error) {
	if _, err := d.exec(ctx, "controller-rbac", time.Minute, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=10s", "apply", "-f", filepath.Join(d.source, "config/rbac/role.yaml")); err != nil {
		return nil, err
	}
	if _, err := d.kube.CoreV1().ServiceAccounts(systemNamespace).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "oskal-controller"}}, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	if _, err := d.kube.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "oskal-demo-controller"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "oskal-controller-role"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "oskal-controller", Namespace: systemNamespace}}}, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	sources := map[string]any{"sources": []any{map[string]any{"id": "tetragon-demo", "kind": "tetragon", "namespace": workloadNamespace, "endpoint": "oskal-tetragon." + systemNamespace + ".svc:54321", "tls": map[string]string{"ca_file": "/source-tls/ca.crt", "cert_file": "/source-tls/client.crt", "key_file": "/source-tls/client.key", "server_name": "oskal-tetragon." + systemNamespace + ".svc"}}}}
	raw, err := json.Marshal(sources)
	if err != nil {
		return nil, err
	}
	if err := d.saveJSON("sources.json", sources); err != nil {
		return nil, err
	}
	if _, err := d.kube.CoreV1().ConfigMaps(systemNamespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "oskal-sources"}, Data: map[string]string{"sources.json": string(raw)}}, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	user := int64(65532)
	mode := int32(0440)
	replicas := int32(1)
	container := corev1.Container{
		Name: "controller", Image: d.image, ImagePullPolicy: corev1.PullNever,
		Args: []string{"--enable-webhook=false", "--namespace=" + workloadNamespace, "--sources=/config/sources.json", "--evaluation-interval=2s", "--source-session-window=1m", "--source-clock-ahead=1s", "--evidence-dir=" + evidenceDir},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "evidence", MountPath: evidenceDir},
			{Name: "signing", MountPath: evidenceDir + "/receipt-signing.key", SubPath: "receipt-signing.key", ReadOnly: true},
			{Name: "signing", MountPath: evidenceDir + "/receipt-signing.pub", SubPath: "receipt-signing.pub", ReadOnly: true},
			{Name: "source-tls", MountPath: "/source-tls", ReadOnly: true},
			{Name: "config", MountPath: "/config", ReadOnly: true},
		},
		ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(8081)}}},
		SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(false), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
	}
	volumes := []corev1.Volume{
		{Name: "evidence", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "signing", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "oskal-receipt-signing", DefaultMode: &mode}}},
		{Name: "source-tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "oskal-source-client", DefaultMode: &mode}}},
		{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "oskal-sources"}}}},
	}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "oskal-controller"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "oskal-demo-controller"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "oskal-demo-controller"}},
				Spec: corev1.PodSpec{
					ServiceAccountName: "oskal-controller",
					SecurityContext:    &corev1.PodSecurityContext{RunAsUser: &user, RunAsGroup: &user, RunAsNonRoot: boolPtr(true), FSGroup: &user},
					Containers:         []corev1.Container{container}, Volumes: volumes,
				},
			},
		},
	}
	if err := d.saveJSON("controller-deployment.json", deployment); err != nil {
		return nil, err
	}
	if _, err := d.kube.AppsV1().Deployments(systemNamespace).Create(ctx, deployment, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	var ready *corev1.Pod
	err = until(ctx, 60*time.Second, func(ctx context.Context) (bool, error) {
		pods, err := d.kube.CoreV1().Pods(systemNamespace).List(ctx, metav1.ListOptions{LabelSelector: "app=oskal-demo-controller", Limit: 2})
		if err != nil {
			return false, err
		}
		if len(pods.Items) != 1 || !podReady(pods.Items[0]) {
			return false, nil
		}
		ready = &pods.Items[0]
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if len(ready.Status.ContainerStatuses) != 1 || !strings.Contains(ready.Status.ContainerStatuses[0].ImageID, "sha256:") {
		return nil, fmt.Errorf("controller did not publish an actual image identity")
	}
	_, manifest, _ := strings.Cut(d.image, "@")
	actual := regexpDigest.FindString(ready.Status.ContainerStatuses[0].ImageID)
	if actual != manifest && actual != d.imageConfig && actual != d.imageIndex {
		return nil, fmt.Errorf("deployed controller image differs from the verified Kind-loaded OCI index/manifest/configuration")
	}
	if err := d.saveJSON("controller-running.json", ready); err != nil {
		return nil, err
	}
	return ready, nil
}

func (d *demo) stopSensor(ctx context.Context) (time.Time, error) {
	if _, err := d.exec(ctx, "sensor-before-stop", 10*time.Second, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=5s", "get", "daemonset/tetragon", "-n", systemNamespace, "-o", "json"); err != nil {
		return time.Time{}, err
	}
	if _, err := d.exec(ctx, "sensor-before-stop-logs", 10*time.Second, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=5s", "logs", "-n", systemNamespace, "daemonset/tetragon", "-c", "tetragon", "--tail=100"); err != nil {
		return time.Time{}, err
	}
	ds, err := d.kube.AppsV1().DaemonSets(systemNamespace).Get(ctx, "tetragon", metav1.GetOptions{})
	if err != nil {
		return time.Time{}, err
	}
	nodes, err := d.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "oskal.demo/sensor-paused=" + d.name, Limit: 1})
	if err != nil {
		return time.Time{}, err
	}
	if len(nodes.Items) != 0 {
		return time.Time{}, fmt.Errorf("source stop selector unexpectedly matches a node")
	}
	if ds.Spec.Template.Spec.NodeSelector == nil {
		ds.Spec.Template.Spec.NodeSelector = map[string]string{}
	}
	ds.Spec.Template.Spec.NodeSelector["oskal.demo/sensor-paused"] = d.name
	stopped := time.Now()
	if _, err := d.kube.AppsV1().DaemonSets(systemNamespace).Update(ctx, ds, metav1.UpdateOptions{}); err != nil {
		return time.Time{}, err
	}
	selector := metav1.FormatLabelSelector(ds.Spec.Selector)
	err = until(ctx, 20*time.Second, func(ctx context.Context) (bool, error) {
		pods, err := d.kube.CoreV1().Pods(systemNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 4})
		if err != nil {
			return false, err
		}
		return len(pods.Items) == 0, nil
	})
	return stopped, err
}

func (d *demo) diagnostics() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if d.kubeconfig == "" {
		return
	}
	_, _ = d.exec(ctx, "diagnostic-pods", 5*time.Second, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=3s", "get", "pods", "-A", "-o", "wide")
	_, _ = d.exec(ctx, "diagnostic-events", 5*time.Second, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=3s", "get", "events", "-A", "-o", "json")
	_, _ = d.exec(ctx, "diagnostic-controller", 5*time.Second, "kubectl", "--kubeconfig", d.kubeconfig, "--request-timeout=3s", "logs", "-n", systemNamespace, "deployment/oskal-controller", "--tail=100")
}

var assuranceGVR = schema.GroupVersionResource{Group: "assurance.ckodex.io", Version: "v1alpha1", Resource: "assurancestates"}
