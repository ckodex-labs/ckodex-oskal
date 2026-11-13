package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/opa"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/collection"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/ingestion"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/policycollection"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

type reportSourceSpec struct {
	Group          string `json:"group"`
	Version        string `json:"version"`
	Resource       string `json:"resource"`
	Kind           string `json:"kind"`
	PollInterval   string `json:"poll_interval"`
	RequestTimeout string `json:"request_timeout"`
	MaxObjects     int    `json:"max_objects"`
	MaxBatchBytes  int    `json:"max_batch_bytes"`
}

func (r reportSourceSpec) gvr() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Resource}
}

type opaSourceSpec struct {
	Listen            string          `json:"listen"`
	TLSMode           string          `json:"tls_mode"`
	ExpectedPublisher string          `json:"expected_publisher"`
	DecisionPath      string          `json:"decision_path"`
	BundleName        string          `json:"bundle_name"`
	AllowResult       json.RawMessage `json:"allow_result"`
	DenyResult        json.RawMessage `json:"deny_result"`
	RequestTimeout    string          `json:"request_timeout"`
	ServerCertFile    string          `json:"server_cert_file,omitempty"`
	ServerKeyFile     string          `json:"server_key_file,omitempty"`
	ClientCAFile      string          `json:"client_ca_file,omitempty"`
}

func durationBound(raw string, min, max time.Duration) (time.Duration, error) {
	d, e := time.ParseDuration(raw)
	if e != nil || d < min || d > max {
		return 0, fmt.Errorf("explicit duration must be in %s..%s", min, max)
	}
	return d, nil
}
func validateSourceSpec(s sourceSpec) error {
	if s.Kind == "tetragon" || s.Kind == "hubble" {
		if s.PolicyMode != "" || s.Report != nil || s.OPA != nil {
			return fmt.Errorf("runtime source cannot declare policy settings")
		}
		if len(validation.IsDNS1123Label(s.Namespace)) != 0 {
			return fmt.Errorf("runtime namespace must be explicit")
		}
		if host, _, err := net.SplitHostPort(s.Endpoint); len(s.Endpoint) > 512 || err != nil || host == "" || strings.ContainsAny(s.Endpoint, " /@\r\n") {
			return fmt.Errorf("runtime source requires explicit host:port")
		}
		_, _, _, err := sourceTransport(s.TLS)
		return err
	}
	if s.PolicyMode != "CAPTURE" {
		return fmt.Errorf("policy sources require policy_mode CAPTURE; control standing is UNKNOWN")
	}
	if s.Endpoint != "" || s.TLS != (sourceTLS{}) {
		return fmt.Errorf("policy source cannot declare runtime transport settings")
	}
	switch s.Kind {
	case "policy-report", "gatekeeper":
		if s.Report == nil || s.OPA != nil {
			return fmt.Errorf("report source requires only report configuration")
		}
		r := s.Report
		cluster := false
		switch r.Group + "/" + r.Version + "/" + r.Resource {
		case "wgpolicyk8s.io/v1alpha2/policyreports":
			if r.Kind != "PolicyReport" {
				return fmt.Errorf("configured report kind differs from served schema")
			}
		case "wgpolicyk8s.io/v1alpha2/clusterpolicyreports":
			cluster = true
			if r.Kind != "ClusterPolicyReport" {
				return fmt.Errorf("configured report kind differs from served schema")
			}
		case "openreports.io/v1alpha1/reports":
			if r.Kind != "Report" {
				return fmt.Errorf("configured report kind differs from served schema")
			}
		case "openreports.io/v1alpha1/clusterreports":
			cluster = true
			if r.Kind != "ClusterReport" {
				return fmt.Errorf("configured report kind differs from served schema")
			}
		default:
			if s.Kind != "gatekeeper" || r.Group != "constraints.gatekeeper.sh" || r.Version != "v1beta1" || len(validation.IsDNS1035Label(r.Resource)) != 0 || r.Kind == "" || len(r.Kind) > 128 || strings.ContainsAny(r.Kind, " /@\r\n") {
				return fmt.Errorf("unsupported explicit policy resource GVR/kind")
			}
			cluster = true
		}
		if s.Kind == "gatekeeper" && r.Group != "constraints.gatekeeper.sh" {
			return fmt.Errorf("gatekeeper source requires constraint API")
		}
		if cluster && s.Namespace != "" || !cluster && len(validation.IsDNS1123Label(s.Namespace)) != 0 {
			return fmt.Errorf("namespace differs from explicit resource scope")
		}
		if _, err := durationBound(r.PollInterval, time.Second, time.Hour); err != nil {
			return err
		}
		if _, err := durationBound(r.RequestTimeout, time.Millisecond, time.Minute); err != nil {
			return err
		}
		if r.MaxObjects < 1 || r.MaxObjects > 256 || r.MaxBatchBytes < 1 || r.MaxBatchBytes > 16<<20 {
			return fmt.Errorf("report object or byte bounds invalid")
		}
		return nil
	case "opa":
		if s.OPA == nil || s.Report != nil || s.Namespace != "" {
			return fmt.Errorf("OPA requires only opa settings; namespace is supplied by each verified subject")
		}
		o := s.OPA
		if err := validatePolicyListen(o.Listen); err != nil {
			return err
		}
		if _, err := durationBound(o.RequestTimeout, time.Millisecond, time.Minute); err != nil {
			return err
		}
		if len(o.ExpectedPublisher) > 2048 || len(o.DecisionPath) > 256 || len(o.BundleName) > 256 {
			return fmt.Errorf("OPA publisher or decision settings exceed bounds")
		}
		uri, err := url.Parse(o.ExpectedPublisher)
		if err != nil || uri.Scheme == "" || uri.Host == "" || uri.Path == "" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || strings.ContainsAny(o.ExpectedPublisher, "*|\r\n") {
			return fmt.Errorf("OPA publisher requires exact absolute identity URI")
		}
		if _, err := opa.NewDecoder(opa.Config{DecisionPath: o.DecisionPath, BundleName: o.BundleName, AllowResult: o.AllowResult, DenyResult: o.DenyResult, Producer: assurance.AuthorityRef{Scheme: "local", Subject: "configuration-validation"}}); err != nil {
			return err
		}
		switch o.TLSMode {
		case "pki":
			_, _, _, err := policyServerTLS(*o)
			return err
		case "spiffe":
			id, err := spiffeid.FromString(o.ExpectedPublisher)
			if err != nil || id.Path() == "" || id.String() != o.ExpectedPublisher {
				return fmt.Errorf("OPA publisher requires canonical exact SPIFFE ID")
			}
			if o.ServerCertFile != "" || o.ServerKeyFile != "" || o.ClientCAFile != "" || uri.Scheme != "spiffe" {
				return fmt.Errorf("SPIFFE mode requires exact SPIFFE publisher and forbids PKI fallback")
			}
			return nil
		default:
			return fmt.Errorf("OPA TLS mode must explicitly be pki or spiffe")
		}
	}
	return fmt.Errorf("unsupported source kind %q", s.Kind)
}

func validatePolicyListen(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return fmt.Errorf("OPA listener requires explicit host:port")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("OPA listener requires concrete numeric port in 1..65535")
	}
	if net.ParseIP(host) == nil && len(validation.IsDNS1123Subdomain(host)) != 0 {
		return fmt.Errorf("OPA listener host must be concrete DNS name or IP")
	}
	return nil
}
func publicCertificateDigest(cert []byte) string {
	if len(cert) == 0 {
		return ""
	}
	return assurance.ComputeDigest(cert)
}

func policyAPIConfig(input *rest.Config) (*rest.Config, []byte, []byte, error) {
	if input == nil {
		return nil, nil, nil, fmt.Errorf("explicit manager Kubernetes configuration required")
	}
	cfg := rest.CopyConfig(input)
	cfg.Timeout = 5 * time.Second
	host, err := url.Parse(cfg.Host)
	if err != nil || host.Scheme != "https" || host.Host == "" || host.User != nil || host.RawQuery != "" || host.Fragment != "" || cfg.Insecure {
		return nil, nil, nil, fmt.Errorf("policy metadata requires authenticated HTTPS Kubernetes API")
	}
	ca := cfg.CAData
	if len(ca) == 0 && cfg.CAFile != "" {
		ca, err = boundedFile(cfg.CAFile, 1<<20)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	roots := x509.NewCertPool()
	if len(ca) > 1<<20 || !roots.AppendCertsFromPEM(ca) {
		return nil, nil, nil, fmt.Errorf("policy API trust requires explicit valid public CA bytes")
	}
	cert := cfg.CertData
	if len(cert) == 0 && cfg.CertFile != "" {
		cert, err = boundedFile(cfg.CertFile, 1<<20)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if len(cert) > 1<<20 {
		return nil, nil, nil, fmt.Errorf("policy API public certificate exceeds bound")
	}

	// Bind transports to exactly the public bytes named in the snapshot. File
	// replacement cannot silently change API trust or the public client identity.
	cfg.CAData = append([]byte(nil), ca...)
	cfg.CAFile = ""
	if len(cert) > 0 {
		cfg.CertData = append([]byte(nil), cert...)
		cfg.CertFile = ""
	}
	// Parse configured TLS credentials before signing keys, storage, or listeners.
	if _, err := rest.HTTPClientFor(cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("policy API credentials: %w", err)
	}
	return cfg, ca, cert, nil
}
func validatePolicyWindow(config sourceConfiguration, window time.Duration) error {
	for _, source := range config.Sources {
		raw := ""
		if source.Report != nil {
			raw = source.Report.RequestTimeout
		}
		if source.OPA != nil {
			raw = source.OPA.RequestTimeout
		}
		if raw != "" {
			timeout, err := time.ParseDuration(raw)
			if err != nil || timeout > window {
				return fmt.Errorf("source %s request timeout must not exceed source-session-window", source.ID)
			}
		}
	}
	return nil
}

func validatePolicyAPIConfiguration(config sourceConfiguration, api *rest.Config) error {
	for _, source := range config.Sources {
		if source.Kind != "tetragon" && source.Kind != "hubble" {
			_, _, _, err := policyAPIConfig(api)
			return err
		}
	}
	return nil
}

type preparedPolicySource struct {
	report     *policycollection.ReportsConfig
	decoder    *opa.Decoder
	principals policycollection.PrincipalResolver
	tls        *tls.Config
	resolver   *policySubjectResolver
}

func preparePolicySource(spec sourceSpec, signer *identitySigner, producer assurance.AuthorityRef, apiConfig *rest.Config) (*preparedPolicySource, any, error) {
	if apiConfig == nil {
		return nil, nil, fmt.Errorf("explicit manager Kubernetes configuration required")
	}
	cfg, ca, cert, err := policyAPIConfig(apiConfig)
	if err != nil {
		return nil, nil, err
	}

	prior := cfg.WrapTransport
	cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		if prior != nil {
			rt = prior(rt)
		}
		return boundedPolicyTransport{rt}
	}
	api, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	objects, err := metadata.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	discover, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}

	prepared := &preparedPolicySource{resolver: &policySubjectResolver{metadata: objects, discovery: discover.RESTClient(), cache: make(map[schema.GroupVersionKind]*meta.RESTMapping)}}
	public := map[string]any{"ID": spec.ID, "Kind": spec.Kind, "Namespace": spec.Namespace, "PolicyMode": spec.PolicyMode, "KubernetesAPI": cfg.Host, "KubernetesServerName": cfg.ServerName, "KubernetesCADigest": assurance.ComputeDigest(ca), "KubernetesClientCertDigest": publicCertificateDigest(cert)}
	if spec.Report != nil {
		r := spec.Report
		poll, _ := time.ParseDuration(r.PollInterval)
		deadline, _ := time.ParseDuration(r.RequestTimeout)
		prepared.report = &policycollection.ReportsConfig{Client: api, GVR: r.gvr(), Kind: r.Kind, Namespace: spec.Namespace, Producer: producer, PollInterval: poll, RequestTimeout: deadline, MaxObjects: r.MaxObjects, MaxBatchBytes: r.MaxBatchBytes}
		public["Report"] = *r
		return prepared, public, nil
	}
	o := spec.OPA
	prepared.decoder, err = opa.NewDecoder(opa.Config{DecisionPath: o.DecisionPath, BundleName: o.BundleName, AllowResult: o.AllowResult, DenyResult: o.DenyResult, Producer: producer})
	if err != nil {
		return nil, nil, err
	}
	public["OPA"] = map[string]any{"Listen": o.Listen, "TLSMode": o.TLSMode, "ExpectedPublisher": o.ExpectedPublisher, "DecisionPath": o.DecisionPath, "BundleName": o.BundleName, "AllowResult": o.AllowResult, "DenyResult": o.DenyResult, "RequestTimeout": o.RequestTimeout}
	if o.TLSMode == "spiffe" {
		if signer.workload == nil {
			return nil, nil, fmt.Errorf("SPIFFE policy listener requires explicit controller Workload API identity")
		}
		prepared.tls, err = signer.workload.TLSServerConfig(context.Background(), []string{o.ExpectedPublisher})
		if err != nil {
			return nil, nil, err
		}
		prepared.principals = policyPinnedPrincipal{workload: signer.workload, publisher: o.ExpectedPublisher, bundleDigest: signer.bundleDigest}
		public["SPIFFEBundleDigest"] = signer.bundleDigest
	} else {
		var roots *x509.CertPool
		var facts map[string]string
		prepared.tls, roots, facts, err = policyServerTLS(*o)
		if err == nil {
			prepared.principals = policyPKIPrincipal{roots: roots, expected: o.ExpectedPublisher}
			public["PublicTLS"] = facts
		}
	}
	if err != nil {
		return nil, nil, err
	}
	return prepared, public, nil
}

type boundedPolicyTransport struct{ http.RoundTripper }

func (t boundedPolicyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.RoundTripper.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	response.Body = http.MaxBytesReader(nil, response.Body, 16<<20)
	return response, nil
}

func policyHTTPLogger() *log.Logger { return log.New(policyLogWriter{}, "", 0) }

type policyLogWriter struct{}

func (policyLogWriter) Write(data []byte) (int, error) {
	setupLog.Info("policy HTTP transport rejected a connection")
	return len(data), nil
}

func policyServerTLS(o opaSourceSpec) (*tls.Config, *x509.CertPool, map[string]string, error) {
	if o.ServerCertFile == "" || o.ServerKeyFile == "" || o.ClientCAFile == "" {
		return nil, nil, nil, fmt.Errorf("PKI OPA requires server cert/key and explicit client CA")
	}
	cert, err := boundedFile(o.ServerCertFile, 1<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := boundedFile(o.ServerKeyFile, 1<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	ca, err := boundedFile(o.ClientCAFile, 1<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, nil, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, nil, fmt.Errorf("OPA client CA has no certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, roots, map[string]string{"ServerCertificateDigest": assurance.ComputeDigest(cert), "ClientCADigest": assurance.ComputeDigest(ca)}, nil
}

type policyPinnedPrincipal struct {
	workload     *spire.WorkloadClient
	publisher    string
	bundleDigest string
}

func (p policyPinnedPrincipal) AuthenticatedPrincipal(ctx context.Context) (string, error) {
	state, ok := policycollection.PeerTLSState(ctx)
	if !ok {
		return "", fmt.Errorf("authenticated policy TLS state missing")
	}
	principal, digest, err := p.workload.AuthenticatedPeerWithTrustBundleDigest(ctx, state, []string{p.publisher})
	if err != nil {
		return "", err
	}
	if p.bundleDigest == "" || digest != p.bundleDigest {
		return "", fmt.Errorf("peer trust bundle differs from authority snapshot; operator review and restart required")
	}
	return principal, nil
}

type policyPKIPrincipal struct {
	roots    *x509.CertPool
	expected string
}

func (p policyPKIPrincipal) AuthenticatedPrincipal(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	state, ok := policycollection.PeerTLSState(ctx)
	if !ok || state.Version != tls.VersionTLS13 || !state.HandshakeComplete || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return "", fmt.Errorf("verified TLS1.3 publisher missing")
	}
	if err := policyTLSExporter(state); err != nil {
		return "", err
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	leaf := state.PeerCertificates[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p.roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", err
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != p.expected {
		return "", fmt.Errorf("publisher differs from exact URI")
	}
	return p.expected, ctx.Err()
}

func policyTLSExporter(state tls.ConnectionState) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("publisher TLS state lacks connection exporter")
		}
	}()
	_, err = state.ExportKeyingMaterial("EXPORTER-OSKAL-Policy-Publisher", nil, 32)
	return err
}

// Subject capture reads only API metadata. It never fetches resource data/spec,
// derives a policy revision, or supplies a runtime binding/control epoch.
type policySubjectResolver struct {
	metadata  metadata.Interface
	discovery rest.Interface
	mu        sync.Mutex
	cache     map[schema.GroupVersionKind]*meta.RESTMapping
}

func allowedPolicySubject(gvk schema.GroupVersionKind) bool {
	switch gvk.Group + "/" + gvk.Kind {
	case "/Pod", "/Namespace", "/ServiceAccount", "/ConfigMap", "apps/Deployment", "apps/DaemonSet", "apps/StatefulSet", "apps/ReplicaSet", "batch/Job", "batch/CronJob", "wgpolicyk8s.io/PolicyReport", "wgpolicyk8s.io/ClusterPolicyReport", "openreports.io/Report", "openreports.io/ClusterReport":
		return true
	}
	return gvk.Group == "constraints.gatekeeper.sh" && gvk.Version == "v1beta1" && gvk.Kind != ""
}
func (r *policySubjectResolver) mapping(ctx context.Context, gvk schema.GroupVersionKind) (*meta.RESTMapping, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if item := r.cache[gvk]; item != nil {
		return item, nil
	}
	if len(r.cache) >= 32 {
		return nil, fmt.Errorf("policy subject mapping capacity exceeded")
	}
	path := "/apis/" + gvk.Group + "/" + gvk.Version
	if gvk.Group == "" {
		path = "/api/" + gvk.Version
	}
	var list metav1.APIResourceList
	if err := r.discovery.Get().AbsPath(path).Do(ctx).Into(&list); err != nil {
		return nil, err
	}
	if len(list.APIResources) > 4096 {
		return nil, fmt.Errorf("served resource discovery exceeds bound")
	}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{gvk.GroupVersion()})
	for _, resource := range list.APIResources {
		if resource.Kind != gvk.Kind || strings.Contains(resource.Name, "/") {
			continue
		}
		scope := meta.RESTScopeRoot
		if resource.Namespaced {
			scope = meta.RESTScopeNamespace
		}
		mapper.AddSpecific(gvk, gvk.GroupVersion().WithResource(resource.Name), gvk.GroupVersion().WithResource(resource.SingularName), scope)
	}
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, err
	}
	r.cache[gvk] = mapping
	return mapping, nil
}
func (r *policySubjectResolver) ResolveCapture(ctx context.Context, event ports.CapturedEvent) (assurance.SubjectRef, assurance.AssuranceEpoch, error) {
	ref := event.Subject.Attributes
	gv, err := schema.ParseGroupVersion(ref["apiVersion"])
	if err != nil {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
	}
	gvk := gv.WithKind(ref["kind"])
	if !allowedPolicySubject(gvk) || ref["uid"] == "" || ref["name"] == "" {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("policy capture requires allowed public metadata GVK and concrete UID")
	}
	mapping, err := r.mapping(ctx, gvk)
	if err != nil {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
	}
	if (mapping.Scope.Name() == meta.RESTScopeNameNamespace) != (ref["namespace"] != "") {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("policy subject namespace differs from served scope")
	}
	object, err := r.metadata.Resource(mapping.Resource).Namespace(ref["namespace"]).Get(ctx, ref["name"], metav1.GetOptions{})
	if err != nil {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
	}
	if ref["uid"] != string(object.UID) || object.CreationTimestamp.IsZero() || event.CapturedAt.Before(object.CreationTimestamp.Time) {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("policy subject UID or capture time differs from current object")
	}
	expectedID := ref["kind"] + "/" + ref["name"]
	if ref["namespace"] != "" {
		expectedID = ref["namespace"] + "/" + expectedID
	}
	if event.Subject.Scheme != "k8s" || event.Subject.ID != expectedID {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, fmt.Errorf("policy subject URI differs from concrete object reference")
	}
	raw, err := json.Marshal(struct {
		APIVersion, Kind, Namespace, Name, UID string
		Generation                             int64
		CreatedAt                              metav1.Time
	}{gv.String(), gvk.Kind, object.Namespace, object.Name, string(object.UID), object.Generation, object.CreationTimestamp})
	if err != nil {
		return assurance.SubjectRef{}, assurance.AssuranceEpoch{}, err
	}
	return event.Subject, assurance.AssuranceEpoch{SubjectDigest: assurance.ComputeDigest(raw)}, nil
}

type policyCaptureWriter struct{ writer ports.CapturedEventWriter }

func (w policyCaptureWriter) WriteCapturedEvent(ctx context.Context, event ports.CapturedEvent) error {
	event.ControlRefs = nil
	return w.writer.WriteCapturedEvent(ctx, event)
}

type policyBatches struct {
	group   *sourceGroup
	source  preparedSource
	mu      sync.Mutex
	session *collection.Session
	expires time.Time
}

func (b *policyBatches) begin(ctx context.Context) (ports.CapturedEventWriter, func(error), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, status := range b.group.captureCandidates.Snapshot() {
		if status.ID == b.source.spec.ID && status.Lifecycle == collection.SourceSafeHold {
			return nil, nil, fmt.Errorf("%w: %s", policycollection.ErrSafeHold, status.Reason)
		}
	}

	session, err := b.group.captureCandidates.BeginSession(b.source.spec.ID)
	if err != nil {
		return nil, nil, err
	}
	b.session = session
	b.expires = time.Now().Add(b.group.window)
	writer := &ingestion.Writer{Repository: session.Repository(), Resolver: b.source.policy.resolver, MaxClockAhead: b.group.clockAhead}
	return policyCaptureWriter{writer}, func(err error) {
		if err != nil {
			reason := "policy batch failed; signed history retained but eligibility invalidated"
			if errors.Is(err, collection.ErrSaturated) || errors.Is(err, policycollection.ErrSafeHold) || errors.Is(err, ports.ErrEvidenceCapacity) {
				b.mu.Lock()
				_ = session.SafeHold("policy source bound exceeded; operator review and restart required")
				b.mu.Unlock()
				return
			}
			_ = session.End(reason)
		}
	}, nil
}
func (b *policyBatches) end(reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session != nil {
		_ = b.session.End(reason)
	}
}
func (b *policyBatches) expire() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session != nil && time.Now().After(b.expires) {
		_ = b.session.End("policy capture session expired; awaiting a fresh complete batch")
		b.session = nil
	}
}

func (g *sourceGroup) followPolicy(ctx context.Context, source preparedSource) {
	batches := &policyBatches{group: g, source: source}
	defer batches.end("policy source stopped; no archived fallback")
	for failures := 0; failures < 3 && ctx.Err() == nil; failures++ {
		err := g.runPolicy(ctx, source, batches)
		batches.end("policy source stopped or failed; eligible candidates invalidated")
		if ctx.Err() != nil {
			return
		}
		setupLog.Error(err, "policy source unavailable; no control standing was inferred", "source", source.spec.ID, "failedRuns", failures+1)
		if errors.Is(err, collection.ErrSaturated) || errors.Is(err, policycollection.ErrSafeHold) || errors.Is(err, ports.ErrEvidenceCapacity) {
			return
		}
		if failures == 2 {
			return
		}
		timer := time.NewTimer(time.Duration(failures+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (g *sourceGroup) runPolicy(ctx context.Context, source preparedSource, batches *policyBatches) error {
	g.setCaptureTransport(source.spec.ID, "UNAVAILABLE")
	defer g.setCaptureTransport(source.spec.ID, "UNAVAILABLE")
	if source.policy.report != nil {
		config := *source.policy.report
		config.BeginBatch = batches.begin
		config.PollCompleted = func(err error) {
			state := "POLLING"
			if err != nil {
				state = "UNAVAILABLE"
			}
			g.setCaptureTransport(source.spec.ID, state)
		}
		runner, err := policycollection.NewReportsRunner(config)
		if err != nil {
			return err
		}
		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- runner.Run(runCtx) }()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case err := <-done:
				return err
			case <-ticker.C:
				batches.expire()
			case <-ctx.Done():
				cancel()
				return <-done
			}
		}
	}
	o := source.spec.OPA
	timeout, _ := time.ParseDuration(o.RequestTimeout)
	receiver, err := policycollection.NewOPAReceiver(policycollection.OPAConfig{Decoder: source.policy.decoder, Principals: source.policy.principals, ExpectedPrincipal: o.ExpectedPublisher, BeginBatch: batches.begin, RequestTimeout: timeout})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return fmt.Errorf("policy listener startup: %w", err)
	}
	limited := newPolicyListener(listener, 16)
	defer func() { _ = limited.Close() }()
	server := &http.Server{Handler: receiver, TLSConfig: source.policy.tls, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: timeout, WriteTimeout: timeout + time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: policyHTTPLogger()}
	done := make(chan error, 1)
	serving := &servingPolicyListener{Listener: limited, ready: func() { g.setCaptureTransport(source.spec.ID, "LISTENING") }}
	go func() { done <- server.ServeTLS(serving, "", "") }()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			batches.expire()
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := server.Shutdown(shutdown)
			cancel()
			if err != nil {
				_ = server.Close()
			}
			return errors.Join(ctx.Err(), err)
		}
	}
}

// Cap pre-handshake connections so stalled clients cannot fan out Workload API
// verification or consume unbounded TLS goroutines.
type policyListener struct {
	net.Listener
	tokens chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newPolicyListener(l net.Listener, limit int) *policyListener {
	return &policyListener{Listener: l, tokens: make(chan struct{}, limit), closed: make(chan struct{})}
}
func (l *policyListener) Accept() (net.Conn, error) {
	select {
	case l.tokens <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	c, e := l.Listener.Accept()
	if e != nil {
		<-l.tokens
		return nil, e
	}
	return &policyConnection{Conn: c, release: func() { <-l.tokens }}, nil
}
func (l *policyListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type policyConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *policyConnection) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

func validateAdmissionSources(configuration sourceConfiguration, enabled bool) error {
	if !enabled {
		return nil
	}
	for _, source := range configuration.Sources {
		if source.Kind == "tetragon" || source.Kind == "hubble" {
			return nil
		}
	}
	return fmt.Errorf("admission requires a bound runtime source; capture-only/read-only mode requires explicit --enable-webhook=false")
}
