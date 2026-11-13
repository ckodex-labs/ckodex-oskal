package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/webhook"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/binding"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/evaluation"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/reconcile"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
)

var (
	version  = "v1.0.0"
	commit   = "dev"
	date     = "unknown"
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(assurancev1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var enableWebhook bool
	var webhookPort int
	var webhookServiceName string
	var webhookNamespace string
	var webhookMode string
	var webhookTLSCertFile string
	var webhookTLSKeyFile string
	var evidenceDir string
	var showVersion bool
	var sourcesPath, workloadAPI, expectedSPIFFEID, managedNamespace string
	var evaluationInterval, sourceWindow, clockAhead time.Duration

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. Enabling this will ensure only one active controller manager.")
	flag.BoolVar(&enableWebhook, "enable-webhook", true, "Enable admission request validation; this does not provide hardware attestation.")
	flag.IntVar(&webhookPort, "webhook-port", 8443, "The port the validating admission webhook listens on.")
	flag.StringVar(&webhookServiceName, "webhook-service-name", "oskal-webhook", "Kubernetes Service name for the admission webhook.")
	flag.StringVar(&webhookNamespace, "webhook-namespace", "ckodex-system", "Kubernetes Namespace for the admission webhook.")
	flag.StringVar(&webhookMode, "webhook-mode", "enforcing", "Webhook mode (enforcing, warn, or audit)")
	flag.StringVar(&webhookTLSCertFile, "webhook-tls-cert-file", "", "Path to TLS certificate file for the admission webhook.")
	flag.StringVar(&webhookTLSKeyFile, "webhook-tls-key-file", "", "Path to TLS private key file for the admission webhook.")
	flag.StringVar(&evidenceDir, "evidence-dir", "/tmp/oskal/evidence", "Path to local directory for content-addressed evidence storage.")
	flag.BoolVar(&showVersion, "version", false, "Print version information and exit.")

	flag.StringVar(&sourcesPath, "sources", "", "Authenticated evidence source JSON configuration")
	flag.StringVar(&managedNamespace, "namespace", "", "Only reconcile OSKAL resources in this namespace (empty means cluster-wide)")
	flag.DurationVar(&evaluationInterval, "evaluation-interval", 2*time.Second, "Control re-evaluation interval (500ms..5m)")
	flag.DurationVar(&sourceWindow, "source-session-window", time.Minute, "Bounded source session lifetime (1s..5m)")
	flag.DurationVar(&clockAhead, "source-clock-ahead", 0, "Explicit source clock-ahead allowance (0..1s), preserving timestamps")
	flag.StringVar(&workloadAPI, "workload-api", "", "Explicit SPIRE Workload API Unix socket URI")
	flag.StringVar(&expectedSPIFFEID, "spiffe-id", "", "Exact own SPIFFE ID required when Workload API is configured")

	opts := zap.Options{
		Development: false,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if showVersion {
		fmt.Printf("oskal-controller %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	ctx := ctrl.SetupSignalHandler()
	if evaluationInterval < 500*time.Millisecond || evaluationInterval > 5*time.Minute {
		setupLog.Error(fmt.Errorf("invalid interval"), "use --evaluation-interval in 500ms..5m")
		os.Exit(1)
	}
	sourceConfig, err := readSourceConfiguration(sourcesPath)
	if err != nil {
		setupLog.Error(err, "correct --sources configuration before starting")
		os.Exit(1)
	}
	if enableWebhook && len(sourceConfig.Sources) == 0 {
		setupLog.Error(fmt.Errorf("no authenticated evidence sources configured"), "provide --sources; explicitly disable webhook for a read-only UNKNOWN controller")
		os.Exit(1)
	}
	for _, source := range sourceConfig.Sources {
		if _, _, _, err := sourceTransport(source.TLS); err != nil {
			setupLog.Error(err, "correct source TLS configuration", "source", source.ID)
			os.Exit(1)
		}
	}
	producer := assurance.AuthorityRef{Scheme: "local", Subject: "oskal-controller"}
	var identity *spire.WorkloadClient
	if workloadAPI != "" || expectedSPIFFEID != "" {
		identity, err = spire.NewWorkloadClient(ctx, workloadAPI, expectedSPIFFEID, 5*time.Second)
		if err != nil {
			setupLog.Error(err, "configure an exact SPIRE identity and reachable Unix Workload API")
			os.Exit(1)
		}
		defer func() { _ = identity.Close() }()
		actual, err := identity.Identity(ctx)
		if err != nil {
			setupLog.Error(err, "SPIRE identity unavailable; refusing local identity fallback")
			os.Exit(1)
		}
		producer = assurance.AuthorityRef{Scheme: "spiffe", Subject: strings.TrimPrefix(actual.SPIFFEID, "spiffe://"), TrustDomain: actual.TrustDomain}
	}

	cacheOptions := cache.Options{}
	if managedNamespace != "" {
		cacheOptions.DefaultNamespaces = map[string]cache.Config{managedNamespace: {}}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Cache:  cacheOptions,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "oskal-controller-leader.assurance.ckodex.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	evidenceRepo, err := openEvidenceRepository(evidenceDir)
	if err != nil {
		setupLog.Error(err, "cannot initialize durable evidence storage; inspect the path and permissions before restarting", "path", evidenceDir)
		os.Exit(1)
	}
	setupLog.Info("Initialized durable content-addressed evidence repository", "path", evidenceDir)

	receiptMgr, err := receipts.LoadOrCreateReceiptManager(producer, evidenceDir)
	if err != nil {
		setupLog.Error(err, "initialize explicit persistent signing identity")
		os.Exit(1)
	}
	signer := &identitySigner{ReceiptManager: receiptMgr, workload: identity}
	sourceGroup, verification, authorityDigest, err := prepareSources(sourceConfig, evidenceRepo, signer, producer, binding.NewResolver(mgr.GetAPIReader()), sourceWindow, clockAhead)
	if err != nil {
		setupLog.Error(err, "initialize bounded authenticated evidence sources")
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Join(evidenceDir, "configuration"), 0755); err != nil {
		setupLog.Error(err, "initialize public configuration directory")
		os.Exit(1)
	}
	if err := writePublicFact(filepath.Join(evidenceDir, "configuration", "authority-snapshot.json"), sourceGroup.authoritySnapshot); err != nil {
		setupLog.Error(err, "persist public authority snapshot")
		os.Exit(1)
	}
	publicKeys, err := json.Marshal(map[string]string{producer.Canonical(): receiptMgr.PublicKey()})
	if err != nil {
		setupLog.Error(err, "encode public producer keys")
		os.Exit(1)
	}
	if err := writePublicFact(filepath.Join(evidenceDir, "configuration", "producer-keys.json"), publicKeys); err != nil {
		setupLog.Error(err, "persist public producer keys")
		os.Exit(1)
	}
	setupLog.Info("Configured producer authority", "producer", producer.Canonical(), "authorityDigest", authorityDigest, "sourceCount", len(sourceConfig.Sources), "root", "local signing key; no hardware attestation")
	evaluator, err := evaluation.NewEvaluator(sourceGroup.candidates, verification)
	if err != nil {
		setupLog.Error(err, "initialize strict evidence evaluation")
		os.Exit(1)
	}
	receiptStore, ok := evidenceRepo.(ports.ReceiptRepository)
	if !ok {
		setupLog.Error(fmt.Errorf("receipt persistence not available"), "a durable receipt store is required")
		os.Exit(1)
	}
	if err = mgr.Add(sourceGroup); err != nil {
		setupLog.Error(err, "register source lifecycle")
		os.Exit(1)
	}
	if err = (&reconcile.LiveControlReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(), Resolver: sourceGroup.resolver, Evaluator: evaluator, Signer: signer, Receipts: receiptStore, Interval: evaluationInterval, Sources: sourceGroup.candidates}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "register live evaluation")
		os.Exit(1)
	}

	if err = (&reconcile.AssuranceStateReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Log:    ctrl.Log.WithName("controllers").WithName("AssuranceState"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AssuranceState")
		os.Exit(1)
	}

	if err = (&reconcile.ControlExceptionReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Log:    ctrl.Log.WithName("controllers").WithName("ControlException"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ControlException")
		os.Exit(1)
	}

	if err = (&reconcile.AssurancePolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Log:    ctrl.Log.WithName("controllers").WithName("AssurancePolicy"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AssurancePolicy")
		os.Exit(1)
	}

	if err = (&reconcile.CapabilityLeaseReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Log:           ctrl.Log.WithName("controllers").WithName("CapabilityLease"),
		ReceiptSigner: receiptMgr,
		EvidenceRepo:  evidenceRepo,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CapabilityLease")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("sources", sourceGroup.Ready); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	if enableWebhook {
		whCfg := webhook.ServerConfig{
			ListenAddr: fmt.Sprintf(":%d", webhookPort),
			Mode:       webhook.WebhookMode(webhookMode),
			ObserverAuth: assurance.AuthorityRef{
				Scheme:  "k8s:admission-controller",
				Subject: fmt.Sprintf("%s/%s", webhookNamespace, webhookServiceName),
			},
			EvidenceSink: func(env assurance.EvidenceEnvelope) {
				sinkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, putErr := evidenceRepo.Put(sinkCtx, env, nil); putErr != nil {
					setupLog.Error(putErr, "failed to persist in-flight evidence envelope", "envelopeID", env.ID)
				} else {
					setupLog.Info("Persisted in-flight admission evidence envelope", "envelopeID", env.ID, "subject", env.Subject.URI())
				}
			},
		}

		if webhookTLSCertFile != "" && webhookTLSKeyFile != "" && fileReadable(webhookTLSCertFile) && fileReadable(webhookTLSKeyFile) {
			whCfg.TLSCertPath = webhookTLSCertFile
			whCfg.TLSKeyPath = webhookTLSKeyFile
			setupLog.Info("Using mounted TLS certificate and key for admission webhook", "cert", webhookTLSCertFile, "key", webhookTLSKeyFile)
		} else {
			dnsNames := []string{
				webhookServiceName,
				fmt.Sprintf("%s.%s", webhookServiceName, webhookNamespace),
				fmt.Sprintf("%s.%s.svc", webhookServiceName, webhookNamespace),
				fmt.Sprintf("%s.%s.svc.cluster.local", webhookServiceName, webhookNamespace),
				"oskal-webhook",
				"oskal-webhook.ckodex-system",
				"oskal-webhook.ckodex-system.svc",
				"oskal-webhook.ckodex-system.svc.cluster.local",
				"localhost",
			}
			ips := []net.IP{net.ParseIP("127.0.0.1")}
			certPEM, keyPEM, err := webhook.GenerateSelfSignedCert(webhookServiceName, dnsNames, ips)
			if err != nil {
				setupLog.Error(err, "unable to generate self-signed cert for webhook")
				os.Exit(1)
			}
			whCfg.TLSCertBytes = certPEM
			whCfg.TLSKeyBytes = keyPEM
		}

		whServer := webhook.NewAdmissionWebhookServer(whCfg)
		if err := mgr.Add(whServer); err != nil {
			setupLog.Error(err, "unable to register webhook server with manager")
			os.Exit(1)
		}
		setupLog.Info("Registered validating admission webhook with manager", "port", webhookPort, "service", webhookServiceName, "namespace", webhookNamespace, "mode", webhookMode)
	}

	setupLog.Info("Starting OSKAL Controller Manager", "version", version, "commit", commit, "built", date, "metrics", metricsAddr, "probes", probeAddr, "leaderElection", enableLeaderElection)
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func openEvidenceRepository(path string) (ports.EvidenceRepository, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("--evidence-dir must name a durable writable directory")
	}
	repo, err := storage.NewFilesystemEvidenceRepository(path)
	if err != nil {
		return nil, fmt.Errorf("open durable evidence store: %w", err)
	}
	return repo, nil
}

func fileReadable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() > 0
}
