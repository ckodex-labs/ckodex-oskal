package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/kubernetes"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/storage"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/webhook"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/reconcile"
	"github.com/ckodex-labs/ckodex-oskal/internal/ports"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/ckodex-labs/ckodex-oskal/internal/verifier"
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

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. Enabling this will ensure only one active controller manager.")
	flag.BoolVar(&enableWebhook, "enable-webhook", true, "Enable validating admission webhook with in-flight attestation.")
	flag.IntVar(&webhookPort, "webhook-port", 8443, "The port the validating admission webhook listens on.")
	flag.StringVar(&webhookServiceName, "webhook-service-name", "oskal-webhook", "Kubernetes Service name for the admission webhook.")
	flag.StringVar(&webhookNamespace, "webhook-namespace", "ckodex-system", "Kubernetes Namespace for the admission webhook.")
	flag.StringVar(&webhookMode, "webhook-mode", "enforcing", "Webhook mode (enforcing or monitor-only).")
	flag.StringVar(&webhookTLSCertFile, "webhook-tls-cert-file", "", "Path to TLS certificate file for the admission webhook.")
	flag.StringVar(&webhookTLSKeyFile, "webhook-tls-key-file", "", "Path to TLS private key file for the admission webhook.")
	flag.StringVar(&evidenceDir, "evidence-dir", "/tmp/oskal/evidence", "Path to local directory for content-addressed evidence storage.")

	opts := zap.Options{
		Development: false,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
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

	var evidenceRepo ports.EvidenceRepository
	if evidenceDir != "" {
		fsRepo, err := storage.NewFilesystemEvidenceRepository(evidenceDir)
		if err != nil {
			setupLog.Error(err, "unable to initialize filesystem evidence repository, falling back to in-memory", "path", evidenceDir)
			evidenceRepo = storage.NewMemoryEvidenceRepository()
		} else {
			evidenceRepo = fsRepo
			setupLog.Info("Initialized filesystem content-addressed evidence repository", "path", evidenceDir)
		}
	} else {
		evidenceRepo = storage.NewMemoryEvidenceRepository()
		setupLog.Info("Initialized in-memory content-addressed evidence repository")
	}

	evaluator := &reconcile.ContractEvaluator{
		EvidenceRepo: evidenceRepo,
		Verifier:     verifier.NewDefaultEvidenceVerifier(),
	}

	receiptMgr, err := receipts.LoadOrCreateReceiptManager(assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "prod/ns/ckodex-system/sa/oskal-controller",
		TrustDomain: "prod",
	}, evidenceDir)
	if err != nil {
		setupLog.Error(err, "unable to initialize receipt manager")
		os.Exit(1)
	}

	subjectResolver := kubernetes.NewSubjectResolver(mgr.GetClient())
	controlResolver := kubernetes.NewControlResolver(mgr.GetClient())
	svidValidator := spire.NewSVIDValidator(spire.NewTrustBundle(), assurance.AuthorityRef{
		Scheme:      "spiffe",
		Subject:     "prod/ns/ckodex-system/sa/oskal-controller",
		TrustDomain: "prod",
	})

	if err = (&reconcile.ControlBindingReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Log:             ctrl.Log.WithName("controllers").WithName("ControlBinding"),
		ClaimEvaluator:  evaluator,
		EvidenceRepo:    evidenceRepo,
		SubjectResolver: subjectResolver,
		ControlResolver: controlResolver,
		ReceiptSigner:   receiptMgr,
		SVIDValidator:   svidValidator,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ControlBinding")
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
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
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
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func fileReadable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() > 0
}
