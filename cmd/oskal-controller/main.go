package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	assurancev1alpha1 "github.com/ckodex-labs/ckodex-oskal/api/assurance/v1alpha1"
	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/webhook"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/reconcile"
)

var (
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

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. Enabling this will ensure only one active controller manager.")
	flag.BoolVar(&enableWebhook, "enable-webhook", true, "Enable validating admission webhook with in-flight attestation.")
	flag.IntVar(&webhookPort, "webhook-port", 8443, "The port the validating admission webhook listens on.")

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

	evaluator := &reconcile.ContractEvaluator{}

	if err = (&reconcile.ControlBindingReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		Log:            ctrl.Log.WithName("controllers").WithName("ControlBinding"),
		ClaimEvaluator: evaluator,
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

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	if enableWebhook {
		dnsNames := []string{
			"oskal-webhook",
			"oskal-webhook.ckodex-system",
			"oskal-webhook.ckodex-system.svc",
			"oskal-webhook.ckodex-system.svc.cluster.local",
			"localhost",
		}
		ips := []net.IP{net.ParseIP("127.0.0.1")}
		certPEM, keyPEM, err := webhook.GenerateSelfSignedCert("oskal-webhook", dnsNames, ips)
		if err != nil {
			setupLog.Error(err, "unable to generate self-signed cert for webhook")
			os.Exit(1)
		}

		whServer := webhook.NewAdmissionWebhookServer(webhook.ServerConfig{
			ListenAddr:   fmt.Sprintf(":%d", webhookPort),
			TLSCertBytes: certPEM,
			TLSKeyBytes:  keyPEM,
			ObserverAuth: assurance.AuthorityRef{
				Scheme:  "k8s:admission-controller",
				Subject: "ckodex-system/oskal-webhook",
			},
		})
		if err := mgr.Add(whServer); err != nil {
			setupLog.Error(err, "unable to register webhook server with manager")
			os.Exit(1)
		}
		setupLog.Info("Registered validating admission webhook with manager", "port", webhookPort)
	}

	setupLog.Info("Starting OSKAL Controller Manager", "metrics", metricsAddr, "probes", probeAddr, "leaderElection", enableLeaderElection)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
