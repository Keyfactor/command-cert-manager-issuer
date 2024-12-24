/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/utils/clock"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	commandissuerv1alpha1 "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
	"github.com/Keyfactor/command-cert-manager-issuer/internal/command"
	"github.com/Keyfactor/command-cert-manager-issuer/internal/controller"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
	_        = cmapi.AddToScheme(scheme)
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(commandissuerv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var clusterResourceNamespace string
	var disableApprovedCheck bool
	var secretAccessGrantedAtClusterLevel bool

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false,
		"If set the metrics endpoint is served securely")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.StringVar(&clusterResourceNamespace, "cluster-resource-namespace", "", "The namespace for secrets in which cluster-scoped resources are found.")
	flag.BoolVar(&disableApprovedCheck, "disable-approved-check", false,
		"Disables waiting for CertificateRequests to have an approved condition before signing.")
	flag.BoolVar(&secretAccessGrantedAtClusterLevel, "secret-access-granted-at-cluster-level", false,
		"Set this flag to true if the secret access is granted at cluster level. This will allow the controller to access secrets in any namespace. ")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancelation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	tlsOpts := []func(*tls.Config){}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: tlsOpts,
	})

	if clusterResourceNamespace == "" {
		var err error
		clusterResourceNamespace, err = getInClusterNamespace()
		if err != nil {
			if errors.Is(err, ErrNotInCluster) {
				setupLog.Error(err, "please supply --cluster-resource-namespace")
			} else {
				setupLog.Error(err, "unexpected error while getting in-cluster Namespace")
			}
			os.Exit(1)
		}
	}

	if secretAccessGrantedAtClusterLevel {
		setupLog.Info("expecting secret access at cluster level")
	} else {
		setupLog.Info(fmt.Sprintf("expecting secret access at namespace level (%s)", clusterResourceNamespace))
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: secureMetrics,
			TLSOpts:       tlsOpts,
		},
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "b68cef20.keyfactor.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.IssuerReconciler{
		Client:                            mgr.GetClient(),
		Kind:                              "Issuer",
		ClusterResourceNamespace:          clusterResourceNamespace,
		SecretAccessGrantedAtClusterLevel: secretAccessGrantedAtClusterLevel,
		Scheme:                            mgr.GetScheme(),
		HealthCheckerBuilder:              command.NewHealthChecker,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Issuer")
		os.Exit(1)
	}
	if err = (&controller.IssuerReconciler{
		Client:                            mgr.GetClient(),
		Scheme:                            mgr.GetScheme(),
		Kind:                              "ClusterIssuer",
		ClusterResourceNamespace:          clusterResourceNamespace,
		SecretAccessGrantedAtClusterLevel: secretAccessGrantedAtClusterLevel,
		HealthCheckerBuilder:              command.NewHealthChecker,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterIssuer")
		os.Exit(1)
	}
	if err = (&controller.CertificateRequestReconciler{
		Client:                            mgr.GetClient(),
		Scheme:                            mgr.GetScheme(),
		ClusterResourceNamespace:          clusterResourceNamespace,
		SignerBuilder:                     command.NewSignerBuilder,
		CheckApprovedCondition:            !disableApprovedCheck,
		SecretAccessGrantedAtClusterLevel: secretAccessGrantedAtClusterLevel,
		Clock:                             clock.RealClock{},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CertificateRequest")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

var ErrNotInCluster = errors.New("not running in-cluster")

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// Copied from controller-runtime/pkg/leaderelection
func getInClusterNamespace() (string, error) {
	// Check whether the namespace file exists.
	// If not, we are not running in cluster so can't guess the namespace.
	_, err := os.Stat(inClusterNamespacePath)
	if os.IsNotExist(err) {
		return "", ErrNotInCluster
	} else if err != nil {
		return "", fmt.Errorf("error checking namespace file: %w", err)
	}

	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(namespace), nil
}
