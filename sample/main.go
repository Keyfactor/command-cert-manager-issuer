package main

import (
	"context"
	"fmt"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/Keyfactor/command-cert-manager-issuer/internal/command"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
	_        = cmapi.AddToScheme(scheme)
)

func init() {
	//+kubebuilder:scaffold:scheme
}

func main() {
	logger := funcr.New(func(prefix, args string) {
		println(prefix, args)
	}, funcr.Options{})
	ctx := logr.NewContext(context.Background(), logger)
	log := log.FromContext(ctx)
	source, err := command.NewGCPDefaultCredentialSource(ctx, []string{"openid", "profile", "email", "https://www.googleapis.com/auth/cloud-platform"})
	if err != nil {
		log.Error(err, fmt.Sprintf("Error getting credentials: %s", err))
		return
	}
	token, err := source.GetAccessToken(ctx)
	if err != nil {
		log.Error(err, fmt.Sprintf("Error getting token: %s", err))
		return
	}
	log.Info(fmt.Sprintf("source obtained: %s", token))
	isValid := command.ValidateToken(ctx, token, "command")
	if !isValid {
		log.Info(fmt.Sprintf("Token not valid"))
	}
	log.Info(fmt.Sprintf("Token successfully validated"))
}
