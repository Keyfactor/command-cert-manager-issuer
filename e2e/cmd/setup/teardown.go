/*
Copyright © 2026 Keyfactor

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
	"context"
	"flag"
	"fmt"
	"os"
)

func runTeardown(ctx context.Context, args []string) error {
	var o options
	fs := flag.NewFlagSet("teardown", flag.ContinueOnError)
	registerCommonFlags(fs, &o)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := resolveCommon(&o); err != nil {
		return err
	}
	if err := requireTools("kubectl", "helm"); err != nil {
		return err
	}

	kubeContext, server, err := resolveContext(ctx, o.kubeContext)
	if err != nil {
		return err
	}
	c := cluster{kubeContext: kubeContext}

	fmt.Println("The teardown will delete the following from this cluster:")
	fmt.Println()
	fmt.Printf("  Kubernetes context : %s\n", kubeContext)
	fmt.Printf("  API server         : %s\n", server)
	fmt.Println()
	fmt.Printf("  Helm release       : %s (namespace %s)\n", o.releaseName, o.namespace)
	fmt.Printf("  Auth Secret        : %s\n", o.authSecretName)
	fmt.Printf("  CA trust Secret    : %s\n", o.caSecretName)
	fmt.Println()
	fmt.Println("  cert-manager and the namespace are not removed.")
	if err := confirm(os.Stdin, kubeContext, o.yes); err != nil {
		return err
	}

	step("Uninstalling %s", o.releaseName)
	if _, err := c.helm(ctx, execOpts{quiet: true}, "status", o.releaseName, "-n", o.namespace); err != nil {
		fmt.Println("Helm release not found, skipping.")
	} else if _, err := c.helm(ctx, execOpts{stream: true}, "uninstall", o.releaseName, "-n", o.namespace, "--wait"); err != nil {
		return err
	}

	step("Deleting Secrets")
	for _, name := range []string{o.authSecretName, o.caSecretName} {
		if _, err := c.kubectl(ctx, execOpts{stream: true}, "-n", o.namespace, "delete", "secret", name, "--ignore-not-found"); err != nil {
			return err
		}
	}

	fmt.Println("\nTeardown complete.")
	return nil
}
