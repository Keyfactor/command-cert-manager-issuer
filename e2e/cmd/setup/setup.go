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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type credentials struct {
	tokenURL, clientID, clientSecret, audience, scopes string
}

func credentialsFromEnv() (credentials, error) {
	c := credentials{
		tokenURL:     os.Getenv(envTokenURL),
		clientID:     os.Getenv(envClientID),
		clientSecret: os.Getenv(envClientSecret),
		audience:     os.Getenv(envAudience),
		scopes:       os.Getenv(envScopes),
	}

	var missing []string
	for name, v := range map[string]string{envTokenURL: c.tokenURL, envClientID: c.clientID, envClientSecret: c.clientSecret} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return c, fmt.Errorf("required environment variables are not set: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

func runSetup(ctx context.Context, args []string) error {
	var o options
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	registerCommonFlags(fs, &o)
	fs.StringVar(&o.chartVersion, "chart-version", localTag, `Helm chart to deploy: "local" for the chart in this repository, or a published chart version (e.g. 2.5.0)`)
	fs.StringVar(&o.imageTag, "image-tag", localTag, `Image tag to deploy: "local" builds the image from this repository, or a published tag (e.g. 2.5.0)`)
	fs.StringVar(&o.imageRepository, "image-repository", defaultImageRepo, "Image repository. Must be set explicitly with --push.")
	fs.BoolVar(&o.push, "push", false, "Push the locally built image to --image-repository instead of loading it into the cluster")
	fs.StringVar(&o.certManagerVersion, "cert-manager-version", "v1.17.0", "cert-manager chart version to install if cert-manager is not already present")
	fs.StringVar(&o.caCertsDir, "ca-certs-dir", "", "Directory of CA certificates to trust when connecting to Command (default: <repo root>/e2e/certs)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := resolveCommon(&o); err != nil {
		return err
	}
	creds, err := credentialsFromEnv()
	if err != nil {
		return fmt.Errorf("%w\nSee e2e/README.md for the full list, or pass --env-file", err)
	}

	imageRepoExplicit := false
	fs.Visit(func(f *flag.Flag) { imageRepoExplicit = imageRepoExplicit || f.Name == "image-repository" })

	localImage := o.imageTag == localTag
	localChart := o.chartVersion == localTag

	if o.push && !localImage {
		return errors.New("--push only applies when --image-tag is \"local\"")
	}
	if o.push && !imageRepoExplicit {
		return errors.New("--push requires --image-repository to be set explicitly, to avoid pushing to the default public repository")
	}
	if (localImage || localChart) && o.repoRoot == "" {
		return errors.New("could not find the repository root (needed for the local chart or image); run from inside the repository or pass --repo-root")
	}

	tools := []string{"kubectl", "helm"}
	if localImage {
		tools = append(tools, "docker")
	}
	if err := requireTools(tools...); err != nil {
		return err
	}

	kubeContext, server, err := resolveContext(ctx, o.kubeContext)
	if err != nil {
		return err
	}
	c := cluster{kubeContext: kubeContext}

	// Decide up front how a local image will reach the cluster, so that this
	// fails before anything is changed.
	var loader imageLoader
	var loaderName string
	if localImage && !o.push {
		loader, loaderName = imageLoaderFor(kubeContext)
		if loader == loaderNone {
			return fmt.Errorf("don't know how to load a local image into context %q. Re-run with --push and --image-repository pointing to a registry the cluster can pull from, or use --image-tag with a published version", kubeContext)
		}
		if err := requireTools(loader.tool()); err != nil {
			return err
		}
	}

	caCerts, err := collectCACerts(&o)
	if err != nil {
		return err
	}

	printSetupSummary(o, creds, kubeContext, server, loader, caCerts)
	if err := confirm(os.Stdin, kubeContext, o.yes); err != nil {
		return err
	}

	step("Checking cluster connectivity")
	if _, err := c.kubectl(ctx, execOpts{}, "get", "--raw", "/version"); err != nil {
		return fmt.Errorf("cannot reach cluster: %w", err)
	}

	step("Ensuring cert-manager is installed")
	if err := ensureCertManager(ctx, c, o.certManagerVersion); err != nil {
		return err
	}

	step("Ensuring namespace %s exists", o.namespace)
	if err := c.applyManifest(ctx, mustJSON(map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": o.namespace},
	})); err != nil {
		return err
	}

	step("Creating Secrets in namespace %s", o.namespace)
	if err := applyAuthSecret(ctx, c, o, creds); err != nil {
		return err
	}
	if len(caCerts) > 0 {
		if err := applyCASecret(ctx, c, o, caCerts); err != nil {
			return err
		}
	}

	imageRef := o.imageRepository + ":" + o.imageTag
	if localImage {
		step("Building image %s", imageRef)
		if _, err := execCmd(ctx, execOpts{stream: true}, "docker", "build", "-t", imageRef, o.repoRoot); err != nil {
			return err
		}
		if o.push {
			step("Pushing image %s", imageRef)
			if _, err := execCmd(ctx, execOpts{stream: true}, "docker", "push", imageRef); err != nil {
				return err
			}
		} else {
			step("Loading image %s into %s", imageRef, kubeContext)
			if err := loader.load(ctx, imageRef, loaderName); err != nil {
				return err
			}
		}
	}

	step("Deploying %s", o.releaseName)
	if err := deployIssuer(ctx, c, o, localChart, localImage, loader); err != nil {
		return err
	}

	fmt.Printf("\nSetup complete. The issuer is running in namespace %s.\n", o.namespace)
	fmt.Printf("Auth Secret: %s/%s\n", o.namespace, o.authSecretName)
	if len(caCerts) > 0 {
		fmt.Printf("CA trust Secret: %s/%s\n", o.namespace, o.caSecretName)
	}
	return nil
}

func printSetupSummary(o options, creds credentials, kubeContext, server string, loader imageLoader, caCerts []string) {
	chart := "published chart " + o.chartVersion
	if o.chartVersion == localTag {
		chart = "local chart from " + filepath.Join(o.repoRoot, localChartRelPath)
	}

	image := "published image " + o.imageRepository + ":" + o.imageTag
	switch {
	case o.imageTag == localTag && o.push:
		image = "local build, pushed to " + o.imageRepository + ":" + o.imageTag
	case o.imageTag == localTag:
		image = "local build, loaded into the cluster (" + loader.String() + ")"
	}

	fmt.Println("The setup will make changes to this cluster:")
	fmt.Println()
	fmt.Printf("  Kubernetes context : %s\n", kubeContext)
	fmt.Printf("  API server         : %s\n", server)
	fmt.Println()
	fmt.Printf("  cert-manager       : install %s only if not already present\n", o.certManagerVersion)
	fmt.Printf("  Namespace          : %s\n", o.namespace)
	fmt.Printf("  Helm release       : %s\n", o.releaseName)
	fmt.Printf("  Chart              : %s\n", chart)
	fmt.Printf("  Image              : %s\n", image)
	fmt.Printf("  Auth Secret        : %s\n", o.authSecretName)
	if len(caCerts) > 0 {
		fmt.Printf("  CA trust Secret    : %s (%d certificate file(s) from %s)\n", o.caSecretName, len(caCerts), o.caCertsDir)
	} else {
		fmt.Printf("  CA trust Secret    : not created (no certificate files in %s)\n", o.caCertsDir)
	}
	fmt.Println()
	fmt.Println("  Command credentials (values are never printed):")
	fmt.Printf("    %-24s %s\n", envTokenURL, creds.tokenURL)
	fmt.Printf("    %-24s %s\n", envClientID, "set")
	fmt.Printf("    %-24s %s\n", envClientSecret, "set")
	fmt.Printf("    %-24s %s\n", envAudience, setOrUnset(creds.audience))
	fmt.Printf("    %-24s %s\n", envScopes, setOrUnset(creds.scopes))
}

func setOrUnset(v string) string {
	if v == "" {
		return "not set"
	}
	return "set"
}

// ensureCertManager installs cert-manager unless it is already present, either
// as a Helm release or as CRDs from some other installation method. Existing
// installations are never modified.
func ensureCertManager(ctx context.Context, c cluster, version string) error {
	ns := "cert-manager"

	if _, err := c.helm(ctx, execOpts{quiet: true}, "status", "cert-manager", "-n", ns); err == nil {
		fmt.Println("cert-manager Helm release found in namespace", ns, "- leaving it as is.")
		return nil
	}
	if _, err := c.kubectl(ctx, execOpts{quiet: true}, "get", "crd", certManagerCRD); err == nil {
		fmt.Println("cert-manager CRDs found (installed outside of this tool) - leaving it as is.")
		return nil
	}

	if _, err := c.helm(ctx, execOpts{stream: true},
		"install", "cert-manager", "cert-manager",
		"--repo", certManagerRepoURL,
		"--version", version,
		"--namespace", ns, "--create-namespace",
		"--set", "crds.enabled=true",
		"--wait", "--timeout", "5m",
	); err != nil {
		return err
	}
	return nil
}

func applyAuthSecret(ctx context.Context, c cluster, o options, creds credentials) error {
	data := map[string]string{
		"tokenUrl":     creds.tokenURL,
		"clientId":     creds.clientID,
		"clientSecret": creds.clientSecret,
	}
	if creds.audience != "" {
		data["audience"] = creds.audience
	}
	if creds.scopes != "" {
		data["scopes"] = creds.scopes
	}

	fmt.Printf("  applying Secret %s/%s\n", o.namespace, o.authSecretName)
	return c.applyManifest(ctx, mustJSON(secretManifest(o.namespace, o.authSecretName, data)))
}

func applyCASecret(ctx context.Context, c cluster, o options, files []string) error {
	var bundle strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		bundle.Write(b)
		if !strings.HasSuffix(bundle.String(), "\n") {
			bundle.WriteByte('\n')
		}
	}

	fmt.Printf("  applying Secret %s/%s\n", o.namespace, o.caSecretName)
	return c.applyManifest(ctx, mustJSON(secretManifest(o.namespace, o.caSecretName, map[string]string{"ca.crt": bundle.String()})))
}

func secretManifest(namespace, name string, stringData map[string]string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"type":       "Opaque",
		"stringData": stringData,
	}
}

// collectCACerts returns the certificate files to bundle into the CA trust Secret.
func collectCACerts(o *options) ([]string, error) {
	if o.caCertsDir == "" {
		if o.repoRoot == "" {
			return nil, nil
		}
		o.caCertsDir = filepath.Join(o.repoRoot, "e2e", "certs")
	}

	entries, err := os.ReadDir(o.caCertsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		files = append(files, filepath.Join(o.caCertsDir, e.Name()))
	}
	return files, nil
}

func deployIssuer(ctx context.Context, c cluster, o options, localChart, localImage bool, loader imageLoader) error {
	args := []string{"upgrade", "--install", o.releaseName}

	if localChart {
		args = append(args, filepath.Join(o.repoRoot, localChartRelPath))
	} else {
		args = append(args, chartName, "--repo", chartRepoURL, "--version", o.chartVersion)
		if strings.Contains(o.chartVersion, "-") {
			args = append(args, "--devel") // allow pre-release versions
		}
	}

	args = append(args,
		"--namespace", o.namespace,
		"--set", "fullnameOverride="+o.releaseName,
		"--set", "image.tag="+o.imageTag,
	)
	if localImage || o.imageRepository != defaultImageRepo {
		args = append(args, "--set", "image.repository="+o.imageRepository)
	}
	if localImage {
		// A loaded image only exists on the node; a pushed one is mutable under the same tag.
		policy := "Always"
		if loader != loaderNone {
			policy = "Never"
		}
		args = append(args, "--set", "image.pullPolicy="+policy)
	}
	args = append(args, "--wait", "--timeout", "5m")

	if _, err := c.helm(ctx, execOpts{stream: true}, args...); err != nil {
		return err
	}

	// A rebuilt image reuses the "local" tag, so Helm sees no change and keeps the old pods.
	if localImage {
		if _, err := c.kubectl(ctx, execOpts{stream: true}, "-n", o.namespace, "rollout", "restart", "deployment/"+o.releaseName); err != nil {
			return err
		}
	}
	_, err := c.kubectl(ctx, execOpts{stream: true}, "-n", o.namespace, "rollout", "status", "deployment/"+o.releaseName, "--timeout", "300s")
	return err
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only called with plain maps of strings
	}
	return b
}
