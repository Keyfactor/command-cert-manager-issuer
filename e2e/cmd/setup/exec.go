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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// execOpts controls how a command is run.
type execOpts struct {
	stdin  []byte // optional stdin. Used to pass secrets without exposing them in argv.
	stream bool   // stream stdout/stderr to the terminal instead of capturing stdout
	quiet  bool   // do not echo the command line
}

// execCmd runs a command and returns its captured stdout. Arguments are echoed
// to the terminal, so they must never contain secret values.
func execCmd(ctx context.Context, o execOpts, name string, args ...string) (string, error) {
	if !o.quiet {
		fmt.Printf("  $ %s %s\n", name, strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, name, args...)
	if o.stdin != nil {
		cmd.Stdin = bytes.NewReader(o.stdin)
	}

	var stdout, stderr bytes.Buffer
	if o.stream {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return stdout.String(), fmt.Errorf("%s %s: %w: %s", name, args[0], err, msg)
		}
		return stdout.String(), fmt.Errorf("%s %s: %w", name, args[0], err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// cluster runs kubectl and helm against one explicitly named kubeconfig
// context, so that nothing depends on the kubeconfig's current-context.
type cluster struct {
	kubeContext string
}

func (c cluster) kubectl(ctx context.Context, o execOpts, args ...string) (string, error) {
	return execCmd(ctx, o, "kubectl", append([]string{"--context", c.kubeContext}, args...)...)
}

func (c cluster) helm(ctx context.Context, o execOpts, args ...string) (string, error) {
	return execCmd(ctx, o, "helm", append([]string{"--kube-context", c.kubeContext}, args...)...)
}

// applyManifest applies a manifest through stdin. The manifest may contain
// secret data, so it is never echoed.
func (c cluster) applyManifest(ctx context.Context, manifest []byte) error {
	_, err := c.kubectl(ctx, execOpts{stdin: manifest, quiet: true}, "apply", "-f", "-")
	return err
}

// requireTools verifies that each tool is on the PATH.
func requireTools(tools ...string) error {
	var missing []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required tools not found on PATH: %s", strings.Join(missing, ", "))
	}
	return nil
}

// isTerminal reports whether f is an interactive terminal.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// confirm makes the user type the kubeconfig context name before anything is
// changed, so the wrong cluster is not modified by accident. Without a
// terminal, it refuses to continue unless --yes was given.
func confirm(in io.Reader, kubeContext string, yes bool) error {
	if yes {
		fmt.Println("--yes given, skipping confirmation.")
		return nil
	}
	if f, ok := in.(*os.File); ok && !isTerminal(f) {
		return errors.New("stdin is not a terminal, so the target cluster cannot be confirmed; re-run with --yes to proceed")
	}

	fmt.Printf("\nType the kubeconfig context name (%s) to continue: ", kubeContext)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if strings.TrimSpace(line) != kubeContext {
		return errors.New("confirmation did not match the context name; aborting")
	}
	return nil
}
