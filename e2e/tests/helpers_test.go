//go:build e2e

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

package tests

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const pollInterval = 2 * time.Second

// Polls check until it reports done or the timeout elapses. check
// returns a short description of the current state, which is included in the
// failure message so a timeout says what the resource was doing. Errors from
// check are treated as transient and reported the same way.
func waitFor(t *testing.T, what string, timeout time.Duration, check func(ctx context.Context) (done bool, status string, err error)) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	last := "no status observed"
	for {
		done, status, err := check(ctx)
		switch {
		case err != nil:
			last = "error: " + err.Error()
		case status != "":
			last = status
		}
		if err == nil && done {
			return
		}

		select {
		case <-ctx.Done():
			t.Fatalf("timed out after %s waiting for %s; last status: %s", timeout, what, last)
		case <-time.After(pollInterval):
		}
	}
}

// Returns a short random string for unique resource names.
func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Creates a uniquely named namespace for one test and deletes it when the test ends,
// which also removes everything the test created in it.
// Set E2E_KEEP_RESOURCES=true to leave it for debugging.
func createTestNamespace(t *testing.T) string {
	t.Helper()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "e2e-" + randomSuffix(t),
		Labels: map[string]string{"app.kubernetes.io/managed-by": "command-cert-manager-issuer-e2e"},
	}}
	if err := suite.client.Create(context.Background(), ns); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}
	t.Logf("created namespace %s", ns.Name)

	t.Cleanup(func() {
		if suite.cfg.keepResources {
			t.Logf("%s=true: leaving namespace %s in place", envKeepResources, ns.Name)
			return
		}
		if err := suite.client.Delete(context.Background(), ns, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
			t.Logf("deleting namespace %s: %v", ns.Name, err)
		}
	})
	return ns.Name
}
