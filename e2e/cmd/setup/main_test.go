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

import "testing"

func TestImageLoaderFor(t *testing.T) {
	tests := []struct {
		ctx  string
		want imageLoader
		name string
	}{
		{"minikube", loaderMinikube, "minikube"},
		{"kind-e2e", loaderKind, "e2e"},
		{"docker-desktop", loaderSharedDaemon, ""},
		{"gke_proj_zone_cluster", loaderNone, ""},
	}
	for _, tt := range tests {
		got, name := imageLoaderFor(tt.ctx)
		if got != tt.want || name != tt.name {
			t.Errorf("imageLoaderFor(%q) = (%v, %q), want (%v, %q)", tt.ctx, got, name, tt.want, tt.name)
		}
	}
}
