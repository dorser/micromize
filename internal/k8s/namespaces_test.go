// Copyright The micromize authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func namespace(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func TestListExemptNamespaces(t *testing.T) {
	const labelKey = "micromize.dev/exempt"

	tests := []struct {
		name       string
		namespaces []corev1.Namespace
		labelKey   string
		want       []string
		wantErr    bool
	}{
		{
			name:     "empty label key returns error",
			labelKey: "",
			wantErr:  true,
		},
		{
			name:     "whitespace label key returns error",
			labelKey: "   ",
			wantErr:  true,
		},
		{
			name:       "no namespaces returns empty slice",
			labelKey:   labelKey,
			namespaces: []corev1.Namespace{},
			want:       []string{},
		},
		{
			name:     "namespaces without label not returned",
			labelKey: labelKey,
			namespaces: []corev1.Namespace{
				namespace("default", nil),
				namespace("kube-system", map[string]string{"foo": "bar"}),
			},
			want: []string{},
		},
		{
			name:     "namespace with label=true is returned",
			labelKey: labelKey,
			namespaces: []corev1.Namespace{
				namespace("default", nil),
				namespace("azuresecuritylinuxagent", map[string]string{labelKey: "true"}),
			},
			want: []string{"azuresecuritylinuxagent"},
		},
		{
			name:     "namespace with label=false is not returned",
			labelKey: labelKey,
			namespaces: []corev1.Namespace{
				namespace("gadget", map[string]string{labelKey: "false"}),
			},
			want: []string{},
		},
		{
			name:     "multiple exempt namespaces all returned",
			labelKey: labelKey,
			namespaces: []corev1.Namespace{
				namespace("azuresecuritylinuxagent", map[string]string{labelKey: "true"}),
				namespace("gadget", map[string]string{labelKey: "true"}),
				namespace("default", nil),
			},
			want: []string{"azuresecuritylinuxagent", "gadget"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset()
			for _, ns := range tt.namespaces {
				ns := ns
				if _, err := client.CoreV1().Namespaces().Create(context.Background(), &ns, metav1.CreateOptions{}); err != nil {
					t.Fatalf("creating test namespace %q: %v", ns.Name, err)
				}
			}

			got, err := ListExemptNamespaces(context.Background(), client, tt.labelKey)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			wantSet := make(map[string]bool, len(tt.want))
			for _, w := range tt.want {
				wantSet[w] = true
			}
			gotSet := make(map[string]bool, len(got))
			for _, g := range got {
				gotSet[g] = true
			}

			for w := range wantSet {
				if !gotSet[w] {
					t.Errorf("expected namespace %q in result, got %v", w, got)
				}
			}
			for g := range gotSet {
				if !wantSet[g] {
					t.Errorf("unexpected namespace %q in result", g)
				}
			}
		})
	}
}

func TestCurrentNamespace(t *testing.T) {
	t.Run("returns POD_NAMESPACE env when set", func(t *testing.T) {
		t.Setenv(podNamespaceEnvVar, "team-security")
		if got := CurrentNamespace("micromize"); got != "team-security" {
			t.Errorf("CurrentNamespace() = %q, want %q", got, "team-security")
		}
	})

	t.Run("trims whitespace from env value", func(t *testing.T) {
		t.Setenv(podNamespaceEnvVar, "  prod  ")
		if got := CurrentNamespace("micromize"); got != "prod" {
			t.Errorf("CurrentNamespace() = %q, want %q", got, "prod")
		}
	})

	t.Run("falls back when env empty and no service account file", func(t *testing.T) {
		t.Setenv(podNamespaceEnvVar, "")
		if got := CurrentNamespace("sigward"); got != "sigward" {
			t.Errorf("CurrentNamespace() = %q, want %q", got, "sigward")
		}
	})
}
