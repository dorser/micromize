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
	"fmt"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const exemptLabelValue = "true"

const (
	// podNamespaceEnvVar can be populated via the Kubernetes Downward API
	// (fieldRef: metadata.namespace).
	podNamespaceEnvVar = "POD_NAMESPACE"
	// serviceAccountNamespacePath is the namespace file mounted into every pod
	// that has a service account token.
	serviceAccountNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// CurrentNamespace returns the namespace the agent is running in. It is
// discovered from the POD_NAMESPACE environment variable (Downward API) first,
// then the in-cluster service account namespace file. When neither is available
// (e.g. running outside Kubernetes), it returns fallback. This avoids hardcoding
// the agent's namespace, which would otherwise let it monitor itself when the
// chart is installed into an arbitrarily named namespace.
func CurrentNamespace(fallback string) string {
	if ns := strings.TrimSpace(os.Getenv(podNamespaceEnvVar)); ns != "" {
		return ns
	}
	if data, err := os.ReadFile(serviceAccountNamespacePath); err == nil {
		if ns := strings.TrimSpace(string(data)); ns != "" {
			return ns
		}
	}
	return fallback
}

// NewClient builds a Kubernetes client using in-cluster config, falling back
// to the default kubeconfig for local development.
func NewClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("building kubernetes client config: %w", err)
		}
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}
	return client, nil
}

// ListExemptNamespaces returns the names of namespaces that carry the label
// <labelKey>=true. An empty key is rejected; any other validation of the key
// is left to the Kubernetes API server.
func ListExemptNamespaces(ctx context.Context, client kubernetes.Interface, labelKey string) ([]string, error) {
	if strings.TrimSpace(labelKey) == "" {
		return nil, fmt.Errorf("exempt label key must not be empty")
	}

	selector := fmt.Sprintf("%s=%s", labelKey, exemptLabelValue)
	list, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces with label %q: %w", selector, err)
	}

	names := make([]string, 0, len(list.Items))
	for _, ns := range list.Items {
		names = append(names, ns.Name)
	}
	return names, nil
}
