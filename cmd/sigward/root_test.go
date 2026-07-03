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

package main

import "testing"

func TestBuildNamespaceFilter(t *testing.T) {
	tests := []struct {
		name             string
		filterNamespaces string
		want             string
	}{
		{
			name:             "empty filter returns only sigward exclusion",
			filterNamespaces: "",
			want:             "!sigward",
		},
		{
			name:             "single namespace appends sigward exclusion",
			filterNamespaces: "default",
			want:             "!sigward,default",
		},
		{
			name:             "multiple namespaces append sigward exclusion",
			filterNamespaces: "default,kube-system",
			want:             "!sigward,default,kube-system",
		},
		{
			name:             "user already excludes sigward",
			filterNamespaces: "default,!sigward",
			want:             "!sigward,default",
		},
		{
			name:             "empty segments are skipped",
			filterNamespaces: "default,,kube-system,",
			want:             "!sigward,default,kube-system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildNamespaceFilter(tt.filterNamespaces)
			if got != tt.want {
				t.Errorf("buildNamespaceFilter(%q) = %q, want %q", tt.filterNamespaces, got, tt.want)
			}
		})
	}
}
