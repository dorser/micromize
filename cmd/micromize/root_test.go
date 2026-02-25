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
			name:             "empty filter returns only micromize exclusion",
			filterNamespaces: "",
			want:             "!micromize",
		},
		{
			name:             "single namespace appends micromize exclusion",
			filterNamespaces: "default",
			want:             "!micromize,default",
		},
		{
			name:             "multiple namespaces append micromize exclusion",
			filterNamespaces: "default,kube-system",
			want:             "!micromize,default,kube-system",
		},
		{
			name:             "user already excludes micromize",
			filterNamespaces: "default,!micromize",
			want:             "!micromize,default",
		},
		{
			name:             "only micromize exclusion",
			filterNamespaces: "!micromize",
			want:             "!micromize",
		},
		{
			name:             "exclusion filter appends micromize exclusion",
			filterNamespaces: "!kube-system",
			want:             "!micromize,!kube-system",
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
