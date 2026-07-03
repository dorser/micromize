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

func TestBuildDisabledSet(t *testing.T) {
	tests := []struct {
		name           string
		disableGadgets string
		wantDisabled   []string
		wantEnabled    []string
	}{
		{
			name:           "empty string disables nothing",
			disableGadgets: "",
			wantEnabled:    []string{"ptrace-restrict", "fs-restrict"},
		},
		{
			name:           "single gadget disabled",
			disableGadgets: "ptrace-restrict",
			wantDisabled:   []string{"ptrace-restrict"},
			wantEnabled:    []string{"fs-restrict", "cap-restrict"},
		},
		{
			name:           "multiple gadgets disabled",
			disableGadgets: "ptrace-restrict,cap-restrict",
			wantDisabled:   []string{"ptrace-restrict", "cap-restrict"},
			wantEnabled:    []string{"fs-restrict"},
		},
		{
			name:           "whitespace around names is trimmed",
			disableGadgets: " ptrace-restrict , cap-restrict ",
			wantDisabled:   []string{"ptrace-restrict", "cap-restrict"},
			wantEnabled:    []string{"fs-restrict"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDisabledSet(tt.disableGadgets)
			for _, g := range tt.wantDisabled {
				if !got[g] {
					t.Errorf("buildDisabledSet(%q): expected %q to be disabled", tt.disableGadgets, g)
				}
			}
			for _, g := range tt.wantEnabled {
				if got[g] {
					t.Errorf("buildDisabledSet(%q): expected %q to be enabled", tt.disableGadgets, g)
				}
			}
		})
	}
}
