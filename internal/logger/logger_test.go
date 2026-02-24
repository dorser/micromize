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

package logger

import (
	"context"
	"log/slog"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name        string
		verbose     bool
		env         string
		checkLevel  slog.Level
		wantEnabled bool
		wantLogrus  logrus.Level
	}{
		{"verbose true", true, "", slog.LevelDebug, true, logrus.DebugLevel},
		{"verbose false, no env", false, "", slog.LevelInfo, true, logrus.InfoLevel},
		{"verbose false, no env, debug check", false, "", slog.LevelDebug, false, logrus.InfoLevel},
		{"verbose false, env DEBUG", false, "DEBUG", slog.LevelDebug, true, logrus.DebugLevel},
		{"verbose false, env WARN", false, "WARN", slog.LevelInfo, false, logrus.WarnLevel},
		{"verbose false, env WARN check warn", false, "WARN", slog.LevelWarn, true, logrus.WarnLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("LOG_LEVEL", tt.env)
			} else {
				t.Setenv("LOG_LEVEL", "")
			}

			Setup(tt.verbose)

			if got := slog.Default().Enabled(context.Background(), tt.checkLevel); got != tt.wantEnabled {
				t.Errorf("Enabled(%v) = %v, want %v", tt.checkLevel, got, tt.wantEnabled)
			}

			if got := logrus.GetLevel(); got != tt.wantLogrus {
				t.Errorf("logrus.GetLevel() = %v, want %v", got, tt.wantLogrus)
			}
		})
	}
}
