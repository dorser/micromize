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
