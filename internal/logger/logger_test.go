package logger

import (
	"context"
	"log/slog"
	"testing"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name        string
		verbose     bool
		env         string
		checkLevel  slog.Level
		wantEnabled bool
	}{
		{"verbose true", true, "", slog.LevelDebug, true},
		{"verbose false, no env", false, "", slog.LevelInfo, true},
		{"verbose false, no env, debug check", false, "", slog.LevelDebug, false},
		{"verbose false, env DEBUG", false, "DEBUG", slog.LevelDebug, true},
		{"verbose false, env WARN", false, "WARN", slog.LevelInfo, false},
		{"verbose false, env WARN check warn", false, "WARN", slog.LevelWarn, true},
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
		})
	}
}
