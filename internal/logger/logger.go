package logger

import (
	"fmt"
	"log/slog"
	"os"
)

// Setup configures the default slog logger. The verbose flag takes precedence; if true, debug level is used. Otherwise, LOG_LEVEL environment variable is checked, defaulting to INFO if not set or invalid.
func Setup(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	} else {
		if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
			var l slog.Level
			if err := l.UnmarshalText([]byte(envLevel)); err == nil {
				level = l
			} else {
				fmt.Fprintf(os.Stderr, "Invalid LOG_LEVEL %q, defaulting to INFO\n", envLevel)
			}
		}
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(logger)
}
