package logger

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/sirupsen/logrus"
)

// Setup configures the default slog logger and the global logrus logger. The verbose flag takes precedence; if true, debug level is used for both. Otherwise, the LOG_LEVEL environment variable is checked to set the level for both, defaulting to INFO if not set or invalid.
func Setup(verbose bool) {
	level := slog.LevelInfo
	logrusLevel := logrus.InfoLevel

	if verbose {
		level = slog.LevelDebug
		logrusLevel = logrus.DebugLevel
	} else {
		if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
			var slogOk, logrusOk bool

			var l slog.Level
			if err := l.UnmarshalText([]byte(envLevel)); err == nil {
				level = l
				slogOk = true
			}

			if parsedLevel, err := logrus.ParseLevel(envLevel); err == nil {
				logrusLevel = parsedLevel
				logrusOk = true
			}

			if !slogOk && !logrusOk {
				fmt.Fprintf(os.Stderr, "Invalid LOG_LEVEL %q, defaulting to INFO\n", envLevel)
			}
		}
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(logger)

	logrus.SetLevel(logrusLevel)
}
