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
