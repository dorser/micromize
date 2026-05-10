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

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/micromize-dev/micromize/internal/gadget"
	"github.com/micromize-dev/micromize/internal/logger"
	"github.com/micromize-dev/micromize/internal/operators"
	"github.com/micromize-dev/micromize/internal/runtime"
	"github.com/micromize-dev/micromize/internal/utils"
)

const (
	fsRestrictGadgetImageRepo        = "ghcr.io/micromize-dev/micromize/fs-restrict"
	capRestrictGadgetImageRepo       = "ghcr.io/micromize-dev/micromize/cap-restrict"
	ptraceRestrictGadgetImageRepo    = "ghcr.io/micromize-dev/micromize/ptrace-restrict"
	socketRestrictGadgetImageRepo    = "ghcr.io/micromize-dev/micromize/socket-restrict"
	binaryAttestationGadgetImageRepo = "ghcr.io/micromize-dev/micromize/binary-attestation"
)

var (
	enforce          bool
	verbose          bool
	filterNamespaces  string
	filterImageDigest string
	disableGadgets    string
)

var rootCmd = &cobra.Command{
	Use:   "micromize",
	Short: "micromize is a security hardening tool for containerized applications",
	Long:  `micromize is a security hardening tool designed to detect and break the post-exploit kill chain for containerized applications using BPF LSM.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Setup(verbose)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd.Context())
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = Version
	rootCmd.PersistentFlags().BoolVar(&enforce, "enforce", true, "Enforce restrictions")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&filterNamespaces, "filter-namespaces", "", "Comma-separated list of Kubernetes namespaces to monitor (empty means all except 'micromize'). Supports exclusion with '!' prefix.")
	rootCmd.PersistentFlags().StringVar(&filterImageDigest, "filter-image-digest", "", "Filter out containers running this image digest from monitoring (e.g. sha256:abc123...)")
	rootCmd.PersistentFlags().StringVar(&disableGadgets, "disable-gadgets", "", "Comma-separated list of gadgets to disable (e.g. ptrace-restrict,cap-restrict)")
}

func run(ctx context.Context) error {
	slog.Info("Starting micromize...")

	// Validate BPF LSM is enabled before starting
	if err := utils.ValidateBPFLSM(); err != nil {
		return fmt.Errorf("BPF LSM validation failed: %w", err)
	}
	slog.Info("BPF LSM is enabled")

	if enforce {
		slog.Info("Enforcement enabled")
	} else {
		slog.Info("Enforcement disabled (audit mode)")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("Received shutdown signal")
		cancel()
	}()

	runtimeManager, err := runtime.NewManager()
	if err != nil {
		return fmt.Errorf("initializing runtime manager: %w", err)
	}

	defer runtimeManager.Close()

	ociHandlerOp := operators.NewOCIHandler()
	imaOp := operators.NewImaOperator()
	eventTypeOp := operators.NewEventTypeOperator()
	outputOp := operators.NewOutputOperator()

	localManagerOp, err := operators.NewLocalManager()
	if err != nil {
		return fmt.Errorf("creating local manager operator: %w", err)
	}

	contextManager := gadget.NewContextManager([]operators.DataOperator{ociHandlerOp, localManagerOp, imaOp, eventTypeOp, outputOp})

	// Create gadget registry
	registry := gadget.NewRegistry(contextManager, runtimeManager)

	hostPidnsID, err := utils.GetHostPidNamespaceID()
	if err != nil {
		return fmt.Errorf("getting host pid namespace ID: %w", err)
	}

	nsFilter := buildNamespaceFilter(filterNamespaces)
	slog.Info("Namespace filter", "filter", nsFilter)

	disabled := buildDisabledSet(disableGadgets)
	if len(disabled) > 0 {
		slog.Info("Disabled gadgets", "gadgets", disableGadgets)
	}

	commonParams := map[string]string{
		"operator.oci.ebpf.enforce":           fmt.Sprintf("%d", utils.BoolToInt(enforce)),
		"operator.LocalManager.k8s-namespace": nsFilter,
	}

	if filterImageDigest != "" {
		digest := strings.TrimPrefix(filterImageDigest, "!")
		commonParams["operator.LocalManager.runtime-containerimage-digest"] = "!" + digest
		slog.Info("Filtering out containers by image digest", "digest", digest)
	}

	if !disabled["fs-restrict"] {
		registry.Register("fs-restrict", &gadget.GadgetConfig{
			Bytes:     fsRestrictGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", fsRestrictGadgetImageRepo, Version),
			Params:    commonParams,
		})
	}

	capRestrictParams := map[string]string{
		"operator.oci.ebpf.host_pidns_id": fmt.Sprintf("%d", hostPidnsID),
	}
	for k, v := range commonParams {
		capRestrictParams[k] = v
	}

	if !disabled["cap-restrict"] {
		registry.Register("cap-restrict", &gadget.GadgetConfig{
			Bytes:     capRestrictGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", capRestrictGadgetImageRepo, Version),
			Params:    capRestrictParams,
		})
	}

	if !disabled["ptrace-restrict"] {
		registry.Register("ptrace-restrict", &gadget.GadgetConfig{
			Bytes:     ptraceRestrictGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", ptraceRestrictGadgetImageRepo, Version),
			Params:    commonParams,
		})
	}

	if !disabled["socket-restrict"] {
		registry.Register("socket-restrict", &gadget.GadgetConfig{
			Bytes:     socketRestrictGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", socketRestrictGadgetImageRepo, Version),
			Params:    commonParams,
		})
	}

	if !disabled["binary-attestation"] {
		registry.Register("binary-attestation", &gadget.GadgetConfig{
			Bytes:     binaryAttestationGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", binaryAttestationGadgetImageRepo, Version),
			Params:    commonParams,
		})
	}

	// Run all gadgets
	if err := registry.RunAll(ctx); err != nil {
		return fmt.Errorf("running gadgets: %w", err)
	}

	// Wait for context to be done (which happens on signal)
	<-ctx.Done()
	return nil
}

// buildDisabledSet parses a comma-separated list of gadget names into a set
// for O(1) lookup. Empty string returns an empty set.
func buildDisabledSet(disableGadgets string) map[string]bool {
	disabled := make(map[string]bool)
	if disableGadgets == "" {
		return disabled
	}
	for _, name := range strings.Split(disableGadgets, ",") {
		if n := strings.TrimSpace(name); n != "" {
			disabled[n] = true
		}
	}
	return disabled
}

// buildNamespaceFilter constructs the k8s-namespace filter value.
// It always excludes the "micromize" namespace and appends any user-specified
// namespace filters. When filterNamespaces is empty, only "!micromize" is used.
func buildNamespaceFilter(filterNamespaces string) string {
	const excludeMicromize = "!micromize"
	normalizedFilter := excludeMicromize

	if filterNamespaces == "" {
		return normalizedFilter
	}

	parts := strings.Split(filterNamespaces, ",")
	for _, p := range parts {
		nsPart := strings.TrimSpace(p)
		if nsPart != excludeMicromize {
			normalizedFilter += "," + nsPart
		}
	}

	return normalizedFilter
}
