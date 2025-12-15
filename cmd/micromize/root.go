package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/micromize-dev/micromize/internal/gadget"
	"github.com/micromize-dev/micromize/internal/operators"
	"github.com/micromize-dev/micromize/internal/runtime"
	"github.com/micromize-dev/micromize/internal/utils"
	"github.com/spf13/cobra"
)

const (
	fsRestrictGadgetImageRepo     = "ghcr.io/micromize-dev/micromize/fs-restrict"
	capRestrictGadgetImageRepo    = "ghcr.io/micromize-dev/micromize/cap-restrict"
	ptraceRestrictGadgetImageRepo = "ghcr.io/micromize-dev/micromize/ptrace-restrict"
)

var (
	enforce bool
)

var rootCmd = &cobra.Command{
	Use:   "micromize",
	Short: "micromize is a security hardening tool for containerized applications",
	Long:  `micromize is a security hardening tool designed to detect and break the post-exploit kill chain for containerized applications using BPF LSM.`,
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
	rootCmd.PersistentFlags().BoolVar(&enforce, "enforce", true, "Enforce restrictions")
}

func run(ctx context.Context) error {
	fmt.Println("Starting micromize...")
	if enforce {
		fmt.Println("Enforcement enabled")
	} else {
		fmt.Println("Enforcement disabled (audit mode)")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("Received shutdown signal")
		cancel()
	}()

	runtimeManager, err := runtime.NewManager()
	if err != nil {
		return fmt.Errorf("initializing runtime manager: %w", err)
	}

	defer runtimeManager.Close()

	ociHandlerOp := operators.NewOCIHandler()
	cliOp := operators.NewCLIOperator()

	localManagerOp, err := operators.NewLocalManager()
	if err != nil {
		return fmt.Errorf("creating local manager operator: %w", err)
	}

	contextManager := gadget.NewContextManager([]operators.DataOperator{ociHandlerOp, localManagerOp, cliOp})

	// Create gadget registry
	registry := gadget.NewRegistry(contextManager, runtimeManager)

	commonParams := map[string]string{
		"operator.cli.output":       "json",
		"operator.oci.ebpf.enforce": fmt.Sprintf("%d", utils.BoolToInt(enforce)),
	}

	registry.Register("fs-restrict", &gadget.GadgetConfig{
		Bytes:     fsRestrictGadgetBytes,
		ImageName: fmt.Sprintf("%s:%s", fsRestrictGadgetImageRepo, Version),
		Params:    commonParams,
	})

	registry.Register("cap-restrict", &gadget.GadgetConfig{
		Bytes:     capRestrictGadgetBytes,
		ImageName: fmt.Sprintf("%s:%s", capRestrictGadgetImageRepo, Version),
		Params:    commonParams,
	})

	registry.Register("ptrace-restrict", &gadget.GadgetConfig{
		Bytes:     ptraceRestrictGadgetBytes,
		ImageName: fmt.Sprintf("%s:%s", ptraceRestrictGadgetImageRepo, Version),
		Params:    commonParams,
	})

	// Run all gadgets
	if err := registry.RunAll(ctx); err != nil {
		return fmt.Errorf("running gadgets: %w", err)
	}

	// Wait for context to be done (which happens on signal)
	<-ctx.Done()
	return nil
}
