package gadget

import (
	"context"
	"fmt"
	"log/slog"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

// RuntimeManager defines the interface for running gadgets
type RuntimeManager interface {
	RunGadget(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error
}

// GadgetContextCreator defines the interface for creating gadget contexts
type GadgetContextCreator interface {
	CreateContext(ctx context.Context, gadgetBytes []byte, gadgetImage string) (*gadgetcontext.GadgetContext, error)
}

// GadgetConfig holds the configuration for a single gadget
type GadgetConfig struct {
	Bytes     []byte
	ImageName string
	Params    map[string]string
	Context   GadgetContextCreator // Optional context manager override
}

// Registry manages multiple gadgets and their execution
type Registry struct {
	defaultContextManager GadgetContextCreator
	runtimeManager        RuntimeManager
	gadgets               map[string]*GadgetConfig
}

// NewRegistry creates a new gadget registry
func NewRegistry(defaultContextManager GadgetContextCreator, runtimeManager RuntimeManager) *Registry {
	return &Registry{
		defaultContextManager: defaultContextManager,
		runtimeManager:        runtimeManager,
		gadgets:               make(map[string]*GadgetConfig),
	}
}

// Register adds a new gadget to the registry
func (r *Registry) Register(name string, config *GadgetConfig) {
	r.gadgets[name] = config
}

// RunAll starts all registered gadgets
func (r *Registry) RunAll(ctx context.Context) error {
	for name, config := range r.gadgets {
		contextManager := r.defaultContextManager
		if config.Context != nil {
			contextManager = config.Context
		}

		gadgetCtx, err := contextManager.CreateContext(ctx, config.Bytes, config.ImageName)
		if err != nil {
			return fmt.Errorf("creating context for gadget %s: %w", name, err)
		}

		go func(name string, config *GadgetConfig, gadgetCtx *gadgetcontext.GadgetContext) {
			if err := r.runtimeManager.RunGadget(gadgetCtx, config.Params); err != nil {
				slog.Error("Error running gadget", "name", name, "error", err)
			}
		}(name, config, gadgetCtx)
	}
	return nil
}
