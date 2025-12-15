package runtime

import (
	"fmt"
	"log/slog"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// Manager handles runtime initialization and gadget execution
type Manager struct {
	runtime *local.Runtime
}

// NewManager creates a new runtime manager
func NewManager() (*Manager, error) {
	slog.Debug("Initializing runtime manager")
	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return nil, fmt.Errorf("runtime init: %w", err)
	}

	return &Manager{
		runtime: runtime,
	}, nil
}

// RunGadget runs a gadget with the given context and parameters
func (m *Manager) RunGadget(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
	slog.Debug("Running gadget", "image", gadgetCtx.ImageName())
	return m.runtime.RunGadget(gadgetCtx, nil, params)
}

// Close cleans up runtime resources
func (m *Manager) Close() {
	slog.Debug("Closing runtime manager")
	m.runtime.Close()
}
