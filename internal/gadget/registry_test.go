package gadget

import (
	"context"
	"testing"
	"time"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

type mockRuntimeManager struct {
	runGadgetFunc func(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error
}

func (m *mockRuntimeManager) RunGadget(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
	if m.runGadgetFunc != nil {
		return m.runGadgetFunc(gadgetCtx, params)
	}
	return nil
}

type mockContextCreator struct {
	createContextFunc func(ctx context.Context, gadgetBytes []byte, gadgetImage string) (*gadgetcontext.GadgetContext, error)
}

func (m *mockContextCreator) CreateContext(ctx context.Context, gadgetBytes []byte, gadgetImage string) (*gadgetcontext.GadgetContext, error) {
	if m.createContextFunc != nil {
		return m.createContextFunc(ctx, gadgetBytes, gadgetImage)
	}
	return gadgetcontext.New(ctx, gadgetImage), nil
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry(&mockContextCreator{}, &mockRuntimeManager{})
	config := &GadgetConfig{
		ImageName: "test-image",
	}
	r.Register("test", config)

	if len(r.gadgets) != 1 {
		t.Errorf("expected 1 gadget, got %d", len(r.gadgets))
	}
	if r.gadgets["test"] != config {
		t.Errorf("expected config %v, got %v", config, r.gadgets["test"])
	}
}

func TestRegistry_RunAll(t *testing.T) {
	done := make(chan struct{})
	mockRuntime := &mockRuntimeManager{
		runGadgetFunc: func(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
			close(done)
			return nil
		},
	}

	mockContext := &mockContextCreator{}
	r := NewRegistry(mockContext, mockRuntime)

	r.Register("test", &GadgetConfig{
		ImageName: "test-image",
		Params:    map[string]string{"foo": "bar"},
	})

	if err := r.RunAll(context.Background()); err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for RunGadget")
	}
}
