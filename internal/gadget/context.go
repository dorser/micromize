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

package gadget

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/sirupsen/logrus"
	orasoci "oras.land/oras-go/v2/content/oci"
)

// ContextManager handles the creation and management of gadget contexts
type ContextManager struct {
	operators []operators.DataOperator
}

// NewContextManager creates a new ContextManager with the given operators
func NewContextManager(operators []operators.DataOperator) *ContextManager {
	return &ContextManager{
		operators: operators,
	}
}

// CreateContext creates a new gadget context with the given configuration
func (cm *ContextManager) CreateContext(ctx context.Context, gadgetBytes []byte, gadgetImage string) (*gadgetcontext.GadgetContext, error) {
	slog.Debug("Creating gadget context", "image", gadgetImage)
	// Create OCI target from gadget bytes
	reader := bytes.NewReader(gadgetBytes)
	fs, err := tarfs.New(reader)
	if err != nil {
		return nil, fmt.Errorf("creating tarfs: %w", err)
	}

	target, err := orasoci.NewFromFS(ctx, fs)
	if err != nil {
		return nil, fmt.Errorf("getting oci store from bytes: %w", err)
	}

	// Create gadget context with operators
	gadgetCtx := gadgetcontext.New(
		ctx,
		gadgetImage,
		gadgetcontext.WithDataOperators(cm.operators...),
		gadgetcontext.WithOrasReadonlyTarget(target),
		gadgetcontext.WithLogger(logrus.StandardLogger()),
	)

	return gadgetCtx, nil
}
