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

package operators

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"

	"github.com/micromize-dev/micromize/internal/sbom"
)

// DataOperator is an alias for igoperators.DataOperator to avoid direct dependency in main
type DataOperator = igoperators.DataOperator

func NewLocalManager() (igoperators.DataOperator, error) {
	slog.Debug("Initializing local manager operator")
	host.Init(host.Config{})
	localManagerOp := localmanager.LocalManagerOperator
	localManagerParams := localManagerOp.GlobalParamDescs().ToParams()

	if err := localManagerOp.Init(localManagerParams); err != nil {
		return nil, fmt.Errorf("init local manager: %w", err)
	}
	return localManagerOp, nil
}

// NewOCIHandler creates and returns the OCI handler operator
func NewOCIHandler() igoperators.DataOperator {
	slog.Debug("Creating OCI handler operator")
	return ocihandler.OciHandler
}

// NewCLIOperator creates and returns the CLI operator
func NewCLIOperator() igoperators.DataOperator {
	slog.Debug("Creating CLI operator")
	return clioperator.CLIOperator
}

// NewImaOperator creates and returns the IMA operator
func NewImaOperator() igoperators.DataOperator {
	slog.Debug("Creating IMA operator")
	opPriority := math.MaxInt
	sbomFetcher := sbom.NewFetcher()

	operatorOptions := []simple.Option{
		simple.WithPriority(opPriority),
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			ctx := gadgetCtx.Context()
			containersDatasource := gadgetCtx.GetDataSources()["containers"]
			if containersDatasource == nil {
				slog.Debug("IMA Operator: containers datasource not available, skipping")
				return nil
			}

			eventTypeField := containersDatasource.GetField("event_type")
			if eventTypeField == nil {
				return fmt.Errorf("containers datasource missing event_type field")
			}

			containerConfigField := containersDatasource.GetField("container_config")
			if containerConfigField == nil {
				return fmt.Errorf("containers datasource missing container_config field")
			}

			containerIDField := containersDatasource.GetField("container_id")
			if containerIDField == nil {
				slog.Debug("containers datasource missing container_id field, Docker config fallback will be unavailable")
			}

			if err := containersDatasource.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				eventType, err := eventTypeField.String(data)
				if err != nil {
					return fmt.Errorf("getting event_type value: %w", err)
				}
				if eventType == "CREATED" {
					handleContainerCreated(ctx, sbomFetcher, containerConfigField, containerIDField, data)
				}
				return nil
			}, opPriority); err != nil {
				return fmt.Errorf("subscribing to containers datasource: %w", err)
			}
			return nil
		}),
	}
	return simple.New("imaOperator", operatorOptions...)
}

func handleContainerCreated(ctx context.Context, fetcher *sbom.Fetcher, configField datasource.FieldAccessor, containerIDField datasource.FieldAccessor, data datasource.Data) {
	ociConfig, err := configField.String(data)
	if err != nil {
		slog.Debug("Failed to read container_config field", "error", err)
		return
	}

	imageRef, err := sbom.ImageRefFromOCIConfig(ociConfig)
	if err != nil {
		slog.Debug("Failed to parse OCI config", "error", err)
		return
	}

	// Fallback: read image ref from Docker's config.v2.json when
	// OCI annotations don't contain the image name (plain Docker).
	if imageRef == "" && containerIDField != nil {
		containerID, _ := containerIDField.String(data)
		imageRef = sbom.ImageRefFromDockerConfig(containerID)
	}

	imageRef = sbom.NormalizeImageRef(imageRef)

	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	sbomData, err := fetcher.FetchForImage(fetchCtx, imageRef)
	if err != nil {
		slog.Error("Failed to fetch SBOM", "error", err)
		return
	}
	if sbomData != nil {
		slog.Info("SBOM fetched for container image", "image", imageRef, "size", len(sbomData))

		files, err := sbom.ParseFiles(sbomData)
		if err != nil {
			slog.Error("Failed to parse SBOM files", "error", err)
			return
		}
		for _, f := range files {
			slog.Info("SBOM binary file", "image", imageRef, "file", f.FileName, "sha256", f.SHA256)
		}
	}
}
