// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package components

import (
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.uber.org/zap"
)

func InitComponent() error {

	if ldflags.IsDev() {
		logger, err := zap.NewDevelopment()
		if err != nil {
			return err
		}
		zap.ReplaceGlobals(logger)
	} else {
		logger, err := zap.NewProduction()
		if err != nil {
			return err
		}
		zap.ReplaceGlobals(logger)
	}

	zap.L().Debug("Labels",
		zap.String("gitCommit", ldflags.GitCommit),
		zap.String("gitBranch", ldflags.GitBranch),
		zap.String("gitTag", ldflags.GitTag),
		zap.Bool("productionMode", ldflags.IsProduction()),
		zap.Bool("devMode", ldflags.IsDev()),
	)

	return nil
}
