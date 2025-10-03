/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package nodeinit

import (
	"context"
	"os/exec"

	"go.uber.org/zap"
)

func Run(ctx context.Context) error {

	modules := []string{
		"ip6table_filter",
		"wireguard",
	}

	for _, module := range modules {
		if err := exec.Command("modprobe", module).Run(); err != nil {
			zap.L().Warn("Could not modprobe", zap.String("module", module), zap.Error(err))
		}
	}

	return nil
}
