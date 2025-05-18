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

package httputils

import (
	"strings"

	"github.com/pkg/errors"
)

type GRPCInfo struct {
	Service         string
	Package         string
	FullServiceName string
	Method          string
}

func GetGRPCInfo(path string) (*GRPCInfo, error) {

	ret := &GRPCInfo{}
	slashParts := strings.Split(path, "/")
	if len(slashParts) != 3 {
		return nil, errors.Errorf("Invalid gRPC path")
	}
	ret.FullServiceName = slashParts[1]
	ret.Method = slashParts[2]

	idx := strings.LastIndex(ret.FullServiceName, ".")
	if idx < 0 {
		return nil, errors.Errorf("Invalid full gRPC service name")
	}
	if idx >= len(ret.FullServiceName) {
		return nil, errors.Errorf("gRPC service name cannot end with a .")
	}

	ret.Package = ret.FullServiceName[:idx]
	ret.Service = ret.FullServiceName[idx+1:]

	return ret, nil
}
