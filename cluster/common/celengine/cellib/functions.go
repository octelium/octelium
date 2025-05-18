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

package cellib

import (
	"encoding/json"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func functionNow() cel.EnvOption {
	return cel.Function("now",
		cel.Overload("now",
			nil,
			cel.TimestampType,
			cel.FunctionBinding(func(values ...ref.Val) ref.Val {
				return types.DefaultTypeAdapter.NativeToValue(time.Now())
			}),
		),
	)
}

func functionJSONFrom() cel.EnvOption {
	return cel.Function("json.parse",
		cel.Overload("json_parse",
			[]*cel.Type{
				cel.StringType,
			},
			cel.DynType,
			cel.UnaryBinding(fnJSONFrom),
		),
	)
}

func fnJSONFrom(val ref.Val) ref.Val {
	value := val.Value()
	switch tVal := value.(type) {
	case string:
		out := make(map[string]any)
		if err := json.Unmarshal([]byte(tVal), &out); err != nil {
			return types.NewErr("Could not parse json")
		}
		return types.DefaultTypeAdapter.NativeToValue(out)
	case []byte:
		out := make(map[string]any)
		if err := json.Unmarshal(tVal, &out); err != nil {
			return types.NewErr("Could not parse json")
		}
		return types.DefaultTypeAdapter.NativeToValue(out)
	default:
		return types.NewErr("Invalid json_from arg")
	}
}
