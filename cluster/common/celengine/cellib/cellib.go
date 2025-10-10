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
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

func CELLib() cel.EnvOption {
	return cel.Lib(&celLib{})
}

type celLib struct{}

func (*celLib) CompileOptions() []cel.EnvOption {
	var ret []cel.EnvOption

	ret = append(ret, functionNow())
	ret = append(ret, functionJSONFrom())

	ret = append(ret, MethodsList())
	ret = append(ret, Str())
	ret = append(ret, ext.Strings())
	ret = append(ret, ext.Encoders())
	ret = append(ret, ext.Math())
	ret = append(ret, ext.Bindings())

	return ret
}

func (*celLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
