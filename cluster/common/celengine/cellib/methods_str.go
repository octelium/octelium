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
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func Str() cel.EnvOption {
	return cel.Lib(stringLib)
}

type strLib struct{}

var stringLib = &strLib{}

func (*strLib) CompileOptions() []cel.EnvOption {
	var options []cel.EnvOption

	/*
		options = append(options, cel.Function("matches",
			cel.MemberOverload("str_matches_str",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.StringType,
				cel.BinaryBinding(strMatches),
			),
		))
	*/

	options = append(options, cel.Function("toLower",
		cel.MemberOverload("str_toLower",
			[]*cel.Type{cel.StringType},
			cel.StringType,
			cel.UnaryBinding(strToLower),
		),
	))

	options = append(options, cel.Function("toUpper",
		cel.MemberOverload("str_toUpper",
			[]*cel.Type{cel.StringType},
			cel.StringType,
			cel.UnaryBinding(func(str ref.Val) ref.Val {
				return strToUpper(str)
			}),
		),
	))

	/*
		options = append(options, cel.Function("split",
			cel.MemberOverload("str_split",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.ListType(cel.StringType),
				cel.BinaryBinding(func(str, sep ref.Val) ref.Val {
					return strSplit(str, sep)
				}),
			),
		))
	*/

	return options
}

func (*strLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func strToLower(strVal ref.Val) ref.Val {
	str, ok := strVal.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(strVal)
	}

	return types.String(strings.ToLower(str))
}

func strToUpper(strVal ref.Val) ref.Val {
	str, ok := strVal.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(strVal)
	}

	return types.String(strings.ToUpper(str))
}

func strSplit(strVal, sepVal ref.Val) ref.Val {
	str, ok := strVal.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(strVal)
	}

	sep, ok := sepVal.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(sepVal)
	}

	return types.DefaultTypeAdapter.NativeToValue(strings.Split(str, sep))
}

func strMatches(strVal, sepVal ref.Val) ref.Val {
	str, ok := strVal.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(strVal)
	}

	pattern, ok := sepVal.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(sepVal)
	}

	ret, err := regexp.MatchString(pattern, str)
	if err != nil {
		return types.NewErr("Could not match string")
	}

	return types.DefaultTypeAdapter.NativeToValue(ret)
}
