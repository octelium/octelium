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
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter/functions"
)

type namedCELType struct {
	typeName string
	celType  *cel.Type
}

var summableTypes = []namedCELType{
	{typeName: "int", celType: cel.IntType},
	{typeName: "uint", celType: cel.UintType},
	{typeName: "double", celType: cel.DoubleType},
	{typeName: "duration", celType: cel.DurationType},
}

var zeroValuesOfSummableTypes = map[string]ref.Val{
	"int":      types.Int(0),
	"uint":     types.Uint(0),
	"double":   types.Double(0.0),
	"duration": types.Duration{Duration: 0},
}
var comparableTypes = []namedCELType{
	{typeName: "int", celType: cel.IntType},
	{typeName: "uint", celType: cel.UintType},
	{typeName: "double", celType: cel.DoubleType},
	{typeName: "bool", celType: cel.BoolType},
	{typeName: "duration", celType: cel.DurationType},
	{typeName: "timestamp", celType: cel.TimestampType},
	{typeName: "string", celType: cel.StringType},
	{typeName: "bytes", celType: cel.BytesType},
}

func MethodsList() cel.EnvOption {
	return cel.Lib(listLib)
}

type lstLib struct{}

var listLib = &lstLib{}

func (*lstLib) CompileOptions() []cel.EnvOption {
	var options []cel.EnvOption

	for _, typ := range comparableTypes {
		options = append(options, cel.Function("hasAny",
			cel.MemberOverload(fmt.Sprintf("lst_hasAny_%s", typ.typeName),
				[]*cel.Type{cel.ListType(typ.celType), cel.ListType(typ.celType)},
				cel.BoolType,
				cel.BinaryBinding(methodListHasAny),
			),
		))
	}

	for _, typ := range comparableTypes {
		options = append(options, cel.Function("hasAll",
			cel.MemberOverload(fmt.Sprintf("lst_hasAll_%s", typ.typeName),
				[]*cel.Type{cel.ListType(typ.celType), cel.ListType(typ.celType)},
				cel.BoolType,
				cel.BinaryBinding(methodListHasAll),
			),
		))
	}

	for _, typ := range comparableTypes {
		options = append(options, cel.Function("min",
			cel.MemberOverload(fmt.Sprintf("lst_min_%s", typ.typeName),
				[]*cel.Type{cel.ListType(typ.celType)},
				typ.celType,
				cel.UnaryBinding(methodListMin()),
			),
		))
	}

	for _, typ := range comparableTypes {
		options = append(options, cel.Function("max",
			cel.MemberOverload(fmt.Sprintf("lst_max_%s", typ.typeName),
				[]*cel.Type{cel.ListType(typ.celType)},
				typ.celType,
				cel.UnaryBinding(methodListMax()),
			),
		))
	}

	return options
}

func (*lstLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func methodListMin() functions.UnaryOp {
	return methodListCmp("min", types.IntOne)
}

func methodListMax() functions.UnaryOp {
	return methodListCmp("max", types.IntNegOne)
}

func methodListCmp(opName string, opPreferCmpResult ref.Val) functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		var result traits.Comparer
		iterable, ok := val.(traits.Iterable)
		if !ok {
			return types.MaybeNoSuchOverloadErr(val)
		}
		for it := iterable.Iterator(); it.HasNext() == types.True; {
			next := it.Next()
			nextCmp, ok := next.(traits.Comparer)
			if !ok {
				return types.MaybeNoSuchOverloadErr(next)
			}
			if result == nil {
				result = nextCmp
			} else {
				cmp := result.Compare(next)
				if cmp == opPreferCmpResult {
					result = nextCmp
				}
			}
		}
		if result == nil {
			return types.NewErr("%s called on empty list", opName)
		}
		return result.(ref.Val)
	}
}

func methodListHasAny(listVal ref.Val, listArgVal ref.Val) ref.Val {
	list, ok := listVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}
	listArg, ok := listArgVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}

	sz := listArg.Size().(types.Int)
	for i := types.Int(0); i < sz; i++ {
		if isInList(list, listArg.Get(types.Int(i))) {
			return types.Bool(true)
		}
	}
	return types.Bool(false)
}

func methodListHasAll(listVal ref.Val, listArgVal ref.Val) ref.Val {
	list, ok := listVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}
	listArg, ok := listArgVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}

	sz := listArg.Size().(types.Int)
	for i := types.Int(0); i < sz; i++ {
		if !isInList(list, listArg.Get(types.Int(i))) {
			return types.Bool(false)
		}
	}
	return types.Bool(true)
}

func isInList(list traits.Lister, item ref.Val) bool {

	sz := list.Size().(types.Int)
	for i := types.Int(0); i < sz; i++ {
		if list.Get(types.Int(i)).Equal(item) == types.True {
			return true
		}
	}
	return false
}
