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

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/interpreter/functions"
	"cel.dev/cel-go/parser"
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
	options := []cel.EnvOption{
		cel.Macros(
			cel.ReceiverMacro("hasAny", 1, methodListMembershipMacro(false)),
			cel.ReceiverMacro("hasAll", 1, methodListMembershipMacro(true)),
		),
		cel.Function("@octelium_list_match",
			cel.Overload("octelium_list_match", []*cel.Type{cel.BoolType}, cel.BoolType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					return types.Bool(value == types.True)
				}),
				cel.OverloadIsNonStrict(),
			),
		),
	}

	for _, typ := range comparableTypes {
		options = append(options, cel.Function("@octelium_list_args",
			cel.Overload(fmt.Sprintf("octelium_list_args_%s", typ.typeName),
				[]*cel.Type{cel.ListType(typ.celType), cel.ListType(typ.celType)},
				cel.ListType(cel.ListType(typ.celType)),
				cel.BinaryBinding(methodListMembershipArgs),
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

func methodListMembershipMacro(all bool) cel.MacroFactory {
	return func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
		lists := fmt.Sprintf("@octelium_lists_%d", target.ID())
		item := fmt.Sprintf("@octelium_item_%d", target.ID())
		arg := fmt.Sprintf("@octelium_arg_%d", target.ID())
		listAt := func(index types.Int) ast.Expr {
			return eh.NewCall(operators.Index, eh.NewIdent(lists), eh.NewLiteral(index))
		}
		match := eh.NewCall("@octelium_list_match",
			eh.NewCall(operators.Equals, eh.NewIdent(item), eh.NewIdent(arg)))
		contains, err := parser.MakeExists(eh, listAt(0), []ast.Expr{eh.NewIdent(item), match})
		if err != nil {
			return nil, err
		}
		fold := parser.MakeExists
		if all {
			fold = parser.MakeAll
		}
		result, err := fold(eh, listAt(1), []ast.Expr{eh.NewIdent(arg), contains})
		if err != nil {
			return nil, err
		}
		return eh.NewComprehension(eh.NewList(), "@unused", lists,
			eh.NewCall("@octelium_list_args", target, args[0]),
			eh.NewLiteral(types.False), eh.NewIdent(lists), result), nil
	}
}

func methodListMembershipArgs(listVal ref.Val, listArgVal ref.Val) ref.Val {
	list, ok := listVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(listVal)
	}
	listArg, ok := listArgVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(listArgVal)
	}
	return types.NewRefValList(types.DefaultTypeAdapter, []ref.Val{list, listArg})
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
