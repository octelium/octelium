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
	"net"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/pkg/errors"
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

func funcJSON() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("json.parse",
			cel.Overload("json_parse",
				[]*cel.Type{
					cel.StringType,
				},
				cel.DynType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
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
				}),
			),
		),

		cel.Function("json.marshal",
			cel.Overload("json_marshal",
				[]*cel.Type{
					cel.DynType,
				},
				cel.StringType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					value := val.Value()
					out, err := json.Marshal(value)
					if err != nil {
						return types.NewErr("Could not marshal json")
					}
					return types.DefaultTypeAdapter.NativeToValue(string(out))
				}),
			),
		),
	}
}

func funcNet() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("net.isIP",
			cel.Overload("net_isIP_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(ipArg ref.Val) ref.Val {
					ipStr, ok := ipArg.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					return types.Bool(govalidator.IsIP(ipStr))
				}),
			),
		),
		cel.Function("net.isIPv4",
			cel.Overload("net_isIPv4_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(ipArg ref.Val) ref.Val {
					ipStr, ok := ipArg.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					return types.Bool(govalidator.IsIPv4(ipStr))
				}),
			),
		),

		cel.Function("net.isIPv6",
			cel.Overload("net_isIPv6_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(ipArg ref.Val) ref.Val {
					ipStr, ok := ipArg.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					return types.Bool(govalidator.IsIPv6(ipStr))
				}),
			),
		),
		cel.Function("net.isPrivateIP",
			cel.Overload("net_isPrivateIP_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(ipArg ref.Val) ref.Val {
					ipStr, ok := ipArg.Value().(string)
					if !ok {
						return types.NewErr("Could not get IP arg")
					}

					ip := net.ParseIP(ipStr)
					if ip == nil {
						return types.NewErr("Could not parse IP: %s", ipStr)
					}
					return types.Bool(ip.IsPrivate())
				}),
			),
		),
		cel.Function("net.isIPInRange",
			cel.Overload("net_isIPInRange_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(ipArg, cidrArg ref.Val) ref.Val {
					ipStr, ok := ipArg.Value().(string)
					if !ok {
						return types.NewErr("Could not get IP arg")
					}

					cidrStr, ok := cidrArg.Value().(string)
					if !ok {
						return types.NewErr("Could not get CIDR arg")
					}

					ip := net.ParseIP(ipStr)
					if ip == nil {
						return types.NewErr("Could not parse IP address: %s", ipStr)
					}

					_, subnet, err := net.ParseCIDR(cidrStr)
					if err != nil {
						return types.NewErr("Could not parse CIDR: %+v", err)
					}

					return types.Bool(subnet.Contains(ip))
				}),
			),
		),
	}
}

func funcTime() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("time.isWeekday",
			cel.Overload("time_isWeekday_ts",
				[]*cel.Type{cel.TimestampType}, cel.BoolType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					t, err := toTime(v)
					if err != nil {
						return errToVal(err)
					}
					wd := t.UTC().Weekday()
					return types.Bool(wd >= time.Monday && wd <= time.Friday)
				}),
			),
		),

		cel.Function("time.isWeekdayInTZ",
			cel.Overload("time_isWeekdayInTZ_ts_string",
				[]*cel.Type{cel.TimestampType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(tsVal, tzVal ref.Val) ref.Val {
					t, err := toTime(tsVal)
					if err != nil {
						return errToVal(err)
					}
					loc, err := getTZLocation(tzVal)
					if err != nil {
						return errToVal(err)
					}
					wd := t.In(loc).Weekday()
					return types.Bool(wd >= time.Monday && wd <= time.Friday)
				}),
			),
		),

		cel.Function("time.isWeekend",
			cel.Overload("time_isWeekend_ts",
				[]*cel.Type{cel.TimestampType}, cel.BoolType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					t, err := toTime(v)
					if err != nil {
						return errToVal(err)
					}
					wd := t.UTC().Weekday()
					return types.Bool(wd == time.Saturday || wd == time.Sunday)
				}),
			),
		),

		cel.Function("time.isWeekendInTZ",
			cel.Overload("time_isWeekendInTZ_ts_string",
				[]*cel.Type{cel.TimestampType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(tsVal, tzVal ref.Val) ref.Val {
					t, err := toTime(tsVal)
					if err != nil {
						return errToVal(err)
					}
					loc, err := getTZLocation(tzVal)
					if err != nil {
						return errToVal(err)
					}
					wd := t.In(loc).Weekday()
					return types.Bool(wd == time.Saturday || wd == time.Sunday)
				}),
			),
		),
	}

}

func getTZLocation(arg ref.Val) (*time.Location, error) {
	tz, ok := arg.Value().(string)
	if !ok {
		return nil, errors.Errorf("Could not get timezone")
	}

	if tz == "" || tz == "UTC" {
		return time.UTC, nil
	}

	return time.LoadLocation(tz)
}

func toTime(v ref.Val) (time.Time, error) {
	if ret, ok := v.(types.Timestamp); ok {
		return ret.Time, nil
	}

	return time.Time{}, errors.Errorf("Not a timestamp: %T", v)
}

func errToVal(err error) ref.Val {
	return types.NewErr("%+v", err)
}
