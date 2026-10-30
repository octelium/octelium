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

package otelutils

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
)

func TestConvertValue(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value any
		want  attribute.Value
	}{
		{true, attribute.BoolValue(true)}, {"value", attribute.StringValue("value")},
		{int(1), attribute.Int64Value(1)}, {int8(-1), attribute.Int64Value(-1)},
		{int16(2), attribute.Int64Value(2)}, {int32(3), attribute.Int64Value(3)}, {int64(4), attribute.Int64Value(4)},
		{uint(1), attribute.Int64Value(1)}, {uint8(2), attribute.Int64Value(2)},
		{uint16(3), attribute.Int64Value(3)}, {uint32(4), attribute.Int64Value(4)},
		{uint64(math.MaxInt64), attribute.Int64Value(math.MaxInt64)},
		{uint64(math.MaxUint64), attribute.StringValue("18446744073709551615")},
		{uintptr(5), attribute.Int64Value(5)}, {float32(1.5), attribute.Float64Value(1.5)},
		{float64(2.5), attribute.Float64Value(2.5)}, {time.Second, attribute.Int64Value(int64(time.Second))},
		{now, attribute.Int64Value(now.UnixNano())}, {[]byte{1, 2}, attribute.ByteSliceValue([]byte{1, 2})},
		{fmt.Errorf("failed"), attribute.StringValue("failed")}, {nil, attribute.Value{}},
		{(*int)(nil), attribute.Value{}}, {[]int{1, 2}, attribute.SliceValue(attribute.Int64Value(1), attribute.Int64Value(2))},
		{[2]bool{true, false}, attribute.SliceValue(attribute.BoolValue(true), attribute.BoolValue(false))},
		{map[string]any{"value": true}, attribute.MapValue(attribute.Bool("value", true))},
		{map[int]string{1: "value"}, attribute.MapValue(attribute.String("1", "value"))},
		{struct{ Name string }{Name: "value"}, attribute.StringValue("{Name:value}")},
		{complex64(1 + 2i), attribute.MapValue(attribute.Float64("r", 1), attribute.Float64("i", 2))},
		{complex128(3 + 4i), attribute.MapValue(attribute.Float64("r", 3), attribute.Float64("i", 4))},
	} {
		assert.Equal(t, tc.want, convertValue(tc.value), "%T", tc.value)
	}
	value := "value"
	assert.Equal(t, attribute.StringValue(value), convertValue(&value))
	assert.Contains(t, convertValue(make(chan int)).AsString(), "unhandled:")
}
