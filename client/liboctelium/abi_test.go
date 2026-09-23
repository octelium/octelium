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

package main

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHandles(t *testing.T) {
	h := newHandles[string]()

	id1 := h.add("a")
	id2 := h.add("b")
	assert.NotEqual(t, uint64(0), id1)
	assert.NotEqual(t, id1, id2)

	{
		ret, ok := h.get(id1)
		assert.True(t, ok)
		assert.Equal(t, "a", ret)
	}

	{
		_, ok := h.get(0)
		assert.False(t, ok)

		_, ok = h.get(id2 + 1)
		assert.False(t, ok)
	}

	{
		ret, ok := h.delete(id1)
		assert.True(t, ok)
		assert.Equal(t, "a", ret)

		_, ok = h.get(id1)
		assert.False(t, ok)

		_, ok = h.delete(id1)
		assert.False(t, ok)
	}

	assert.NotEqual(t, id1, h.add("c"))
}

func TestGetResult(t *testing.T) {
	{
		code, data := getResult([]byte("resp"), nil)
		assert.Equal(t, int32(codes.OK), code)
		assert.Equal(t, []byte("resp"), data)
	}

	{
		code, data := getResult(nil, status.Error(codes.NotFound, "Unknown client"))
		assert.Equal(t, int32(codes.NotFound), code)
		assert.Equal(t, []byte("Unknown client"), data)
	}

	{
		code, data := getResult([]byte("resp"), errors.Errorf("some error"))
		assert.Equal(t, int32(codes.Unknown), code)
		assert.Equal(t, []byte("some error"), data)
	}

	{
		code, data := getResult(nil, getPanicErr("boom"))
		assert.Equal(t, int32(codes.Internal), code)
		assert.Contains(t, string(data), "boom")
	}
}

func TestCheckBufferLen(t *testing.T) {
	assert.Nil(t, checkBufferLen(0))
	assert.Nil(t, checkBufferLen(maxBufferLen))
	assert.NotNil(t, checkBufferLen(maxBufferLen+1))
	assert.NotNil(t, checkBufferLen(^uint64(0)))
}
