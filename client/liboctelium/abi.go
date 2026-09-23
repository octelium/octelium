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
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const abiVersion = 1

const maxBufferLen = 16 << 20

type handles[T any] struct {
	mu     sync.Mutex
	nextID uint64
	m      map[uint64]T
}

func newHandles[T any]() *handles[T] {
	return &handles[T]{
		m: make(map[uint64]T),
	}
}

func (h *handles[T]) add(v T) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.nextID++
	h.m[h.nextID] = v

	return h.nextID
}

func (h *handles[T]) get(id uint64) (T, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ret, ok := h.m[id]
	return ret, ok
}

func (h *handles[T]) delete(id uint64) (T, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ret, ok := h.m[id]
	delete(h.m, id)

	return ret, ok
}

func getResult(resp []byte, err error) (int32, []byte) {
	if err == nil {
		return int32(codes.OK), resp
	}

	st, ok := status.FromError(err)
	if !ok {
		return int32(codes.Unknown), []byte(err.Error())
	}

	if st.Code() == codes.OK {
		return int32(codes.Unknown), []byte(st.Message())
	}

	return int32(st.Code()), []byte(st.Message())
}

func getPanicErr(r any) error {
	return status.Errorf(codes.Internal, "liboctelium panic: %v", r)
}

func checkBufferLen(n uint64) error {
	if n > maxBufferLen {
		return status.Errorf(codes.InvalidArgument, "The buffer is too large: %d", n)
	}

	return nil
}
