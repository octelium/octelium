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

/*
#include <stdint.h>
#include <stdlib.h>

typedef void (*octelium_event_fn)(void *ctx, const uint8_t *data, size_t data_len);

typedef void (*octelium_request_fn)(void *ctx, uint64_t request_id,
	const uint8_t *data, size_t data_len);

typedef struct {
	void *ctx;
	octelium_event_fn on_event;
	octelium_request_fn on_request;
} octelium_callbacks_t;

static inline void octelium_invoke_on_event(const octelium_callbacks_t *cb,
	const uint8_t *data, size_t data_len) {
	cb->on_event(cb->ctx, data, data_len);
}

static inline void octelium_invoke_on_request(const octelium_callbacks_t *cb,
	uint64_t request_id, const uint8_t *data, size_t data_len) {
	cb->on_request(cb->ctx, request_id, data, data_len);
}
*/
import "C"

import (
	"context"
	"sync"
	"unsafe"

	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/client/liboctelium/liboctelium"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type instance struct {
	c *liboctelium.Client

	mu       sync.RWMutex
	cb       *C.octelium_callbacks_t
	isClosed bool
}

var instances = newHandles[*instance]()

func (i *instance) SendEvent(ev *mobilev1.Event) {
	data, err := pbutils.Marshal(ev)
	if err != nil {
		return
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.isClosed {
		return
	}

	C.octelium_invoke_on_event(i.cb, getCBytes(data), C.size_t(len(data)))
}

func (i *instance) SendPlatformRequest(id uint64, req *mobilev1.PlatformRequest) {
	data, err := pbutils.Marshal(req)
	if err != nil {
		return
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.isClosed {
		return
	}

	C.octelium_invoke_on_request(i.cb, C.uint64_t(id), getCBytes(data), C.size_t(len(data)))
}

func (i *instance) close() {
	i.c.Close()

	i.mu.Lock()
	defer i.mu.Unlock()

	i.isClosed = true
	C.free(unsafe.Pointer(i.cb))
	i.cb = nil
}

func getCBytes(data []byte) *C.uint8_t {
	if len(data) == 0 {
		return nil
	}

	return (*C.uint8_t)(unsafe.Pointer(&data[0]))
}

func getGoBytes(data *C.uint8_t, dataLen C.size_t) ([]byte, error) {
	if err := checkBufferLen(uint64(dataLen)); err != nil {
		return nil, err
	}

	if data == nil || dataLen == 0 {
		return nil, nil
	}

	return C.GoBytes(unsafe.Pointer(data), C.int(dataLen)), nil
}

func setResult(out **C.uint8_t, outLen *C.size_t, resp []byte, err error) C.int32_t {
	code, data := getResult(resp, err)

	if out != nil && outLen != nil {
		if len(data) == 0 {
			*out = nil
			*outLen = 0
		} else {
			*out = (*C.uint8_t)(C.CBytes(data))
			*outLen = C.size_t(len(data))
		}
	}

	return C.int32_t(code)
}

//export octelium_abi_version
func octelium_abi_version() C.uint32_t {
	return abiVersion
}

//export octelium_client_new
func octelium_client_new(config *C.uint8_t, configLen C.size_t,
	callbacks *C.octelium_callbacks_t, client *C.uint64_t,
	out **C.uint8_t, outLen *C.size_t) (ret C.int32_t) {
	defer func() {
		if r := recover(); r != nil {
			ret = setResult(out, outLen, nil, getPanicErr(r))
		}
	}()

	if client == nil || callbacks == nil || callbacks.on_event == nil || callbacks.on_request == nil {
		return setResult(out, outLen, nil,
			status.Error(codes.InvalidArgument, "The client and the callbacks must be set"))
	}

	cfgBytes, err := getGoBytes(config, configLen)
	if err != nil {
		return setResult(out, outLen, nil, err)
	}

	cfg := &mobilev1.Config{}
	if err := pbutils.Unmarshal(cfgBytes, cfg); err != nil {
		return setResult(out, outLen, nil,
			status.Errorf(codes.InvalidArgument, "Could not unmarshal the config: %s", err))
	}

	inst := &instance{
		cb: (*C.octelium_callbacks_t)(C.malloc(C.size_t(unsafe.Sizeof(C.octelium_callbacks_t{})))),
	}
	*inst.cb = *callbacks

	inst.c, err = liboctelium.New(cfg, inst)
	if err != nil {
		C.free(unsafe.Pointer(inst.cb))
		return setResult(out, outLen, nil, err)
	}

	*client = C.uint64_t(instances.add(inst))

	return setResult(out, outLen, nil, nil)
}

//export octelium_client_call
func octelium_client_call(client C.uint64_t, method *C.char,
	req *C.uint8_t, reqLen C.size_t,
	out **C.uint8_t, outLen *C.size_t) (ret C.int32_t) {
	defer func() {
		if r := recover(); r != nil {
			ret = setResult(out, outLen, nil, getPanicErr(r))
		}
	}()

	inst, ok := instances.get(uint64(client))
	if !ok {
		return setResult(out, outLen, nil, status.Error(codes.NotFound, "Unknown client"))
	}

	if method == nil {
		return setResult(out, outLen, nil, status.Error(codes.InvalidArgument, "The method is not set"))
	}

	reqBytes, err := getGoBytes(req, reqLen)
	if err != nil {
		return setResult(out, outLen, nil, err)
	}

	resp, err := inst.c.Call(context.Background(), C.GoString(method), reqBytes)

	return setResult(out, outLen, resp, err)
}

//export octelium_client_complete_request
func octelium_client_complete_request(client C.uint64_t, requestID C.uint64_t,
	resp *C.uint8_t, respLen C.size_t) (ret C.int32_t) {
	defer func() {
		if r := recover(); r != nil {
			ret = C.int32_t(codes.Internal)
		}
	}()

	inst, ok := instances.get(uint64(client))
	if !ok {
		return C.int32_t(codes.NotFound)
	}

	respBytes, err := getGoBytes(resp, respLen)
	if err != nil {
		code, _ := getResult(nil, err)
		return C.int32_t(code)
	}

	code, _ := getResult(nil, inst.c.CompleteRequest(uint64(requestID), respBytes))

	return C.int32_t(code)
}

//export octelium_client_free
func octelium_client_free(client C.uint64_t) {
	defer func() {
		recover()
	}()

	inst, ok := instances.delete(uint64(client))
	if !ok {
		return
	}

	inst.close()
}

//export octelium_free
func octelium_free(ptr unsafe.Pointer) {
	C.free(ptr)
}
