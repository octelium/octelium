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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/pkg/common/clientlogin"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

const testHarness = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "liboctelium.h"

static volatile int status_events = 0;
static volatile int requests = 0;

static void on_event(void *ctx, const uint8_t *data, size_t data_len) {
	if (ctx == (void *)0x1 && data != NULL && data_len > 0) {
		__atomic_add_fetch(&status_events, 1, __ATOMIC_SEQ_CST);
	}
}

static void on_request(void *ctx, uint64_t request_id, const uint8_t *data, size_t data_len) {
	__atomic_add_fetch(&requests, 1, __ATOMIC_SEQ_CST);
}

static uint8_t *read_file(const char *path, size_t *len) {
	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	*len = (size_t)ftell(f);
	fseek(f, 0, SEEK_SET);
	uint8_t *ret = malloc(*len + 1);
	if (fread(ret, 1, *len, f) != *len) {
		fclose(f);
		free(ret);
		return NULL;
	}
	fclose(f);
	return ret;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
	FILE *f = fopen(path, "wb");
	if (f == NULL) {
		return -1;
	}
	fwrite(data, 1, len, f);
	fclose(f);
	return 0;
}

int main(int argc, char **argv) {
	size_t cfg_len = 0, req_len = 0;
	uint8_t *cfg = read_file(argv[1], &cfg_len);
	uint8_t *req = read_file(argv[2], &req_len);
	if (cfg == NULL || req == NULL) {
		return 2;
	}

	if (octelium_abi_version() != 1) {
		return 3;
	}

	octelium_callbacks_t cb = {
		.ctx = (void *)0x1,
		.on_event = on_event,
		.on_request = on_request,
	};

	uint64_t client = 0;
	uint8_t *out = NULL;
	size_t out_len = 0;

	if (octelium_client_new(cfg, cfg_len, NULL, &client, &out, &out_len) != 3 || out == NULL) {
		return 4;
	}
	octelium_free(out);

	if (octelium_client_new((const uint8_t *)"\xff\xff", 2, &cb, &client, &out, &out_len) != 3) {
		return 5;
	}
	octelium_free(out);

	if (octelium_client_new(cfg, cfg_len, &cb, &client, &out, &out_len) != 0 || client == 0) {
		fprintf(stderr, "%.*s\n", (int)out_len, out);
		return 6;
	}

	if (octelium_client_call(client, "GetInfo", NULL, 0, &out, &out_len) != 0) {
		return 7;
	}
	if (write_file(argv[3], out, out_len) != 0) {
		return 8;
	}
	octelium_free(out);

	if (octelium_client_call(client, "Unknown", NULL, 0, &out, &out_len) != 12 || out_len == 0) {
		return 9;
	}
	octelium_free(out);

	if (octelium_client_call(client + 100, "GetInfo", NULL, 0, &out, &out_len) != 5) {
		return 10;
	}
	octelium_free(out);

	if (octelium_client_call(client, NULL, NULL, 0, &out, &out_len) != 3) {
		return 11;
	}
	octelium_free(out);

	if (octelium_client_complete_request(client, 12345, NULL, 0) != 5) {
		return 12;
	}

	if (octelium_client_complete_request(client + 100, 1, NULL, 0) != 5) {
		return 13;
	}

	if (octelium_client_call(client, "UpdateDomainSettings", req, req_len, &out, &out_len) != 0) {
		fprintf(stderr, "%.*s\n", (int)out_len, out);
		return 14;
	}
	octelium_free(out);

	for (int i = 0; i < 500 && __atomic_load_n(&status_events, __ATOMIC_SEQ_CST) == 0; i++) {
		usleep(10000);
	}
	if (__atomic_load_n(&status_events, __ATOMIC_SEQ_CST) == 0) {
		return 15;
	}

	octelium_client_free(client);
	octelium_client_free(client);

	if (octelium_client_call(client, "GetInfo", NULL, 0, &out, &out_len) != 5) {
		return 16;
	}
	octelium_free(out);

	if (__atomic_load_n(&requests, __ATOMIC_SEQ_CST) != 0) {
		return 17;
	}

	free(cfg);
	free(req);

	return 0;
}
`

func TestCABI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping building the shared library in the short mode")
	}

	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("No C compiler found")
	}

	dir := t.TempDir()

	getEnv := func() []string {
		var ret []string
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "OCTELIUM_") {
				ret = append(ret, kv)
			}
		}
		return ret
	}

	{
		cmd := exec.Command("go", "build", "-buildmode=c-shared",
			"-o", filepath.Join(dir, "liboctelium.so"), ".")
		cmd.Env = append(getEnv(), "CGO_ENABLED=1")
		out, err := cmd.CombinedOutput()
		assert.Nil(t, err, "%s", out)
	}

	{
		header, err := os.ReadFile(filepath.Join(dir, "liboctelium.h"))
		assert.Nil(t, err)
		for _, fn := range []string{
			"octelium_abi_version",
			"octelium_client_new",
			"octelium_client_call",
			"octelium_client_complete_request",
			"octelium_client_free",
			"octelium_free",
			"octelium_callbacks_t",
		} {
			assert.Contains(t, string(header), fn)
		}
	}

	{
		assert.Nil(t, os.WriteFile(filepath.Join(dir, "harness.c"), []byte(testHarness), 0600))

		cmd := exec.Command(cc, "-o", filepath.Join(dir, "harness"),
			filepath.Join(dir, "harness.c"),
			"-I", dir, "-L", dir, "-loctelium",
			"-Wl,-rpath,"+dir, "-lpthread")
		out, err := cmd.CombinedOutput()
		assert.Nil(t, err, "%s", out)
	}

	cfgPath := filepath.Join(dir, "config.bin")
	assert.Nil(t, os.WriteFile(cfgPath, pbutils.MarshalMust(&mobilev1.Config{
		Platform: mobilev1.Config_ANDROID,
		StateDir: filepath.Join(dir, "state"),
		StateKey: utilrand.GetRandomBytesMust(32),
	}), 0600))

	reqPath := filepath.Join(dir, "req.bin")
	assert.Nil(t, os.WriteFile(reqPath, pbutils.MarshalMust(&daemonv1.UpdateDomainSettingsRequest{
		Domain:   "example.com",
		Settings: &daemonv1.DomainSettings{},
	}), 0600))

	infoPath := filepath.Join(dir, "info.bin")

	{
		cmd := exec.Command(filepath.Join(dir, "harness"), cfgPath, reqPath, infoPath)
		cmd.Env = getEnv()
		out, err := cmd.CombinedOutput()
		assert.Nil(t, err, "%s", out)
	}

	infoBytes, err := os.ReadFile(infoPath)
	assert.Nil(t, err)

	info := &mobilev1.GetInfoResponse{}
	assert.Nil(t, pbutils.Unmarshal(infoBytes, info))
	assert.Equal(t, uint32(1), info.ApiMajorVersion)
	assert.NotEmpty(t, info.InstanceID)
	assert.Equal(t, clientlogin.AppCallbackURL, info.AuthenticationCallbackURL)
}
