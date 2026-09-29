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

package deviceprobe

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestGetProbeLimit(t *testing.T) {
	assert.Equal(t, 1<<14, defaultMaxOutput)

	assert.Equal(t, defaultMaxOutput, getProbeLimit(&authv1.DeviceProbe{}))

	assert.Equal(t, defaultMaxOutput, getProbeLimit(&authv1.DeviceProbe{
		Type: &authv1.DeviceProbe_RunCommand_{
			RunCommand: &authv1.DeviceProbe_RunCommand{},
		},
	}))

	assert.Equal(t, 100, getProbeLimit(&authv1.DeviceProbe{
		Type: &authv1.DeviceProbe_RunCommand_{
			RunCommand: &authv1.DeviceProbe_RunCommand{
				MaxOutputBytes: 100,
			},
		},
	}))

	assert.Equal(t, maxOutputBytes, getProbeLimit(&authv1.DeviceProbe{
		Type: &authv1.DeviceProbe_ReadFile_{
			ReadFile: &authv1.DeviceProbe_ReadFile{
				MaxBytes: 1 << 20,
			},
		},
	}))

	assert.Equal(t, defaultMaxOutput, getProbeLimit(&authv1.DeviceProbe{
		Type: &authv1.DeviceProbe_ReadRegistry_{
			ReadRegistry: &authv1.DeviceProbe_ReadRegistry{},
		},
	}))
}

func TestIsResultWithinLimits(t *testing.T) {
	p := &authv1.DeviceProbe{
		ProbeID: "p1",
		Type: &authv1.DeviceProbe_PlatformIdentifier_{
			PlatformIdentifier: &authv1.DeviceProbe_PlatformIdentifier{
				Kind: authv1.DeviceProbe_PlatformIdentifier_MAC_ADDRESS,
			},
		},
	}

	getList := func(n, l int) *authv1.DeviceProbeResult {
		ret := &authv1.DeviceProbeResult{
			ProbeID: "p1",
			Status:  authv1.DeviceProbeResult_OK,
			Value: &authv1.DeviceProbeResult_List_{
				List: &authv1.DeviceProbeResult_List{},
			},
		}
		for range n {
			ret.GetList().Items = append(ret.GetList().Items, strings.Repeat("a", l))
		}
		return ret
	}

	assert.True(t, isResultWithinLimits(p, probeStatus("p1", authv1.DeviceProbeResult_NOT_FOUND, "")))
	assert.True(t, isResultWithinLimits(p, probeText("p1", strings.Repeat("a", defaultMaxOutput))))
	assert.False(t, isResultWithinLimits(p, probeText("p1", strings.Repeat("a", defaultMaxOutput+1))))
	assert.True(t, isResultWithinLimits(p, getList(maxListItems, 17)))
	assert.False(t, isResultWithinLimits(p, getList(maxListItems+1, 17)))
	assert.True(t, isResultWithinLimits(p, getList(1, maxListItemLen)))
	assert.False(t, isResultWithinLimits(p, getList(1, maxListItemLen+1)))
}

func TestRunProbesLimits(t *testing.T) {
	results := runProbes(context.Background(), []*authv1.DeviceProbe{
		{
			ProbeID: "p1",
			Type: &authv1.DeviceProbe_ReadFile_{
				ReadFile: &authv1.DeviceProbe_ReadFile{
					Path: "relative/path",
				},
			},
		},
	})

	assert.Equal(t, 1, len(results))
	assert.Equal(t, authv1.DeviceProbeResult_FAILED, results[0].Status)
	assert.True(t, isResultWithinLimits(&authv1.DeviceProbe{}, results[0]))
}

func TestTruncateErr(t *testing.T) {
	assert.Equal(t, "", truncateErr(""))
	assert.Equal(t, "error", truncateErr("error"))
	assert.Equal(t, "error", truncateErr("err\xffor"))

	{
		ret := truncateErr(strings.Repeat("a", maxErrLen+10))
		assert.Equal(t, maxErrLen, len(ret))
	}

	{
		ret := truncateErr(strings.Repeat("a", maxErrLen-1) + "é")
		assert.True(t, utf8.ValidString(ret))
		assert.Equal(t, strings.Repeat("a", maxErrLen-1), ret)
	}

	{
		res := probeStatus("p1", authv1.DeviceProbeResult_FAILED, strings.Repeat("é", maxErrLen))
		assert.LessOrEqual(t, len(res.Detail), maxErrLen)
		_, err := proto.Marshal(res)
		assert.Nil(t, err)
	}
}

func TestProbeText(t *testing.T) {
	{
		res := probeText("p1", "C02XK1ABJHD3")
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, "C02XK1ABJHD3", res.GetText())
	}

	{
		res := probeText("p1", "serial\xff")
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.Equal(t, []byte("serial\xff"), res.GetData())
		_, err := proto.Marshal(res)
		assert.Nil(t, err)
	}
}
