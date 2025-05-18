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

package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/stretchr/testify/assert"
)

func TestController(t *testing.T) {

	{
		ctx, cancel := context.WithCancel(context.Background())
		ctl, err := NewController(ctx, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				L3Mode: userv1.ConnectionState_BOTH,
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				L3Mode: cliconfigv1.Connection_Preferences_BOTH,
			},
		}, nil)
		assert.Nil(t, err)

		ctl.Start(ctx)
		cancel()
		ctl.Close()
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		ctl, err := NewController(ctx, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				L3Mode: userv1.ConnectionState_BOTH,
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				L3Mode: cliconfigv1.Connection_Preferences_BOTH,
			},
		}, &ccommon.TestGoNetCtl{})
		assert.Nil(t, err)

		ctl.Start(ctx)
		ctl.Close()
		cancel()
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		ctl, err := NewController(ctx, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				L3Mode: userv1.ConnectionState_BOTH,
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				L3Mode: cliconfigv1.Connection_Preferences_BOTH,
			},
		}, &ccommon.TestGoNetCtl{})
		assert.Nil(t, err)

		err = ctl.Start(ctx)
		assert.Nil(t, err)
		err = ctl.AddService(&userv1.HostedService{
			Name: "svc-1",
			// Namespace: "ns-1",
			Port:   43210,
			L4Type: userv1.HostedService_TCP,
			Upstream: &userv1.HostedService_Upstream{
				Host: "www.google.com",
				Port: 443,
			},
			Address: &metav1.DualStackIP{
				Ipv4: "127.0.0.1",
			},
		})
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)

		err = ctl.UpdateService(&userv1.HostedService{
			Name: "svc-1",
			// Namespace: "ns-1",
			Port:   43210,
			L4Type: userv1.HostedService_TCP,
			Upstream: &userv1.HostedService_Upstream{
				Host: "www.facebook.com",
				Port: 443,
			},
			Address: &metav1.DualStackIP{
				Ipv4: "127.0.0.1",
			},
		})
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)

		err = ctl.DeleteService("svc-1")
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)

		err = ctl.Close()
		assert.Nil(t, err)
		cancel()
	}

}
