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

package logout

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/db"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestLogoutKeepsDomainSettings(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")

	domain := "example.invalid"
	t.Setenv("OCTELIUM_DOMAIN", domain)

	dbC, err := db.Open("mem")
	assert.Nil(t, err)

	assert.Nil(t, dbC.SetSessionToken(domain, &authv1.SessionToken{
		AccessToken:  "at",
		RefreshToken: "rt",
	}))
	assert.Nil(t, dbC.SetDomainSettings(domain, &daemonv1.DomainSettings{
		Domain:      domain,
		AutoConnect: true,
		ConnectionOptions: &daemonv1.ConnectionOptions{
			TunnelMode: daemonv1.ConnectionOptions_QUICV0,
		},
	}))

	cmd := &cobra.Command{}
	cmd.SetContext(cliutils.WithDB(context.Background(), dbC))

	assert.Nil(t, doCmd(cmd, nil))

	_, err = dbC.GetSessionToken(domain)
	assert.True(t, dbC.ErrorIsNotFound(err))

	itm, err := dbC.Get(domain)
	assert.Nil(t, err)
	assert.True(t, itm.GetSettings().GetAutoConnect())
	assert.Equal(t, daemonv1.ConnectionOptions_QUICV0,
		itm.GetSettings().GetConnectionOptions().GetTunnelMode())
}
