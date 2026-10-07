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

package server

import (
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
)

func TestGetStoredDomains(t *testing.T) {
	canonical := &cliconfigv1.State_Domain{
		SessionToken: &authv1.SessionToken{RefreshToken: "canonical"},
		Settings:     &daemonv1.DomainSettings{AutoConnect: true},
	}
	other := &cliconfigv1.State_Domain{
		SessionToken: &authv1.SessionToken{RefreshToken: "other"},
	}

	domainMap := map[string]*cliconfigv1.State_Domain{
		"example.com":  canonical,
		"Example.com":  {SessionToken: &authv1.SessionToken{RefreshToken: "upper"}},
		"EXAMPLE.COM.": {SessionToken: &authv1.SessionToken{RefreshToken: "dot"}},
		"other.com":    other,
		"Upper.org":    {SessionToken: &authv1.SessionToken{RefreshToken: "upper"}},
		"invalid":      {SessionToken: &authv1.SessionToken{RefreshToken: "invalid"}},
	}

	for range 100 {
		ret := getStoredDomains(domainMap)

		assert.Equal(t, 3, len(ret))
		assert.Equal(t, canonical, ret["example.com"])
		assert.Equal(t, other, ret["other.com"])

		itm, ok := ret["upper.org"]
		assert.True(t, ok)
		assert.Nil(t, itm)
	}

	assert.Empty(t, getStoredDomains(nil))
}
