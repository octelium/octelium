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

package suite

import (
	"fmt"
	"os"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/clientcredentials"
)

func createRootCredential(t *testing.T, h *harness.H, credType string) *corev1.CredentialToken {
	t.Helper()

	cmd := "octeliumctl create cred --user root --policy allow-all -o json"
	if credType != "" {
		cmd = fmt.Sprintf(
			"octeliumctl create cred --user root --policy allow-all --type %s -o json", credType)
	}

	ret := &corev1.CredentialToken{}
	h.MustOutputProto(t, cmd, ret)
	return ret
}

func testCredentialAccessToken(t *testing.T, h *harness.H) {
	tkn := createRootCredential(t, h, "access-token")
	h.CheckPublicToken(t, "demo-nginx", tkn.GetAccessToken().AccessToken)
}

func testCredentialOAuth2(t *testing.T, h *harness.H) {
	tkn := createRootCredential(t, h, "oauth2")

	conf := &clientcredentials.Config{
		ClientID:     tkn.GetOauth2Credentials().ClientID,
		ClientSecret: tkn.GetOauth2Credentials().ClientSecret,
		TokenURL:     h.ClusterURL() + "/oauth2/token",
	}

	oauthToken, err := conf.Token(t.Context())
	require.Nil(t, err)

	h.CheckPublicToken(t, "demo-nginx", oauthToken.AccessToken)
}

func testCredentialAuthToken(t *testing.T, h *harness.H) {
	tkn := createRootCredential(t, h, "")

	tmpDir, err := os.MkdirTemp("", "octelium-e2e-home-*")
	require.Nil(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	cmd := h.Cmd(t.Context(), fmt.Sprintf("octelium login --auth-token %s",
		tkn.GetAuthenticationToken().AuthenticationToken))
	cmd.Env = append(os.Environ(), fmt.Sprintf("OCTELIUM_HOME=%s", tmpDir))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	require.Nil(t, cmd.Run())
}
