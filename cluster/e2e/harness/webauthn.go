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

package harness

import (
	"context"
	"fmt"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/authc"
	"google.golang.org/grpc/metadata"
)

const BrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

func (h *H) BrowserAuthC(t *testing.T) authv1.MainServiceClient {
	t.Helper()

	c, err := authc.NewClient(t.Context(), h.Domain, &authc.Opts{
		UserAgent: BrowserUserAgent,
	})
	if err != nil {
		t.Fatalf("Could not build a browser authentication client for %s: %+v", h.Domain, err)
	}

	t.Cleanup(func() { c.Close() })

	return c.C()
}

func (h *H) RootURL() string {
	return fmt.Sprintf("https://%s", h.Domain)
}

func (h *H) BrowserCtx(ctx context.Context) context.Context {
	return h.OriginCtx(ctx, h.RootURL())
}

func (h *H) OriginCtx(ctx context.Context, origin string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "origin", origin)
}

type VirtualFIDO struct {
	RP   virtualwebauthn.RelyingParty
	Auth virtualwebauthn.Authenticator
	Cred virtualwebauthn.Credential
}

func (h *H) NewVirtualFIDO(t *testing.T) *VirtualFIDO {
	t.Helper()

	handle := uuid.New()

	return &VirtualFIDO{
		RP: virtualwebauthn.RelyingParty{
			ID:     h.Domain,
			Name:   "Octelium",
			Origin: h.RootURL(),
		},
		Auth: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
			UserHandle:     handle[:],
			BackupEligible: true,
			ClientExtensionResults: map[string]any{
				"credProps": map[string]any{
					"rk": true,
				},
			},
		}),
		Cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
}

func (v *VirtualFIDO) Assertion(t *testing.T, request string) string {
	t.Helper()

	opts, err := virtualwebauthn.ParseAssertionOptions(request)
	if err != nil {
		t.Fatalf("Could not parse the passkey assertion options %q: %+v", request, err)
	}

	return virtualwebauthn.CreateAssertionResponse(v.RP, v.Auth, v.Cred, *opts)
}
