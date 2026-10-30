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
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAWSSignatureVerification(t *testing.T, a *awsFixture, key aws.Credentials) {
	c := a.direct("s3", key)
	base := "/verification-" + a.h.Name()
	c.mustRequest(t, http.MethodPut, base, nil, nil, http.StatusOK)
	c.mustRequest(t, http.MethodPut, base+"/object", []byte("original"), nil, http.StatusOK)
	for _, tt := range []struct {
		name string
		key  *aws.Credentials
		code string
	}{
		{"Unsigned", nil, "AccessDenied"},
		{"WrongSecret", &aws.Credentials{AccessKeyID: key.AccessKeyID, SecretAccessKey: "wrong-secret"}, "SignatureDoesNotMatch"},
		{"UnknownKey", &aws.Credentials{AccessKeyID: "AKIAUNKNOWN0000000000", SecretAccessKey: "wrong-secret"}, "InvalidClientTokenId"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			invalid := *c
			invalid.credentials = tt.key
			res := invalid.mustRequest(t, http.MethodGet, base+"/object", nil, nil, http.StatusForbidden)
			assert.Contains(t, string(res.body), tt.code)
		})
	}
	t.Run("TamperedPayload", func(t *testing.T) {
		original := []byte("Action=GetCallerIdentity&Version=2011-06-15")
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.endpoint+"/", bytes.NewReader(original))
		require.Nil(t, err)
		hash := fmt.Sprintf("%x", sha256.Sum256(original))
		req.Header.Set("X-Amz-Content-Sha256", hash)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		require.Nil(t, v4.NewSigner().SignHTTP(t.Context(), key, req, hash, "sts", awsRegion, time.Now()))
		tampered := append(original, []byte("&injected=1")...)
		req.Body = io.NopCloser(bytes.NewReader(tampered))
		req.ContentLength = int64(len(tampered))
		res, err := c.client.Do(req)
		require.Nil(t, err)
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		require.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, res.StatusCode)
		assert.Contains(t, string(body), "SignatureDoesNotMatch")
	})
}

func (a *awsFixture) publicUser(t *testing.T, c *awsClient) *awsClient {
	t.Helper()
	usr := a.h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{InlinePolicies: harness.InlineAllowAny("allow")})
	ret := *c
	ret.headers = http.Header{"Authorization": {"Bearer " + a.h.AccessToken(t, usr)}}
	return &ret
}

func testAWSAccess(t *testing.T, a *awsFixture, key aws.Credentials) {
	svc, c := a.service(t, "s3", key, false)
	base := "/access-" + a.h.Name()
	direct := a.direct("s3", key)
	direct.mustRequest(t, http.MethodPut, base, nil, nil, http.StatusOK)
	direct.mustRequest(t, http.MethodPut, base+"/report", []byte("private-report"), nil, http.StatusOK)
	t.Run("AuthenticationRequired", func(t *testing.T) {
		c.waitRequest(t, a.h, http.MethodGet, base+"/report", http.StatusUnauthorized)
	})
	authorized := a.publicUser(t, c)
	t.Run("ClientlessToken", func(t *testing.T) {
		authorized.waitRequest(t, a.h, http.MethodGet, base+"/report", http.StatusOK)
		res := authorized.mustRequest(t, http.MethodGet, base+"/report", nil, nil, http.StatusOK)
		assert.Equal(t, "private-report", string(res.body))
	})
	t.Run("AuthorizationRevoked", func(t *testing.T) {
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{InlinePolicies: []*corev1.InlinePolicy{{
			Name: "deny", Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{harness.DenyAnyRule("deny", 0)}},
		}}}
		svc = a.h.UpdateService(t, svc)
		authorized.waitRequest(t, a.h, http.MethodGet, base+"/report", http.StatusForbidden)
		svc.Spec.Authorization = nil
		svc = a.h.UpdateService(t, svc)
		authorized.waitRequest(t, a.h, http.MethodGet, base+"/report", http.StatusOK)
	})
	t.Run("ForgedAWSHeaders", func(t *testing.T) {
		svc.Spec.IsAnonymous = true
		svc = a.h.UpdateService(t, svc)
		c.waitRequest(t, a.h, http.MethodGet, base+"/report", http.StatusOK)
		forged := http.Header{
			"Authorization": {"AWS4-HMAC-SHA256 Credential=AKIAFORGED/20000101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=bad"},
			"X-Amz-Date":    {"20000101T000000Z"}, "X-Amz-Content-Sha256": {"wrong"}, "X-Amz-Security-Token": {"forged"},
		}
		res := c.mustRequest(t, http.MethodGet, base+"/report", nil, forged, http.StatusOK)
		assert.Equal(t, "private-report", string(res.body))
	})
	t.Run("SigningDisabled", func(t *testing.T) {
		svc.Spec.Config.GetHttp().Auth = nil
		svc = a.h.UpdateService(t, svc)
		a.h.Eventually(t, "the upstream to reject requests when signing is disabled", harness.DecisionBudget,
			func(ctx context.Context) error {
				res, err := c.request(ctx, http.MethodGet, base+"/report", nil, nil)
				if err != nil {
					return err
				}
				if res.status != http.StatusForbidden || !bytes.Contains(res.body, []byte("AccessDenied")) {
					return errors.Errorf("expected an AWS access denial, got %d: %s", res.status, res.body)
				}
				return nil
			})
	})
}

func testAWSDynamicCredentials(t *testing.T, a *awsFixture, key aws.Credentials) {
	bucket := "tenants-" + a.h.Name()
	direct := a.direct("s3", key)
	direct.mustRequest(t, http.MethodPut, "/"+bucket, nil, nil, http.StatusOK)
	policy := func(prefix string) string {
		return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":%q}]}`, "arn:aws:s3:::"+bucket+"/"+prefix+"/*")
	}
	alphaKey := a.identity(t, policy("alpha"))
	betaKey := a.identity(t, policy("beta"))
	for _, tenant := range []string{"alpha", "beta", "gamma"} {
		direct.mustRequest(t, http.MethodPut, "/"+bucket+"/"+tenant+"/report", []byte(tenant+"-report"), nil, http.StatusOK)
	}
	svc, c := a.service(t, "s3", alphaKey, false)
	alpha := a.publicUser(t, c)
	betaUser := a.h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{InlinePolicies: harness.InlineAllowAny("allow")})
	beta := *c
	beta.headers = http.Header{"Authorization": {"Bearer " + a.h.AccessToken(t, betaUser)}}
	betaSecret := a.h.CreateSecret(t, "", betaKey.SecretAccessKey)
	named := &corev1.Service_Spec_Config{
		Name: "beta", Upstream: svc.Spec.Config.Upstream,
		Type: &corev1.Service_Spec_Config_Http{Http: awsHTTPConfig("s3", betaKey, betaSecret.Metadata.Name)},
	}
	svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
		Configs: []*corev1.Service_Spec_Config{named},
		Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{
			Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: fmt.Sprintf("ctx.user.metadata.name == %q", betaUser.Metadata.Name)}},
			Type:      &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "beta"},
		}},
	}
	svc = a.h.UpdateService(t, svc)
	check := func(ctx context.Context, client *awsClient, tenant string, want int, code string) error {
		res, err := client.request(ctx, http.MethodGet, "/"+bucket+"/"+tenant+"/report", nil, nil)
		if err != nil {
			return err
		}
		if res.status != want {
			return errors.Errorf("%s returned %d, want %d: %s", tenant, res.status, want, res.body)
		}
		if code != "" && !bytes.Contains(res.body, []byte(code)) {
			return errors.Errorf("missing AWS error %s: %s", code, res.body)
		}
		if want == http.StatusOK && string(res.body) != tenant+"-report" {
			return errors.Errorf("unexpected tenant data: %s", res.body)
		}
		return nil
	}
	wait := func(t *testing.T, client *awsClient, tenant string, want int, code string) {
		t.Helper()
		a.h.Eventually(t, fmt.Sprintf("%s to return %d using the selected credentials", tenant, want), harness.DecisionBudget,
			func(ctx context.Context) error { return check(ctx, client, tenant, want, code) })
	}
	t.Run("IdentityIsolation", func(t *testing.T) {
		wait(t, alpha, "alpha", http.StatusOK, "")
		wait(t, &beta, "beta", http.StatusOK, "")
		wait(t, alpha, "beta", http.StatusForbidden, "AccessDenied")
		wait(t, &beta, "alpha", http.StatusForbidden, "AccessDenied")
		for _, tt := range []struct {
			name, other string
			client      *awsClient
		}{
			{"alpha", "beta", alpha}, {"beta", "alpha", &beta},
		} {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				for range 6 {
					require.Nil(t, check(t.Context(), tt.client, tt.name, http.StatusOK, ""))
					require.Nil(t, check(t.Context(), tt.client, tt.other, http.StatusForbidden, "AccessDenied"))
				}
			})
		}
	})
	t.Run("SecretRotation", func(t *testing.T) {
		a.h.UpdateSecret(t, betaSecret.Metadata.Name, "invalid-secret")
		wait(t, &beta, "beta", http.StatusForbidden, "SignatureDoesNotMatch")
		require.Nil(t, check(t.Context(), alpha, "alpha", http.StatusOK, ""))
		a.h.UpdateSecret(t, betaSecret.Metadata.Name, betaKey.SecretAccessKey)
		wait(t, &beta, "beta", http.StatusOK, "")
	})
	t.Run("ReplaceCredentials", func(t *testing.T) {
		gammaKey := a.identity(t, policy("gamma"))
		gammaSecret := a.h.CreateSecret(t, "", gammaKey.SecretAccessKey)
		svc.Spec.DynamicConfig.Configs[0].Type = &corev1.Service_Spec_Config_Http{Http: awsHTTPConfig("s3", gammaKey, gammaSecret.Metadata.Name)}
		svc = a.h.UpdateService(t, svc)
		wait(t, &beta, "gamma", http.StatusOK, "")
		wait(t, &beta, "beta", http.StatusForbidden, "AccessDenied")
		a.h.UpdateSecret(t, betaSecret.Metadata.Name, "retired-secret")
		a.h.Consistently(t, "retiring the old Secret to preserve the replacement credentials", decisionSettle,
			func(ctx context.Context) error {
				if err := check(ctx, &beta, "gamma", http.StatusOK, ""); err != nil {
					return err
				}
				return check(ctx, alpha, "alpha", http.StatusOK, "")
			})
	})
}
