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

package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClientTLSCfg(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Port: 8080,
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svc)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	lb := loadbalancer.NewLbManager(fakeC.OcteliumC, vCache)

	upstream, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
		RequestContext: &corev1.RequestContext{
			Service: vCache.GetService(),
		},
	})
	assert.Nil(t, err, "%+v", err)

	tlscfg, err := GetClientTLSCfg(ctx, svc, nil, secretMan, upstream)
	assert.Nil(t, err)
	assert.Nil(t, tlscfg)

	kubeconfig := `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMvakNDQWVhZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJek1ERXlNVEF5TXpVME5sb1hEVE16TURFeE9EQXlNelUwTmxvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTUdZCkY1YmdqNmc2ZG9RUkE0bkNQaEoyK2NnOEcrZkFiY2NnWFZDWWw5cWFPZ29yczFMT29VTFphS0Ric2RvRTJWNUYKQmFYUHp0U2xiekVWZ1RNc2RJSGpaUU5VZU0yMlJWbWI3TmFGWGN2aUVHbjYyVU5RVHVDM0ZCVkcvWncyQU1VUwpkb2lEeXFBd1loMElRbHoydWhlb0dkSEU1dmgvRFVoQzJhK3h1Q1VFU1ZBWTRwMmdscmI4OTd5aVA5OGcxYWgyCk55MC9xYkY3NjJJMENreXVnMzRnYWtyYmZGSXJtU0ZubTdpVlN6S0NldExvaXFPakpLV2g2emlGUlBsVTY1MS8KbnJTa0dVckpwZDd5a2dsS25WQldjMXd5TlVxbDNJaC84cGtuVzhRY0UzQUpuSFlDbHJ0bndPdDRpc25GRHBtKwp2bmNlcVVRQTlQTzJBaHJCbmowQ0F3RUFBYU5aTUZjd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZIWEFBaTRpRGFjVVppcWJsc2x6bWdyQWZTZDZNQlVHQTFVZEVRUU8KTUF5Q0NtdDFZbVZ5Ym1WMFpYTXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRUNLL0xqSmxWcVR2WkcxTUt5Wgowck0xUVhaQm5YZHNaQjFmT3lBTVBnazJkL2libXh1emdpOXd2TWZ1SVZBekdHb1ZVY3E2dmtHODB2S3VSNjQzCnJSR3BJS0Z0VlZZNXZDN3NMUnpwNWtVTWpZN3dYUUxscFNEOTRXUkJKdTY0a0M4Wk54cFBXRFdFN1VMRTNtTnYKZjNubjF6NlQ4V2tzeSs0QnVjTCtlSU45U1ZqdWFGNkdXVjl0U1BDeDl0cks0R253alJJNUxUOElXNGtFVlZEQwp4ZjgzTnlNbEU3QlRnNVBkQ2I3bE9hczNwRlZrMExLQ09WLzBMMExINTZXdlVHUWY2dXhuSy9vRXRpUlBnUXM0ClBVNjBJWjZiYkJPMTBMN3FOaUNmdEdXR0FJRCtHYWRZZjhLNnlZL2VCd21tMFFiZkxHY3J6dFpINWJuWnNMRU8KdXNnPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://example.com:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubernetes-admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
kind: Config
preferences: {}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURJVENDQWdtZ0F3SUJBZ0lJWTVOWTJ6OVhZc0V3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TXpBeE1qRXdNak0xTkRaYUZ3MHlOREF4TWpFd01qTTFORGxhTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXRlUXNJVG16M2dlc3h1ZkwKcnlBNjQyQm9TY21qNjg1eDB0LzdQbXg3OXZXMkJzWmcyZHRKOUF3K0QxVmJuRW5KaGZZcHNlZzBnZUhCVXRlKwo4czhCQVFSOU9HdEh3cWV0bVR0Qmh6MTE0WXFzMDg5RlI0SnJvWTQ0OXpwUmRRMFZrUWNhR29XU1dESzd5ZVhICjJrQUxkVm9uTS9KWktsdzBISE9hVWRPaEZaNzkveFlmc0ZhWVpOR3FjU2hjTlZ1T0MwRmE0SXc2YU8wSDRiMGMKeEI2NitmWVRYYkV3c2hGTWYya1hlZnRVeUNaRitiTEVvcUtIUUJCV09Nd2lqblpGdCtzRGk5QTYwM0k3Qk9mQwpiamdadEVZQW4zL3NsZkZHVTFLaWczQ3Z4VTVaUUFzaU8rVXlwdEtuUk8ySERheGNZOCs3TTRSdjZkcXFraDd2CjVmb1IzUUlEQVFBQm8xWXdWREFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RBWURWUjBUQVFIL0JBSXdBREFmQmdOVkhTTUVHREFXZ0JSMXdBSXVJZzJuRkdZcW01YkpjNW9Ld0gwbgplakFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBZmZJL1hNcy9WVmc1R1ozbHZpQ090N2JRdjRNVER5b0VYN1ZoCm84YTUyRjNpVW1zbExwZGUxVm0rbTRMN3l6eFZRcmg5YmNBSk0yVnRXNmlOTis4RWtJQzVTeE9XTkpFWDFDZTQKaXU4THd3RGFCaFg2ZmdteEp6Z2N1cm1tNWdWT3Y0b2FBOUtndGNLb0l6STVSQWx3bS9iV2dTZ1NqUVpobU84Lwp4cVJVS1ZQenYzZHdUOWFjNkgvOEZ5bFpLTHIrRXltU0JxRWtMeVdJemsrT0tmM0pITUVtWTJIQjQvQXpqVzN4CkIzU0ZwcWwwWmtNczViYmVSUE9YeDMvV0NvZE8zbmlrYUVqU0I1am5GYmdUOUlqeUFsR1BmVzdCaFI4eE10UTkKYXhxcStrWHl6TjRMV2Jya2ZSYXVBQ3c3dnQvOEN5UTNOVDczeXpFeXh5ZlBXTEtZRUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBdGVRc0lUbXozZ2VzeHVmTHJ5QTY0MkJvU2NtajY4NXgwdC83UG14Nzl2VzJCc1pnCjJkdEo5QXcrRDFWYm5FbkpoZllwc2VnMGdlSEJVdGUrOHM4QkFRUjlPR3RId3FldG1UdEJoejExNFlxczA4OUYKUjRKcm9ZNDQ5enBSZFEwVmtRY2FHb1dTV0RLN3llWEgya0FMZFZvbk0vSlpLbHcwSEhPYVVkT2hGWjc5L3hZZgpzRmFZWk5HcWNTaGNOVnVPQzBGYTRJdzZhTzBINGIwY3hCNjYrZllUWGJFd3NoRk1mMmtYZWZ0VXlDWkYrYkxFCm9xS0hRQkJXT013aWpuWkZ0K3NEaTlBNjAzSTdCT2ZDYmpnWnRFWUFuMy9zbGZGR1UxS2lnM0N2eFU1WlFBc2kKTytVeXB0S25STzJIRGF4Y1k4KzdNNFJ2NmRxcWtoN3Y1Zm9SM1FJREFRQUJBb0lCQUNJUFIvUXd5ZTJab2xEYwp0dGRrUWFLeU90VVdYUXVhN05WLys1d0UxSEc2TVF1enVnOFJjUmV4OHkwTDNzdTFSWGRBVVM1dlBPWFZVRTRpCitDNmZkS0NzSm9hYUVDWHpJQjdCYWRQWlBtbXRmZzlya0oyRFhvUXlEWmk5NHVMNFFFR1lBdHRVaDhMY1BTM2gKU1RzbEl3QW1rWkM0b05tOXlrUkpvV3dSSk9qWFBBV0xiMG1kU05ucWtnaVBjTEdDMUhuZkExdGM2c1hmVCtYawpiYkg1TndsUHQ2K1d2S3A3dkhnKzNySnJIcTZzVTFDSnY0Mm9CdHJ1NUNUd3ZMRWVXRmFaMzBnczZUZlMrM3JYCkozWVQrV1pXVmdWTll1Ymw0cDA2YjJ1dGVaNlhvUjFIMVJVTFZEU2xiUC83Mzh6Sk11WmVwTHJXNXF1Y0N6cEUKK0R2TG5FRUNnWUVBMnpZMW1ZRFVnd2dEb0lwdjRlOE8rSEE0RUVkSXdWeFhSaG9uL0pmc2hDL2h5My9XaGU2QQovUjRGRFFROWNPamxzZjQ1NEFqaVQvV2MvRko3WHF4a2hJSC9SYmQ2NC9HTWIvMzVIRGtBY3J4dFNGeitDRnROCmdmalR0WjAzMENhYnJUdlY2Z202WWJzNk4rbHlyLysxWmV3WmJDNEl4aG15R0h3TjBaeXpSME1DZ1lFQTFHcVoKVks2K3h4eFE5YzlUZkpkVXpiOVlIbE1xcFdIUnR2MlFDMWh4Y1NWa0I4d3lockVIL050UU5DZHZib1BuYTZsdApOWTArU1VDbXhVc0M5cE84eDhobUhKT3BhM29zMFJTUHo2Y2dvaFNPWFpEZkxPYXVQOGhkODhmcC9taVorcTdwCkVqWXA5S0pNb3FVT3RDbDZ6c0ljTmNwL1RhUUxZK1QvdGMwSTRGOENnWUFnNW1Ycy8vVGxKWkxGeVlFNU81UFgKbmFBTWNXWnQvdG5xWDRxWTBvUmc0bjdVOS83T1l4bGc0OXlHTTVpMUZYOUQwNUFFRzlFN2h2Vmt1VXhpelNUWQo3bG5Oc05mMDFnL3B6d2hRUUEzZEtvS01WY2lhb0hsbGhGN2g1eEsxWHRZR2pmQnhDN3k1Wmt3NmtBTHlmMEpPClpiejdDMzJ0bmJXcER4VlQzRnpiMlFLQmdRRExLMXFWSUw3Zyt6aUVwRlVhS2pTMnhubW1KNjMybVdWWlBaWDEKQkJjZFBjSTdveGdBdEhzTFkwbUhXT0RBTi9HMWpFd2ttSUFtMkd1cThXQllNRjYwUi8xREFBbGYvMisyVzVCaAo4VnpKS2hneGJrdklTcXdIM2NIZlZpdDladGRBYXVRS3d6dkYvU2FIdXBBaHlqcm9YOGxUdWVlaGYzSlZqY2IzClFMRm95UUtCZ1FEVVlUdjZLOVFnR1lNWXVib1VXZTJBRWV6QTVvcXo1Rm01aEFIS2tGVnp5WVcwUGJuMXR5NUoKOTAySElDRXY5NGVCWEVvS1NWZVVyT3ZMbFpXc2J1VER4aFo0Q1dFMzRUaGwvMzQ0S3VnNnJLNEFJTG81a05pLwpjWVBRTjZ2Z3hpOElQR1FncjRDQU5xd3NXcFJ6RjRMazdBTjNvSENodjRtZHprRGdVYm54bFE9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
`

	sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: kubeconfig,
			},
		},
	})
	assert.Nil(t, err)

	svc.Spec.Mode = corev1.Service_Spec_KUBERNETES
	svc.Spec.Config = &corev1.Service_Spec_Config{

		Type: &corev1.Service_Spec_Config_Kubernetes_{
			Kubernetes: &corev1.Service_Spec_Config_Kubernetes{
				Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_{
					Kubeconfig: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig{
						Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
	}
	svc, err = adminSrv.UpdateService(ctx, svc)
	assert.Nil(t, err, "%+v", err)

	tlscfg, err = GetClientTLSCfg(ctx, svc, nil, secretMan, upstream)
	assert.Nil(t, err)
	assert.NotNil(t, tlscfg)

}

func TestTLSConfigDefaultsAndOverrides(t *testing.T) {
	svc := &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}
	for _, tc := range []struct {
		name string
		cfg  *corev1.Service_Spec_Config
		user bool
		want bool
	}{
		{name: "ExternalDefault"},
		{name: "ClientServedDefault", user: true, want: true},
		{name: "ExplicitTLS", cfg: &corev1.Service_Spec_Config{Tls: &corev1.Service_Spec_Config_TLS{}}, want: true},
		{name: "InsecureTLS", cfg: &corev1.Service_Spec_Config{Tls: &corev1.Service_Spec_Config_TLS{InsecureSkipVerify: true}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc.Spec.Config = tc.cfg
			got, err := GetClientTLSCfg(t.Context(), svc, nil, nil, &loadbalancer.Upstream{
				URL: &url.URL{Scheme: "https", Host: "virtual.example.com"}, SNIHost: "virtual.example.com", IsUser: tc.user,
			})
			require.Nil(t, err)
			if !tc.want {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion)
			assert.Equal(t, uint16(tls.VersionTLS13), got.MaxVersion)
			assert.Equal(t, "virtual.example.com", got.ServerName)
			assert.Equal(t, tc.cfg.GetTls().GetInsecureSkipVerify(), got.InsecureSkipVerify)
		})
	}
	explicit := &corev1.Service_Spec_Config{Tls: &corev1.Service_Spec_Config_TLS{TrustedCAs: []string{"invalid PEM"}}}
	got, err := GetClientTLSCfg(t.Context(), svc, explicit, nil, &loadbalancer.Upstream{})
	assert.NotNil(t, err)
	assert.Nil(t, got)
}

func TestClientServedSecureWebSocketSNI(t *testing.T) {
	svc := &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}
	got, err := GetClientTLSCfg(t.Context(), svc, nil, nil, &loadbalancer.Upstream{
		URL: &url.URL{Scheme: "wss", Host: "virtual.example.com"}, SNIHost: "virtual.example.com", IsUser: true,
	})
	require.Nil(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, "virtual.example.com", got.ServerName)
	}
}

func TestDeprecatedClientCertificatePreservesSNI(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	ca, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	crt, err := utils_cert.GenerateCertificateTmp("virtual.example.com", ca, false)
	require.Nil(t, err)
	secret := &corev1.Secret{Metadata: &metav1.Metadata{Name: "client-certificate"}}
	ucorev1.ToSecret(secret).SetCertificate(string(crt.MustGetCertPEM()), string(crt.MustGetPrivateKeyPEM()))
	secret, err = tst.C.OcteliumC.CoreC().CreateSecret(t.Context(), secret)
	require.Nil(t, err)
	sm, err := secretman.New(t.Context(), tst.C.OcteliumC, nil)
	require.Nil(t, err)
	cfg := &corev1.Service_Spec_Config{ClientCertificate: &corev1.Service_Spec_Config_ClientCertificate{
		Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{FromSecret: secret.Metadata.Name},
	}}
	svc := &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Config: cfg}}
	tlsCfg, err := GetClientTLSCfg(t.Context(), svc, cfg, sm, &loadbalancer.Upstream{
		URL: &url.URL{Scheme: "https", Host: "virtual.example.com"}, SNIHost: "virtual.example.com", IsUser: true,
	})
	require.Nil(t, err)
	require.NotNil(t, tlsCfg)
	assert.Len(t, tlsCfg.Certificates, 1)
	assert.Equal(t, "virtual.example.com", tlsCfg.ServerName)
}

func TestKubernetesTLSCredentialSources(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	ca, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	crt, err := utils_cert.GenerateCertificateTmp("client", ca, false)
	require.Nil(t, err)
	secret := &corev1.Secret{Metadata: &metav1.Metadata{Name: "kubernetes-client"}}
	ucorev1.ToSecret(secret).SetCertificate(string(crt.MustGetCertPEM()), string(crt.MustGetPrivateKeyPEM()))
	_, err = tst.C.OcteliumC.CoreC().CreateSecret(t.Context(), secret)
	require.Nil(t, err)
	sm, err := secretman.New(t.Context(), tst.C.OcteliumC, nil)
	require.Nil(t, err)
	for _, tc := range []struct {
		name   string
		client bool
		ca     string
		secret string
		fail   bool
	}{
		{name: "BearerSystemRoots"},
		{name: "BearerCustomRoots", ca: string(ca.MustGetCertPEM())},
		{name: "BearerInvalidCA", ca: "invalid PEM", fail: true},
		{name: "ClientCertificate", client: true, secret: secret.Metadata.Name},
		{name: "ClientCustomRoots", client: true, secret: secret.Metadata.Name, ca: string(ca.MustGetCertPEM())},
		{name: "ClientMissingSecret", client: true, secret: "missing", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var roots []string
			if tc.ca != "" {
				roots = []string{tc.ca}
			}
			kube := &corev1.Service_Spec_Config_Kubernetes{Type: &corev1.Service_Spec_Config_Kubernetes_BearerToken_{
				BearerToken: &corev1.Service_Spec_Config_Kubernetes_BearerToken{TrustedCAs: roots},
			}}
			if tc.client {
				kube.Type = &corev1.Service_Spec_Config_Kubernetes_ClientCertificate{ClientCertificate: &corev1.Service_Spec_Config_ClientCertificate{
					Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{FromSecret: tc.secret}, TrustedCAs: roots,
				}}
			}
			cfg := &corev1.Service_Spec_Config{Type: &corev1.Service_Spec_Config_Kubernetes_{Kubernetes: kube}}
			svc := &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES, Config: cfg}}
			got, err := GetClientTLSCfg(t.Context(), svc, cfg, sm, &loadbalancer.Upstream{})
			if tc.fail {
				assert.NotNil(t, err)
				return
			}
			require.Nil(t, err)
			require.NotNil(t, got)
			assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion)
			assert.Equal(t, tc.ca != "", got.RootCAs != nil)
			want := 0
			if tc.client {
				want = 1
			}
			assert.Len(t, got.Certificates, want)
		})
	}
}

func TestKubeconfigClientCertificatesAndInvalidReferences(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	ca, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	crt, err := utils_cert.GenerateCertificateTmp("client", ca, false)
	require.Nil(t, err)
	sm, err := secretman.New(t.Context(), tst.C.OcteliumC, nil)
	require.Nil(t, err)
	for _, tc := range []struct {
		name    string
		ca      bool
		cluster string
		user    string
		fail    bool
	}{
		{"CustomCA", true, "cluster", "user", false},
		{"SystemCA", false, "cluster", "user", false},
		{"MissingCluster", true, "missing", "user", true},
		{"MissingUser", true, "cluster", "missing", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kube := &k8sutils.KubeConfig{
				APIVersion: "v1", Kind: "Config", CurrentContext: "selected",
				Clusters: []k8sutils.KubeConfigCluster{{Name: "cluster", Cluster: k8sutils.KubeConfigClusterConfig{Server: "https://api.example.com"}}},
				Users: []k8sutils.KubeConfigUser{{Name: "user", User: k8sutils.KubeConfigUserConfig{
					ClientCertificateData: base64.StdEncoding.EncodeToString(crt.MustGetCertPEM()),
					ClientKeyData:         base64.StdEncoding.EncodeToString(crt.MustGetPrivateKeyPEM()),
				}}},
				Contexts: []k8sutils.KubeConfigContext{{Name: "selected", Context: k8sutils.KubeConfigContextConfig{Cluster: tc.cluster, User: tc.user}}},
			}
			if tc.ca {
				kube.Clusters[0].Cluster.CertificateAuthorityData = base64.StdEncoding.EncodeToString(ca.MustGetCertPEM())
			}
			data, err := kube.MarshalToYAML()
			require.Nil(t, err)
			secret, err := tst.C.OcteliumC.CoreC().CreateSecret(t.Context(), &corev1.Secret{
				Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
				Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: string(data)}},
			})
			require.Nil(t, err)
			cfg := &corev1.Service_Spec_Config{Type: &corev1.Service_Spec_Config_Kubernetes_{Kubernetes: &corev1.Service_Spec_Config_Kubernetes{
				Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_{Kubeconfig: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig{
					Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_FromSecret{FromSecret: secret.Metadata.Name},
				}},
			}}}
			svc := &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES, Config: cfg}}
			var got *tls.Config
			if !assert.NotPanics(t, func() { got, err = GetClientTLSCfg(t.Context(), svc, cfg, sm, &loadbalancer.Upstream{}) }) {
				return
			}
			if tc.fail {
				assert.NotNil(t, err)
				return
			}
			require.Nil(t, err)
			require.NotNil(t, got)
			assert.Len(t, got.Certificates, 1)
			assert.Equal(t, tc.ca, got.RootCAs != nil)
		})
	}
}

func TestGetClientTLSCfgNew(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	crt, err := utils_cert.GenerateCertificateTmp("example.com", rootCA, false)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Port: 8080,
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},

				Tls: &corev1.Service_Spec_Config_TLS{
					TrustedCAs: []string{
						string(rootCA.MustGetCertPEM()),
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svc)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	lb := loadbalancer.NewLbManager(fakeC.OcteliumC, vCache)

	upstream, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
		RequestContext: &corev1.RequestContext{
			Service: vCache.GetService(),
		},
	})
	assert.Nil(t, err, "%+v", err)

	{
		tlscfg, err := GetClientTLSCfg(ctx, svc, nil, secretMan, upstream)
		assert.Nil(t, err)

		pool := x509.NewCertPool()
		pool.AddCert(rootCA.Certificate)

		assert.True(t, tlscfg.RootCAs.Equal(tlscfg.RootCAs))
		assert.False(t, tlscfg.InsecureSkipVerify)
	}

	{
		svc.Spec.Config.Tls.AppendToSystemPool = true
		tlscfg, err := GetClientTLSCfg(ctx, svc, nil, secretMan, upstream)
		assert.Nil(t, err)

		pool, err := x509.SystemCertPool()
		assert.Nil(t, err)
		pool.AddCert(rootCA.Certificate)

		assert.True(t, tlscfg.RootCAs.Equal(tlscfg.RootCAs))
		assert.False(t, tlscfg.InsecureSkipVerify)
	}

	{
		svc.Spec.Config.Tls.AppendToSystemPool = true
		svc.Spec.Config.Tls.InsecureSkipVerify = true
		tlscfg, err := GetClientTLSCfg(ctx, svc, nil, secretMan, upstream)
		assert.Nil(t, err)

		pool, err := x509.SystemCertPool()
		assert.Nil(t, err)
		pool.AddCert(rootCA.Certificate)

		assert.True(t, tlscfg.RootCAs.Equal(tlscfg.RootCAs))
		assert.True(t, tlscfg.InsecureSkipVerify)
	}

	{

		sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Secret_Spec{
				Data: &corev1.Secret_Spec_Data{
					Type: &corev1.Secret_Spec_Data_Value{
						Value: string(crt.MustGetCertPEM()),
					},
				},
			},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: string(crt.MustGetPrivateKeyPEM()),
				},
			},
		})
		assert.Nil(t, err)

		svc.Spec.Config.Tls.AppendToSystemPool = false
		svc.Spec.Config.Tls.InsecureSkipVerify = false
		svc.Spec.Config.ClientCertificate = &corev1.Service_Spec_Config_ClientCertificate{
			Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{
				FromSecret: sec.Metadata.Name,
			},
		}

		tlscfg, err := GetClientTLSCfg(ctx, svc, nil, secretMan, upstream)
		assert.Nil(t, err)

		pool, err := x509.SystemCertPool()
		assert.Nil(t, err)
		pool.AddCert(rootCA.Certificate)

		assert.True(t, tlscfg.RootCAs.Equal(tlscfg.RootCAs))
		assert.Equal(t, crt.Certificate.Raw, tlscfg.Certificates[0].Leaf.Raw)
		assert.False(t, tlscfg.InsecureSkipVerify)
	}
}

func TestGeneratedTLSConfigSchemes(t *testing.T) {
	for _, scheme := range []string{"https", "tls", "wss", "http", "ws", "tcp", ""} {
		for _, isUser := range []bool{false, true} {
			for _, selected := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/ClientServed%t/SelectedConfig%t", scheme, isUser, selected), func(t *testing.T) {
					svc := &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}
					var cfg *corev1.Service_Spec_Config
					if selected {
						cfg = &corev1.Service_Spec_Config{Name: "selected"}
					} else {
						svc.Spec.Config = &corev1.Service_Spec_Config{}
					}
					got, err := GetClientTLSCfg(t.Context(), svc, cfg, nil, &loadbalancer.Upstream{
						URL:      &url.URL{Scheme: scheme, Host: "url.example.com:8443"},
						HostPort: "192.0.2.1:8443", SNIHost: "certificate.example.com", IsUser: isUser,
					})
					require.Nil(t, err)
					if !isUser || (scheme != "https" && scheme != "tls" && scheme != "wss") {
						assert.Nil(t, got)
						return
					}
					require.NotNil(t, got)
					assert.Equal(t, "certificate.example.com", got.ServerName)
					assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion)
					assert.Equal(t, uint16(tls.VersionTLS13), got.MaxVersion)
					assert.False(t, got.InsecureSkipVerify)
					assert.Nil(t, got.RootCAs)
					assert.Empty(t, got.Certificates)
				})
			}
		}
	}
}

func TestWSSCertificateVerification(t *testing.T) {
	crt, err := utils_cert.GenerateSelfSignedCert("virtual.example.com", []string{"virtual.example.com"}, time.Hour)
	require.Nil(t, err)
	certificate, err := tls.X509KeyPair(crt.MustGetCertPEM(), crt.MustGetPrivateKeyPEM())
	require.Nil(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(crt.Certificate)
	sni := make(chan string, 3)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	backend.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni <- hello.ServerName
			return nil, nil
		},
	}
	backend.StartTLS()
	defer backend.Close()
	for _, tc := range []struct {
		name       string
		serverName string
		trusted    bool
	}{
		{name: "TrustedName", serverName: "virtual.example.com", trusted: true},
		{name: "WrongName", serverName: "other.example.com", trusted: true},
		{name: "Untrusted", serverName: "virtual.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}
			cfg, err := GetClientTLSCfg(t.Context(), svc, nil, nil, &loadbalancer.Upstream{
				URL: &url.URL{Scheme: "wss", Host: tc.serverName}, SNIHost: tc.serverName, IsUser: true,
			})
			require.Nil(t, err)
			require.NotNil(t, cfg)
			cfg.RootCAs = x509.NewCertPool()
			if tc.trusted {
				cfg.RootCAs = roots
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
			switch tc.name {
			case "TrustedName":
				require.Nil(t, err)
				defer conn.Close()
				state := conn.(*tls.Conn).ConnectionState()
				assert.NotEmpty(t, state.VerifiedChains)
				assert.Equal(t, tc.serverName, state.ServerName)
			case "WrongName":
				var hostnameErr x509.HostnameError
				assert.ErrorAs(t, err, &hostnameErr)
				assert.Nil(t, conn)
			case "Untrusted":
				var authorityErr x509.UnknownAuthorityError
				assert.ErrorAs(t, err, &authorityErr)
				assert.Nil(t, conn)
			}
			select {
			case name := <-sni:
				assert.Equal(t, tc.serverName, name)
			case <-ctx.Done():
				t.Fatal("The TLS backend did not receive a client hello")
			}
		})
	}
}

func newTestKubeconfigService(t *testing.T, tst *tests.T, kube *k8sutils.KubeConfig, contextName string) *corev1.Service {
	t.Helper()
	data, err := kube.MarshalToYAML()
	require.Nil(t, err)
	secret, err := tst.C.OcteliumC.CoreC().CreateSecret(t.Context(), &corev1.Secret{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: string(data)}},
	})
	require.Nil(t, err)
	return &corev1.Service{Spec: &corev1.Service_Spec{
		Mode: corev1.Service_Spec_KUBERNETES,
		Config: &corev1.Service_Spec_Config{Type: &corev1.Service_Spec_Config_Kubernetes_{Kubernetes: &corev1.Service_Spec_Config_Kubernetes{
			Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_{Kubeconfig: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig{
				Type:    &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_FromSecret{FromSecret: secret.Metadata.Name},
				Context: contextName,
			}},
		}}},
	}}
}

func TestKubeconfigTLSCredentialsAndTrust(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	sm, err := secretman.New(t.Context(), tst.C.OcteliumC, nil)
	require.Nil(t, err)
	ca, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	systemClient, err := utils_cert.GenerateCertificateTmp("system-client", ca, false)
	require.Nil(t, err)
	customClient, err := utils_cert.GenerateCertificateTmp("custom-client", ca, false)
	require.Nil(t, err)
	for _, credential := range []string{"ClientCertificate", "TokenOnly", "EmptyUser"} {
		for _, tc := range []struct {
			name     string
			current  string
			selected string
			customCA bool
		}{
			{name: "CurrentSystemRoots", current: "system"},
			{name: "SelectedSystemRoots", current: "custom", selected: "system"},
			{name: "CurrentCustomRoots", current: "custom", customCA: true},
			{name: "SelectedCustomRoots", current: "system", selected: "custom", customCA: true},
		} {
			t.Run(credential+"/"+tc.name, func(t *testing.T) {
				kube := &k8sutils.KubeConfig{
					APIVersion: "v1", Kind: "Config", CurrentContext: tc.current,
					Clusters: []k8sutils.KubeConfigCluster{
						{Name: "system", Cluster: k8sutils.KubeConfigClusterConfig{Server: "https://system.example.com"}},
						{Name: "custom", Cluster: k8sutils.KubeConfigClusterConfig{
							Server: "https://custom.example.com", CertificateAuthorityData: base64.StdEncoding.EncodeToString(ca.MustGetCertPEM()),
						}},
					},
					Users: []k8sutils.KubeConfigUser{{Name: "system"}, {Name: "custom"}},
					Contexts: []k8sutils.KubeConfigContext{
						{Name: "system", Context: k8sutils.KubeConfigContextConfig{Cluster: "system", User: "system"}},
						{Name: "custom", Context: k8sutils.KubeConfigContextConfig{Cluster: "custom", User: "custom"}},
					},
				}
				for i, crt := range []*utils_cert.Cert{systemClient, customClient} {
					switch credential {
					case "ClientCertificate":
						kube.Users[i].User.ClientCertificateData = base64.StdEncoding.EncodeToString(crt.MustGetCertPEM())
						kube.Users[i].User.ClientKeyData = base64.StdEncoding.EncodeToString(crt.MustGetPrivateKeyPEM())
					case "TokenOnly":
						kube.Users[i].User.Token = fmt.Sprintf("token-%d", i)
					}
				}
				svc := newTestKubeconfigService(t, tst, kube, tc.selected)
				got, err := GetClientTLSCfg(t.Context(), svc, nil, sm, &loadbalancer.Upstream{})
				require.Nil(t, err)
				require.NotNil(t, got)
				assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), got.MaxVersion)
				assert.False(t, got.InsecureSkipVerify)
				if tc.customCA {
					pool := x509.NewCertPool()
					pool.AddCert(ca.Certificate)
					require.NotNil(t, got.RootCAs)
					assert.True(t, pool.Equal(got.RootCAs))
				} else {
					assert.Nil(t, got.RootCAs)
				}
				if credential != "ClientCertificate" {
					assert.Empty(t, got.Certificates)
					return
				}
				require.Len(t, got.Certificates, 1)
				want := systemClient
				if tc.customCA {
					want = customClient
				}
				assert.Equal(t, want.Certificate.Raw, got.Certificates[0].Certificate[0])
			})
		}
	}
}

func TestKubeconfigTLSInvalidCredentials(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	sm, err := secretman.New(t.Context(), tst.C.OcteliumC, nil)
	require.Nil(t, err)
	ca, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	crt, err := utils_cert.GenerateCertificateTmp("client", ca, false)
	require.Nil(t, err)
	other, err := utils_cert.GenerateCertificateTmp("other", ca, false)
	require.Nil(t, err)
	for _, customCA := range []bool{false, true} {
		for _, name := range []string{"CertificateBase64", "KeyBase64", "CertificatePEM", "KeyPEM", "MismatchedKey", "AuthorityBase64", "AuthorityPEM"} {
			if !customCA && (name == "AuthorityBase64" || name == "AuthorityPEM") {
				continue
			}
			t.Run(fmt.Sprintf("CustomCA%t/%s", customCA, name), func(t *testing.T) {
				caData := ""
				if customCA {
					caData = base64.StdEncoding.EncodeToString(ca.MustGetCertPEM())
				}
				user := k8sutils.KubeConfigUserConfig{
					ClientCertificateData: base64.StdEncoding.EncodeToString(crt.MustGetCertPEM()),
					ClientKeyData:         base64.StdEncoding.EncodeToString(crt.MustGetPrivateKeyPEM()),
				}
				switch name {
				case "CertificateBase64":
					user.ClientCertificateData = "%%%"
				case "KeyBase64":
					user.ClientKeyData = "%%%"
				case "CertificatePEM":
					user.ClientCertificateData = base64.StdEncoding.EncodeToString([]byte("invalid certificate"))
				case "KeyPEM":
					user.ClientKeyData = base64.StdEncoding.EncodeToString([]byte("invalid key"))
				case "MismatchedKey":
					user.ClientKeyData = base64.StdEncoding.EncodeToString(other.MustGetPrivateKeyPEM())
				case "AuthorityBase64":
					caData = "%%%"
				case "AuthorityPEM":
					caData = base64.StdEncoding.EncodeToString([]byte("invalid authority"))
				}
				kube := &k8sutils.KubeConfig{
					APIVersion: "v1", Kind: "Config", CurrentContext: "selected",
					Clusters: []k8sutils.KubeConfigCluster{{Name: "cluster", Cluster: k8sutils.KubeConfigClusterConfig{
						Server: "https://api.example.com", CertificateAuthorityData: caData,
					}}},
					Users:    []k8sutils.KubeConfigUser{{Name: "user", User: user}},
					Contexts: []k8sutils.KubeConfigContext{{Name: "selected", Context: k8sutils.KubeConfigContextConfig{Cluster: "cluster", User: "user"}}},
				}
				svc := newTestKubeconfigService(t, tst, kube, "")
				got, err := GetClientTLSCfg(t.Context(), svc, nil, sm, &loadbalancer.Upstream{})
				assert.NotNil(t, err)
				assert.Nil(t, got)
			})
		}
	}
}

func TestKubeconfigTLSMutualAuthentication(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	sm, err := secretman.New(t.Context(), tst.C.OcteliumC, nil)
	require.Nil(t, err)
	clientCA, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	serial, err := utils_cert.GenerateSerialNumber()
	require.Nil(t, err)
	clientCert, err := utils_cert.GenerateCertificate(&x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "kubeconfig-client"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, clientCA.Certificate, clientCA.PrivateKey, false)
	require.Nil(t, err)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(clientCA.Certificate)
	for _, customCA := range []bool{false, true} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(fmt.Sprintf("CustomCA%t/TLS%x", customCA, version), func(t *testing.T) {
				backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !assert.NotNil(t, r.TLS) || !assert.NotEmpty(t, r.TLS.PeerCertificates) {
						return
					}
					assert.Equal(t, clientCert.Certificate.Raw, r.TLS.PeerCertificates[0].Raw)
					assert.NotEmpty(t, r.TLS.VerifiedChains)
					w.Write([]byte("authenticated"))
				}))
				backend.TLS = &tls.Config{
					ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
					MinVersion: version, MaxVersion: version,
				}
				backend.StartTLS()
				defer backend.Close()
				kube := &k8sutils.KubeConfig{
					APIVersion: "v1", Kind: "Config", CurrentContext: "selected",
					Clusters: []k8sutils.KubeConfigCluster{{Name: "cluster", Cluster: k8sutils.KubeConfigClusterConfig{Server: backend.URL}}},
					Users: []k8sutils.KubeConfigUser{{Name: "user", User: k8sutils.KubeConfigUserConfig{
						ClientCertificateData: base64.StdEncoding.EncodeToString(clientCert.MustGetCertPEM()),
						ClientKeyData:         base64.StdEncoding.EncodeToString(clientCert.MustGetPrivateKeyPEM()),
					}}},
					Contexts: []k8sutils.KubeConfigContext{{Name: "selected", Context: k8sutils.KubeConfigContextConfig{Cluster: "cluster", User: "user"}}},
				}
				if customCA {
					kube.Clusters[0].Cluster.CertificateAuthorityData = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
						Type: "CERTIFICATE", Bytes: backend.Certificate().Raw,
					}))
				}
				svc := newTestKubeconfigService(t, tst, kube, "")
				cfg, err := GetClientTLSCfg(t.Context(), svc, nil, sm, &loadbalancer.Upstream{})
				require.Nil(t, err)
				require.NotNil(t, cfg)
				require.Len(t, cfg.Certificates, 1)
				assert.False(t, cfg.InsecureSkipVerify)
				if !customCA {
					assert.Nil(t, cfg.RootCAs)
					cfg.RootCAs = x509.NewCertPool()
					cfg.RootCAs.AddCert(backend.Certificate())
				}
				for _, authenticated := range []bool{true, false} {
					clientConfig := cfg.Clone()
					if !authenticated {
						clientConfig.Certificates = nil
					}
					transport := &http.Transport{TLSClientConfig: clientConfig}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
					response, err := client.Get(backend.URL)
					if !authenticated {
						assert.NotNil(t, err)
						assert.Nil(t, response)
						continue
					}
					require.Nil(t, err)
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					require.Nil(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Equal(t, "authenticated", string(body))
					assert.Equal(t, version, response.TLS.Version)
					assert.NotEmpty(t, response.TLS.VerifiedChains)
				}
			})
		}
	}
}

func TestKubeconfigTLSMissingReferences(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	sm, err := secretman.New(t.Context(), tst.C.OcteliumC, nil)
	require.Nil(t, err)
	ca, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	for _, customCA := range []bool{false, true} {
		for _, tc := range []struct {
			name      string
			context   string
			change    func(*k8sutils.KubeConfig)
			kind      string
			reference string
		}{
			{name: "EmptyConfig", change: func(k *k8sutils.KubeConfig) { *k = k8sutils.KubeConfig{} }, kind: "context"},
			{name: "MissingCurrent", change: func(k *k8sutils.KubeConfig) { k.CurrentContext = "missing" }, kind: "context", reference: "missing"},
			{name: "UnsetCurrent", change: func(k *k8sutils.KubeConfig) { k.CurrentContext = "" }, kind: "context"},
			{name: "NoContexts", change: func(k *k8sutils.KubeConfig) { k.Contexts = nil }, kind: "context", reference: "selected"},
			{name: "MissingExplicit", context: "missing", kind: "context", reference: "missing"},
			{name: "MissingCluster", change: func(k *k8sutils.KubeConfig) { k.Contexts[0].Context.Cluster = "missing" }, kind: "cluster", reference: "missing"},
			{name: "NoClusters", change: func(k *k8sutils.KubeConfig) { k.Clusters = nil }, kind: "cluster", reference: "cluster"},
			{name: "EmptyClusterReference", change: func(k *k8sutils.KubeConfig) { k.Contexts[0].Context.Cluster = "" }, kind: "cluster"},
			{name: "MissingUser", change: func(k *k8sutils.KubeConfig) { k.Contexts[0].Context.User = "missing" }, kind: "user", reference: "missing"},
			{name: "NoUsers", change: func(k *k8sutils.KubeConfig) { k.Users = nil }, kind: "user", reference: "user"},
			{name: "EmptyUserReference", change: func(k *k8sutils.KubeConfig) { k.Contexts[0].Context.User = "" }, kind: "user"},
			{name: "ValidCurrent"},
			{name: "ValidExplicitWithoutCurrent", context: "selected", change: func(k *k8sutils.KubeConfig) { k.CurrentContext = "" }},
			{name: "ValidExplicitWithMissingCurrent", context: "selected", change: func(k *k8sutils.KubeConfig) { k.CurrentContext = "missing" }},
			{name: "ValidExplicitIgnoresBrokenContext", context: "selected", change: func(k *k8sutils.KubeConfig) {
				k.CurrentContext = "broken"
				k.Contexts = append(k.Contexts, k8sutils.KubeConfigContext{Name: "broken", Context: k8sutils.KubeConfigContextConfig{Cluster: "missing", User: "missing"}})
			}},
		} {
			t.Run(fmt.Sprintf("CustomCA%t/%s", customCA, tc.name), func(t *testing.T) {
				kube := &k8sutils.KubeConfig{
					APIVersion: "v1", Kind: "Config", CurrentContext: "selected",
					Clusters: []k8sutils.KubeConfigCluster{{Name: "cluster", Cluster: k8sutils.KubeConfigClusterConfig{Server: "https://api.example.com"}}},
					Users:    []k8sutils.KubeConfigUser{{Name: "user", User: k8sutils.KubeConfigUserConfig{Token: "kubeconfig-token"}}},
					Contexts: []k8sutils.KubeConfigContext{{Name: "selected", Context: k8sutils.KubeConfigContextConfig{Cluster: "cluster", User: "user"}}},
				}
				if customCA {
					kube.Clusters[0].Cluster.CertificateAuthorityData = base64.StdEncoding.EncodeToString(ca.MustGetCertPEM())
				}
				if tc.change != nil {
					tc.change(kube)
				}
				svc := newTestKubeconfigService(t, tst, kube, tc.context)
				var got *tls.Config
				var err error
				require.NotPanics(t, func() {
					got, err = GetClientTLSCfg(t.Context(), svc, nil, sm, &loadbalancer.Upstream{})
				})
				if tc.kind == "" {
					require.Nil(t, err)
					require.NotNil(t, got)
					assert.Equal(t, customCA, got.RootCAs != nil)
					assert.Empty(t, got.Certificates)
					assert.False(t, got.InsecureSkipVerify)
					return
				}
				require.Error(t, err)
				assert.Nil(t, got)
				assert.ErrorContains(t, err, "Kubeconfig "+tc.kind)
				assert.ErrorContains(t, err, fmt.Sprintf("%q", tc.reference))
				if tc.kind != "context" {
					assert.ErrorContains(t, err, "context \"selected\"")
				}
				assert.NotContains(t, err.Error(), "kubeconfig-token")
			})
		}
	}
}

func TestKubeconfigTLSReferenceRotation(t *testing.T) {
	ctx := t.Context()
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	sm, err := secretman.New(ctx, tst.C.OcteliumC, nil)
	require.Nil(t, err)
	ca, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	crt, err := utils_cert.GenerateCertificateTmp("client", ca, false)
	require.Nil(t, err)
	for _, customCA := range []bool{false, true} {
		t.Run(fmt.Sprintf("CustomCA%t", customCA), func(t *testing.T) {
			kube := &k8sutils.KubeConfig{
				APIVersion: "v1", Kind: "Config", CurrentContext: "selected",
				Clusters: []k8sutils.KubeConfigCluster{{Name: "cluster", Cluster: k8sutils.KubeConfigClusterConfig{Server: "https://api.example.com"}}},
				Users: []k8sutils.KubeConfigUser{{Name: "user", User: k8sutils.KubeConfigUserConfig{
					ClientCertificateData: base64.StdEncoding.EncodeToString(crt.MustGetCertPEM()),
					ClientKeyData:         base64.StdEncoding.EncodeToString(crt.MustGetPrivateKeyPEM()),
				}}},
				Contexts: []k8sutils.KubeConfigContext{{Name: "selected", Context: k8sutils.KubeConfigContextConfig{Cluster: "cluster", User: "user"}}},
			}
			if customCA {
				kube.Clusters[0].Cluster.CertificateAuthorityData = base64.StdEncoding.EncodeToString(ca.MustGetCertPEM())
			}
			original, err := kube.MarshalToYAML()
			require.Nil(t, err)
			svc := newTestKubeconfigService(t, tst, kube, "selected")
			secret, err := sm.GetByName(ctx, svc.Spec.Config.GetKubernetes().GetKubeconfig().GetFromSecret())
			require.Nil(t, err)
			cfg, err := GetClientTLSCfg(ctx, svc, nil, sm, &loadbalancer.Upstream{})
			require.Nil(t, err)
			require.NotNil(t, cfg)
			require.Len(t, cfg.Certificates, 1)
			rotate := func(t *testing.T, data []byte) {
				t.Helper()
				next := pbutils.Clone(secret).(*corev1.Secret)
				next.Data = &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: string(data)}}
				previous := sm.Generation()
				secret, err = tst.C.OcteliumC.CoreC().UpdateSecret(ctx, next)
				require.Nil(t, err)
				sm.Set(secret)
				assert.Greater(t, sm.Generation(), previous)
			}
			for _, tc := range []struct {
				kind   string
				change func(*k8sutils.KubeConfig)
			}{
				{kind: "context", change: func(k *k8sutils.KubeConfig) { k.Contexts = nil }},
				{kind: "cluster", change: func(k *k8sutils.KubeConfig) { k.Clusters = nil }},
				{kind: "user", change: func(k *k8sutils.KubeConfig) { k.Users = nil }},
			} {
				t.Run(tc.kind, func(t *testing.T) {
					next, err := k8sutils.UnmarshalKubeConfigFromYAML(original)
					require.Nil(t, err)
					tc.change(next)
					data, err := next.MarshalToYAML()
					require.Nil(t, err)
					rotate(t, data)
					var got *tls.Config
					require.NotPanics(t, func() { got, err = GetClientTLSCfg(ctx, svc, nil, sm, &loadbalancer.Upstream{}) })
					require.ErrorContains(t, err, "Kubeconfig "+tc.kind)
					assert.Nil(t, got)
					rotate(t, original)
					got, err = GetClientTLSCfg(ctx, svc, nil, sm, &loadbalancer.Upstream{})
					require.Nil(t, err)
					require.NotNil(t, got)
					require.Len(t, got.Certificates, 1)
					assert.Equal(t, crt.Certificate.Raw, got.Certificates[0].Certificate[0])
					assert.Equal(t, customCA, got.RootCAs != nil)
					assert.False(t, got.InsecureSkipVerify)
				})
			}
		})
	}
}
