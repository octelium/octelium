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
	"crypto/x509"
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
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
