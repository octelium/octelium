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

package genesis

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"time"

	netv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/clusterconfig"
	oc "github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/jwkctl/jwkutils"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (g *Genesis) RunInit(ctx context.Context) error {
	zap.L().Info("Starting initializing the Cluster")

	if err := waitForNodesReadiness(ctx, g.k8sC); err != nil {
		return err
	}

	if err := g.setNamespace(ctx); err != nil {
		return err
	}

	/*
		if err := g.moveRegcred(ctx); err != nil {
			return err
		}
	*/

	initResources, err := g.loadClusterInitResources(ctx, "default")
	if err != nil {
		return err
	}

	bootstrap := initResources.Bootstrap

	region, err := g.initRegion(initResources)
	if err != nil {
		return err
	}

	zap.L().Debug("Loaded Cluster resources",
		//zap.Any("bootstrap", bootstrap),
		zap.Any("region", region))

	clusterCfg, err := g.initClusterConfig(ctx, bootstrap, initResources.Domain)
	if err != nil {
		return err
	}

	iCtx := &genesisutils.InstallCtx{
		ClusterConfig: clusterCfg,
		Region:        region,
		Bootstrap:     bootstrap,
	}

	if err := g.initStorage(ctx, iCtx); err != nil {
		return err
	}

	{
		rscSrv, err := rscserver.NewServer(ctx, nil)
		if err != nil {
			return err
		}

		if _, err := rscSrv.GetDB().ExecContext(ctx, `TRUNCATE TABLE octelium_resources`); err != nil {
			zap.L().Warn("Could not truncate the octelium_resources table", zap.Error(err))
		}

		redisC := rscSrv.GetRedisC()
		if err := redisC.FlushDB(ctx).Err(); err != nil {
			zap.L().Debug("Could not do Redis flushDB. Trying to manually delete keys", zap.Error(err))

			keys, err := redisC.Keys(ctx, "*").Result()
			if err == nil {
				if len(keys) > 0 {
					if err := redisC.Del(ctx, keys...).Err(); err != nil {
						zap.L().Warn("Could not delete Redis database keys", zap.Error(err))
					}
				}
			} else {
				zap.L().Warn("Could not fetch current Redis keys", zap.Error(err))
			}
		}

		clusterCfgI, err := rscSrv.CreateResource(ctx,
			clusterCfg, ucorev1.API, ucorev1.Version, ucorev1.KindClusterConfig)
		if err != nil {
			return err
		}

		iCtx.ClusterConfig = clusterCfgI.(*corev1.ClusterConfig)

		regionI, err := rscSrv.CreateResource(ctx,
			region, ucorev1.API, ucorev1.Version, ucorev1.KindRegion)
		if err != nil {
			return err
		}
		iCtx.Region = regionI.(*corev1.Region)
	}

	zap.L().Debug("creating rscServer")

	if ldflags.IsTest() {
		os.Setenv("OCTELIUM_TEST_RSCSERVER_PORT", "25432")
		// os.Setenv("OCTELIUM_POSTGRES_DATABASE", "octelium")
		rscSrv, err := rscserver.NewServer(ctx, nil)
		if err != nil {
			return err
		}

		zap.L().Debug("Running rscServer")
		err = rscSrv.Run(ctx)
		if err != nil {
			return err
		}
	} else {
		if err := components.CreateRscServer(ctx, g.k8sC, clusterCfg); err != nil {
			return err
		}

		zap.L().Debug("Waiting for readiness of rscServer")

		if err := checkRscServer(ctx, g.k8sC); err != nil {
			return err
		}
	}

	zap.L().Debug("rscServer is now running")

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	g.octeliumC = octeliumC

	if err := g.createUsersGroups(ctx, clusterCfg); err != nil {
		return err
	}

	if err := g.createSSHCA(ctx); err != nil {
		return err
	}

	if err := g.createAESKey(ctx); err != nil {
		return err
	}

	if _, err := jwkutils.CreateJWKSecret(ctx, octeliumC); err != nil {
		return err
	}

	if err := g.installComponents(ctx, region); err != nil {
		return err
	}

	if err := g.setNadConfig(ctx); err != nil {
		return err
	}

	if err := g.setConnInfoConfig(ctx); err != nil {
		return err
	}

	if err := g.installOcteliumResources(ctx, clusterCfg, iCtx.Region); err != nil {
		return err
	}

	if err := g.setInitClusterCertificate(ctx, clusterCfg); err != nil {
		return err
	}

	if err := g.installBuiltinPolicies(ctx); err != nil {
		zap.L().Warn("Could not install builtin Policies", zap.Error(err))
	}

	if err := g.createInitAuthenticationToken(ctx); err != nil {
		return err
	}

	/*
		if err := g.setGlobalConfigMap(ctx, clusterCfg, region); err != nil {
			return err
		}
	*/

	if err := g.setBootstrapSecret(ctx, bootstrap); err != nil {
		return err
	}

	if err := g.moveClusterInitResources(ctx); err != nil {
		zap.L().Error("Could not move octelium-init", zap.Error(err))
	}

	zap.L().Info("Successfully initialized the Cluster")

	return nil
}

func (g *Genesis) setInitClusterCertificate(ctx context.Context, clusterCfg *corev1.ClusterConfig) error {

	now := time.Now()
	domain := clusterCfg.Status.Domain

	root, err := utils_cert.GenerateCARootFromCert(&x509.Certificate{
		NotBefore: now,
		NotAfter:  now.Add(10 * 365 * 24 * time.Hour),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("Octelium %s Root CA", domain),
		},
	})
	if err != nil {
		return err
	}

	serialNumber, err := utils_cert.GenerateSerialNumber()
	if err != nil {
		return err
	}

	sans := []string{
		domain,
		fmt.Sprintf("*.%s", domain),

		fmt.Sprintf("*.octelium.%s", domain),
		fmt.Sprintf("*.octelium-api.%s", domain),

		fmt.Sprintf("*.local.%s", domain),
		fmt.Sprintf("*.default.%s", domain),
		fmt.Sprintf("*.default.local.%s", domain),

		fmt.Sprintf("*.octelium.local.%s", domain),
		fmt.Sprintf("*.octelium-api.local.%s", domain),
	}

	caCert := &x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: sans,

		NotBefore:   now,
		NotAfter:    now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	initCrt, err := utils_cert.GenerateCertificate(caCert, root.Certificate, root.PrivateKey, false)
	if err != nil {
		return err
	}

	zap.L().Debug("Setting initial Cluster Certificate",
		zap.String("domain", domain),
		zap.Strings("sans", sans))

	chainPEM := new(bytes.Buffer)

	if err := utils_cert.EncodePEMCertificate(chainPEM, initCrt.Certificate); err != nil {
		return err
	}

	if err := utils_cert.EncodePEMCertificate(chainPEM, root.Certificate); err != nil {
		return err
	}

	privPEM, err := initCrt.GetPrivateKeyPEM()
	if err != nil {
		return err
	}

	crt := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: vutils.ClusterCertSecretName,

			IsSystem:       true,
			IsSystemHidden: true,
			IsUserHidden:   true,
			SystemLabels: map[string]string{
				"octelium-cert": "true",
			},
		},

		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
	}

	ucorev1.ToSecret(crt).SetCertificate(chainPEM.String(), privPEM)

	_, err = g.octeliumC.CoreC().CreateSecret(ctx, crt)
	if err != nil {
		return err
	}

	return nil
}

func (g *Genesis) setBootstrapSecret(ctx context.Context, bs *cbootstrapv1.Config) error {

	zap.L().Debug("Setting Bootstrap Secret")

	bootstrapPB, err := pbutils.Marshal(bs)
	if err != nil {
		return err
	}

	crt := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: "sys:bootstrap-config",

			IsSystem:       true,
			IsSystemHidden: true,
			IsUserHidden:   true,
		},

		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{
				ValueBytes: bootstrapPB,
			},
		},
	}

	_, err = g.octeliumC.CoreC().CreateSecret(ctx, crt)
	if err != nil {
		return err
	}

	return nil
}

func (g *Genesis) installOcteliumResources(ctx context.Context, clusterCfg *corev1.ClusterConfig, region *corev1.Region) error {
	zap.L().Debug("Installing Octelium resources")

	if err := k8sutils.WaitReadinessDeployment(ctx, g.k8sC, "octelium-nocturne"); err != nil {
		return err
	}

	zap.L().Debug("Creating system Namespaces and Services")

	if err := genesisutils.CreateOrUpdateNamespace(ctx, g.octeliumC, &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name:        "default",
			IsSystem:    true,
			DisplayName: "Default Namespace",
		},
		Spec:   &corev1.Namespace_Spec{},
		Status: &corev1.Namespace_Status{},
	}); err != nil {
		return err
	}

	if err := genesisutils.CreateOrUpdateNamespace(ctx, g.octeliumC, &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name:         "octelium",
			IsSystem:     true,
			IsUserHidden: true,
		},
		Spec:   &corev1.Namespace_Spec{},
		Status: &corev1.Namespace_Status{},
	}); err != nil {
		return err
	}

	if err := genesisutils.CreateOrUpdateNamespace(ctx, g.octeliumC, &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name:         "octelium-api",
			IsSystem:     true,
			IsUserHidden: true,
		},
		Spec:   &corev1.Namespace_Spec{},
		Status: &corev1.Namespace_Status{},
	}); err != nil {
		return err
	}

	{
		dnsService := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name:         "dns.octelium",
				IsSystem:     true,
				IsUserHidden: true,
				DisplayName:  "The Cluster DNS Server",
			},
			Spec: &corev1.Service_Spec{
				Port: 53,
				Mode: corev1.Service_Spec_DNS,

				Authorization: &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{
				ManagedService: &corev1.Service_Status_ManagedService{
					Image: oc.GetImage(oc.DNSServer, ""),
					Type:  "dnsserver",
					HealthCheck: &corev1.Service_Status_ManagedService_HealthCheck{
						Type: &corev1.Service_Status_ManagedService_HealthCheck_Grpc{
							Grpc: &corev1.Service_Status_ManagedService_HealthCheck_GRPC{
								Port: vutils.HealthCheckPortManagedService,
							},
						},
					},
				},
			},
		}

		if err := genesisutils.CreateOrUpdateService(ctx, g.octeliumC, dnsService); err != nil {
			return err
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name:         "default.octelium-api",
				IsSystem:     true,
				IsUserHidden: true,
				SystemLabels: map[string]string{
					"octelium-apiserver": "true",
					"apiserver-path":     "/octelium.api.main.core, /octelium.api.main.user",
				},
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_GRPC,

				Authorization: &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{

									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_Match{
												Match: `ctx.request.grpc.serviceFullName == "octelium.api.main.user.v1.MainService"`,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{

				ManagedService: &corev1.Service_Status_ManagedService{
					Type:  "apiserver",
					Image: oc.GetImage(oc.APIServer, ""),
					HealthCheck: &corev1.Service_Status_ManagedService_HealthCheck{
						Type: &corev1.Service_Status_ManagedService_HealthCheck_Grpc{
							Grpc: &corev1.Service_Status_ManagedService_HealthCheck_GRPC{
								Port: vutils.HealthCheckPortManagedService,
							},
						},
					},
				},
			},
		}

		if err := genesisutils.CreateOrUpdateService(ctx, g.octeliumC, svc); err != nil {
			return err
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name:         "auth.octelium-api",
				IsSystem:     true,
				IsUserHidden: true,
				SystemLabels: map[string]string{
					"octelium-apiserver": "true",
					"apiserver-path":     "/octelium.api.main.auth",
				},
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_GRPC,

				IsAnonymous: true,
			},
			Status: &corev1.Service_Status{
				ManagedService: &corev1.Service_Status_ManagedService{
					Type:  "apiserver",
					Image: oc.GetImage(oc.AuthServer, ""),
					Args:  []string{"grpc"},
					HealthCheck: &corev1.Service_Status_ManagedService_HealthCheck{
						Type: &corev1.Service_Status_ManagedService_HealthCheck_Grpc{
							Grpc: &corev1.Service_Status_ManagedService_HealthCheck_GRPC{
								Port: vutils.HealthCheckPortManagedService,
							},
						},
					},
				},
			},
		}

		if err := genesisutils.CreateOrUpdateService(ctx, g.octeliumC, svc); err != nil {
			return err
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name:         "default.default",
				IsSystem:     true,
				IsUserHidden: true,
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_WEB,

				IsAnonymous: true,
			},
			Status: &corev1.Service_Status{
				ManagedService: &corev1.Service_Status_ManagedService{
					Image: oc.GetImage(oc.AuthServer, ""),
					Args:  []string{"http"},
					Type:  "authserver",
					HealthCheck: &corev1.Service_Status_ManagedService_HealthCheck{
						Type: &corev1.Service_Status_ManagedService_HealthCheck_Grpc{
							Grpc: &corev1.Service_Status_ManagedService_HealthCheck_GRPC{
								Port: vutils.HealthCheckPortManagedService,
							},
						},
					},
				},
			},
		}

		if err := genesisutils.CreateOrUpdateService(ctx, g.octeliumC, svc); err != nil {
			return err
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name:         "portal.default",
				IsSystem:     true,
				IsUserHidden: true,
				DisplayName:  "Octelium Portal Dashboard",
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_WEB,

				Authorization: &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{

									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_Match{
												Match: `ctx.user.spec.type == "HUMAN"`,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{
				ManagedService: &corev1.Service_Status_ManagedService{
					Image: oc.GetImage(oc.Portal, ""),
					HealthCheck: &corev1.Service_Status_ManagedService_HealthCheck{
						Type: &corev1.Service_Status_ManagedService_HealthCheck_Grpc{
							Grpc: &corev1.Service_Status_ManagedService_HealthCheck_GRPC{
								Port: vutils.HealthCheckPortManagedService,
							},
						},
					},
				},
			},
		}

		if err := genesisutils.CreateOrUpdateService(ctx, g.octeliumC, svc); err != nil {
			return err
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name:        "demo-nginx.default",
				DisplayName: "Demo nginx",
				Description: "A Demo nginx server that is deployed as a managed container and accessible by all Users",
			},
			Spec: &corev1.Service_Spec{
				IsPublic: true,
				Mode:     corev1.Service_Spec_WEB,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Container_{
							Container: &corev1.Service_Spec_Config_Upstream_Container{
								Image: "nginx",
								Port:  80,
							},
						},
					},
				},
				Authorization: &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}

		if err := genesisutils.CreateOrUpdateService(ctx, g.octeliumC, svc); err != nil {
			return err
		}
	}

	return nil
}

func (g *Genesis) setConnInfoConfig(ctx context.Context) error {
	zap.L().Debug("Initializing Connection info Config")

	attrs, err := pbutils.MessageToStruct(&cclusterv1.ClusterConnInfo{})
	if err != nil {
		return err
	}

	_, err = g.octeliumC.CoreC().CreateConfig(ctx, &corev1.Config{
		Metadata: &metav1.Metadata{
			Name:           "sys:conn-info",
			IsSystem:       true,
			IsSystemHidden: true,
			IsUserHidden:   true,
		},
		Spec:   &corev1.Config_Spec{},
		Status: &corev1.Config_Status{},
		Data: &corev1.Config_Data{
			Type: &corev1.Config_Data_Attrs{
				Attrs: attrs,
			},
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (g *Genesis) setNadConfig(ctx context.Context) error {

	nad := &netv1.NetworkAttachmentDefinition{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      "octelium",
			Namespace: vutils.K8sNS,
		},
	}

	zap.L().Debug("Setting k8s NAD configuration", zap.Any("nad", nad))

	_, err := g.nadC.K8sCniCncfIoV1().NetworkAttachmentDefinitions(vutils.K8sNS).
		Create(ctx, nad, k8smetav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (g *Genesis) initClusterConfig(ctx context.Context, bootstrap *cbootstrapv1.Config, domain string) (*corev1.ClusterConfig, error) {
	zap.L().Debug("Initializing Cluster configuration")

	v6Prefix, err := utilrand.GetRandomBytes(2)
	if err != nil {
		return nil, err
	}

	v6Prefix = append(v6Prefix, make([]byte, 2)...)

	clusterCfg := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{
			Name:     "default",
			IsSystem: true,
		},
		Spec: &corev1.ClusterConfig_Spec{},
		Status: &corev1.ClusterConfig_Status{
			Domain: domain,
			Network: &corev1.ClusterConfig_Status_Network{
				ClusterNetwork: &metav1.DualStackNetwork{},
				WgConnSubnet:   &metav1.DualStackNetwork{},
				QuicConnSubnet: &metav1.DualStackNetwork{},
			},
		},
	}

	if bootstrap.Spec.Network != nil {
		clusterCfg.Status.NetworkConfig = &corev1.ClusterConfig_Status_NetworkConfig{}
		if err := pbutils.MarshalInto(clusterCfg.Status.NetworkConfig, bootstrap.Spec.Network); err != nil {
			return nil, err
		}
	}

	clusterCfg.Status.Network.V6RangePrefix = v6Prefix
	if err := clusterconfig.SetClusterSubnets(clusterCfg); err != nil {
		return nil, err
	}

	zap.L().Debug("Initialized ClusterConfig", zap.Any("cc", clusterCfg))

	return clusterCfg, nil
}

func (g *Genesis) initStorage(ctx context.Context, i *genesisutils.InstallCtx) error {

	if i.Bootstrap == nil || i.Bootstrap.Spec == nil {
		return errors.Errorf("Nil Bootstrap")
	}
	if i.Bootstrap.Spec.PrimaryStorage == nil || i.Bootstrap.Spec.PrimaryStorage.GetPostgresql() == nil {
		return errors.Errorf("No Postgres info")
	}
	if i.Bootstrap.Spec.SecondaryStorage == nil || i.Bootstrap.Spec.SecondaryStorage.GetRedis() == nil {
		return errors.Errorf("No Redis info")
	}
	zap.L().Debug("Initializing storage secrets")

	{

		info := i.Bootstrap.Spec.PrimaryStorage.GetPostgresql()

		dataMap := map[string][]byte{
			"postgres-password": []byte(info.Password),
			"username":          []byte(info.Username),
			"host":              []byte(info.Host),
			"database":          []byte(info.Database),
			"port":              []byte(fmt.Sprintf("%d", info.Port)),
			"no_ssl":            []byte(fmt.Sprintf("%t", !info.IsTLS)),
		}

		if err := g.createPostgresSecret(ctx, dataMap); err != nil {
			return err
		}

	}

	{
		info := i.Bootstrap.Spec.SecondaryStorage.GetRedis()
		dataMap := map[string][]byte{
			"password": []byte(info.Password),
			"username": []byte(info.Username),
			"host":     []byte(info.Host),
			"database": []byte(fmt.Sprintf("%d", info.Database)),
			"port":     []byte(fmt.Sprintf("%d", info.Port)),
			"use_tls":  []byte(fmt.Sprintf("%t", info.IsTLS)),
		}

		if err := g.createRedisSecret(ctx, dataMap); err != nil {
			return err
		}
	}

	g.setDBEnvVars(i)

	return nil
}

func (g *Genesis) createSSHCA(ctx context.Context) error {
	zap.L().Debug("Creating the SSH CA secret")

	ecdsaKey, err := utils_cert.GenerateECDSA()
	if err != nil {
		return err
	}

	privPEM, err := ecdsaKey.GetPrivateKeyPEM()
	if err != nil {
		return err
	}

	_, err = g.octeliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name:           "sys:ssh-ca",
			IsSystem:       true,
			IsSystemHidden: true,
			IsUserHidden:   true,
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{
				ValueBytes: []byte(privPEM),
			},
		},
	})
	if err != nil {
		return err
	}

	zap.L().Debug("Successfully created SSH CA Secret")

	return nil
}

func (g *Genesis) createAESKey(ctx context.Context) error {

	secretVal, err := utilrand.GetRandomBytes(32)
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("sys:aes256-key-%s", utilrand.GetRandomStringLowercase(8)),
			SystemLabels: map[string]string{
				"aes256-key": "true",
			},
			IsSystem:       true,
			IsSystemHidden: true,
			IsUserHidden:   true,
		},

		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},

		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{
				ValueBytes: secretVal,
			},
		},
	}

	if _, err := g.octeliumC.CoreC().CreateSecret(ctx, secret); err != nil {
		return err
	}

	return nil
}

func (g *Genesis) createInitAuthenticationToken(ctx context.Context) error {
	zap.L().Debug("Creating the initial root authentication token")

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  g.octeliumC,
		IsEmbedded: true,
	})

	cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name:        "root-init",
			Description: `This is the initial authentication token used upon the Cluster installation. You might want to delete it once you have added your own Users and other resources`,
		},
		Spec: &corev1.Credential_Spec{
			User:        "root",
			Type:        corev1.Credential_Spec_AUTH_TOKEN,
			ExpiresAt:   pbutils.Timestamp(time.Now().Add(30 * 24 * time.Hour)),
			SessionType: corev1.Session_Status_CLIENT,
			Authorization: &corev1.Credential_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Name: "first-session-allow-all",
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	tkn, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
		CredentialRef: umetav1.GetObjectReference(cred),
	})
	if err != nil {
		return err
	}

	_, err = g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      "init-token",
			Namespace: vutils.K8sNS,
		},
		Data: map[string][]byte{
			"data": []byte(tkn.GetAuthenticationToken().AuthenticationToken),
		},
	}, k8smetav1.CreateOptions{})
	if err != nil {
		return err
	}

	zap.L().Debug("Successfully created the root User initial authentication token")

	return nil
}

func (g *Genesis) setNamespace(ctx context.Context) error {
	zap.L().Debug("Initializing the octelium k8s namespace")

	if _, err := g.k8sC.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{}); err == nil {
		zap.L().Debug("Deleting existent octelium namespace")
		if err := g.k8sC.CoreV1().Namespaces().Delete(ctx, vutils.K8sNS, k8smetav1.DeleteOptions{}); err != nil {
			return err
		}

		if err := func() error {
			for i := 0; i < 1000; i++ {
				_, err := g.k8sC.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{})
				if err != nil && k8serr.IsNotFound(err) {
					return nil
				}
				zap.L().Debug("octelium namespace is still deleting. Trying again...")
				time.Sleep(3 * time.Second)
			}
			return errors.Errorf("Could not delete octelium namespace")
		}(); err != nil {
			return err
		}
	} else if !k8serr.IsNotFound(err) {
		return err
	}

	zap.L().Debug("Creating octelium namespace")
	_, err := g.k8sC.CoreV1().Namespaces().Create(ctx, &k8scorev1.Namespace{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: vutils.K8sNS,
			Labels: map[string]string{
				"app": "octelium",
			},
		},
		Spec: k8scorev1.NamespaceSpec{},
	}, k8smetav1.CreateOptions{})
	return err
}

func (g *Genesis) moveK8SSecret(ctx context.Context, secFrom *k8scorev1.Secret) error {
	var err error
	sec := &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      secFrom.Name,
			Namespace: vutils.K8sNS,
		},
		Data:       secFrom.Data,
		StringData: secFrom.StringData,
		Type:       secFrom.Type,
	}

	_, err = g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, sec, k8smetav1.CreateOptions{})
	if err != nil {
		return err
	}

	g.k8sC.CoreV1().Secrets(secFrom.Namespace).Delete(ctx, secFrom.Name, k8smetav1.DeleteOptions{})

	return nil
}

func (g *Genesis) createUsersGroups(ctx context.Context, clusterCfg *corev1.ClusterConfig) error {

	var err error

	rootUser := &corev1.User{
		Metadata: &metav1.Metadata{
			Name: "root",
		},

		Spec: &corev1.User_Spec{
			Type: corev1.User_Spec_WORKLOAD,
		},
	}

	_, err = g.octeliumC.CoreC().CreateUser(ctx, rootUser)
	if err != nil {
		return err
	}

	{

		usr := &corev1.User{
			Metadata: &metav1.Metadata{
				Name:     "octelium",
				IsSystem: true,
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_WORKLOAD,
			},
		}
		_, err = g.octeliumC.CoreC().CreateUser(ctx, usr)
		if err != nil {
			return err
		}

	}

	return nil
}

func (g *Genesis) setDBEnvVars(i *genesisutils.InstallCtx) {
	zap.L().Debug("Setting postgres and redis env vars")

	if ldflags.IsTest() {
		os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
		os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
		os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
		os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")
		return
	}

	pgOpts := i.Bootstrap.Spec.PrimaryStorage.GetPostgresql()

	if pgOpts.Database != "" {
		os.Setenv("OCTELIUM_POSTGRES_DATABASE", pgOpts.Database)
	}

	if pgOpts.Username != "" {
		os.Setenv("OCTELIUM_POSTGRES_USERNAME", pgOpts.Username)
	}

	if pgOpts.Password != "" {
		os.Setenv("OCTELIUM_POSTGRES_PASSWORD", pgOpts.Password)
	}

	if !pgOpts.IsTLS {
		os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
	}

	if pgOpts.Host != "" {
		os.Setenv("OCTELIUM_POSTGRES_HOST", pgOpts.Host)
	}

	if pgOpts.Port != 0 {
		os.Setenv("OCTELIUM_POSTGRES_PORT", fmt.Sprintf("%d", pgOpts.Port))
	}

	redisOpts := i.Bootstrap.Spec.SecondaryStorage.GetRedis()
	if redisOpts.Database != 0 {
		os.Setenv("OCTELIUM_REDIS_DATABASE", fmt.Sprintf("%d", redisOpts.Database))
	}

	if redisOpts.Username != "" {
		os.Setenv("OCTELIUM_REDIS_USERNAME", redisOpts.Username)
	}

	if redisOpts.Password != "" {
		os.Setenv("OCTELIUM_REDIS_PASSWORD", redisOpts.Password)
	}

	if redisOpts.Host != "" {
		os.Setenv("OCTELIUM_REDIS_HOST", redisOpts.Host)
	}

	if redisOpts.Port != 0 {
		os.Setenv("OCTELIUM_REDIS_PORT", fmt.Sprintf("%d", redisOpts.Port))
	}

	if redisOpts.IsTLS {
		os.Setenv("OCTELIUM_REDIS_USE_TLS", "true")
	}
}

func (g *Genesis) loadClusterInitResources(ctx context.Context, ns string) (*LoadedClusterResource, error) {
	if ns == "" {
		ns = "default"
	}
	zap.L().Debug("Loading Cluster resources")
	ret := &LoadedClusterResource{}
	sec, err := g.k8sC.CoreV1().Secrets(ns).Get(ctx, "octelium-init", k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	bootstrap := &cbootstrapv1.Config{}

	if sec.Data["bootstrap"] != nil {
		if err := pbutils.Unmarshal(sec.Data["bootstrap"], bootstrap); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.Errorf("Could not find bootstrap field")
	}
	ret.Bootstrap = bootstrap

	if sec.Data["region"] != nil {
		region := &corev1.Region{}
		if err := pbutils.Unmarshal(sec.Data["region"], region); err != nil {
			return nil, err
		}
		ret.Region = region
	}

	if sec.Data["domain"] != nil {
		ret.Domain = string(sec.Data["domain"])
	}

	return ret, nil
}

func (g *Genesis) moveClusterInitResources(ctx context.Context) error {

	sec, err := g.k8sC.CoreV1().Secrets("default").Get(ctx, "octelium-init", k8smetav1.GetOptions{})
	if err != nil {
		return err
	}

	return g.moveK8SSecret(ctx, sec)
}
