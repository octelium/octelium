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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	netv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/clusterconfig"
	oc "github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type InitOpts struct{}

func (g *Genesis) RunInit(ctx context.Context, o *InitOpts) error {
	zap.L().Info("Starting initializing the Cluster")
	if o == nil {
		o = &InitOpts{}
	}

	if err := waitForNodesReadiness(ctx, g.k8sC); err != nil {
		return err
	}

	initResources, err := g.loadInitializationInput(ctx)
	if err != nil {
		return err
	}
	if initResources.Bootstrap.GetSpec().GetPrimaryStorage().GetPostgresql() == nil ||
		initResources.Bootstrap.GetSpec().GetSecondaryStorage().GetRedis() == nil {
		return errors.Errorf("The bootstrap must contain PostgreSQL and Redis storage configuration")
	}
	if err := g.waitForConcurrentGenesis(ctx); err != nil {
		return err
	}
	init, err := g.prepareInitializationWithPreflight(ctx, initResources, func(ctx context.Context, passwords *storagePasswords) error {
		if g.pod != nil && g.pod.Annotations[initializationInputHashKey] != "" {
			hash, err := initializationInputHash(initResources)
			if err != nil {
				return err
			}
			if initializationInputBinding(hash, g.inputBindingKey) != g.pod.Annotations[initializationInputHashKey] {
				return errors.New("The bootstrap no longer matches the submitted initialization")
			}
		}
		return preflightInitializationStorage(ctx, initResources.Bootstrap, passwords)
	})
	if err != nil {
		return err
	}
	g.initializationID = init.id
	if init.complete {
		_, err := g.getInitAuthenticationToken(ctx)
		return err
	}

	if err := g.initStorageWithPasswords(ctx, &genesisutils.InstallCtx{Bootstrap: initResources.Bootstrap}, init.passwords); err != nil {
		return err
	}
	rscSrv, err := rscserver.NewServer(ctx, nil)
	if err != nil {
		return err
	}
	defer rscSrv.Stop()
	unlock, err := lockInitialization(ctx, rscSrv.GetDB())
	if err != nil {
		return err
	}
	defer unlock()

	iCtx, err := initializeClusterResources(ctx, rscSrv, init)
	if err != nil {
		return err
	}
	iCtx.Bootstrap = initResources.Bootstrap
	clusterCfg := iCtx.ClusterConfig
	region := iCtx.Region
	if _, err := g.getInitAuthenticationToken(ctx); err == nil {
		return g.completeInitialization(ctx, init)
	} else if !k8serr.IsNotFound(err) {
		return err
	}

	if err := g.reconcileInstallationTarget(ctx, clusterCfg, region, false); err != nil {
		return err
	}
	if err := g.setInstallationConfigMap(ctx, clusterCfg); err != nil {
		return err
	}
	if err := g.reconcileInstallationTarget(ctx, clusterCfg, region, true); err != nil {
		return err
	}
	if err := g.setDataPlaneNodeTaints(ctx); err != nil {
		return err
	}

	zap.L().Debug("creating rscServer")

	if ldflags.IsTest() {
		if g.rscServer == nil {
			if os.Getenv("OCTELIUM_TEST_RSCSERVER_PORT") == "" {
				os.Setenv("OCTELIUM_TEST_RSCSERVER_PORT", "25432")
			}
			g.rscServer, err = rscserver.NewServer(ctx, nil)
			if err != nil {
				return err
			}
			if err := g.rscServer.Run(ctx); err != nil {
				g.rscServer.Stop()
				g.rscServer = nil
				return err
			}
		}
	} else {
		if err := components.CreateRscServer(ctx, &components.CommonOpts{
			K8sC:          g.k8sC,
			ClusterConfig: clusterCfg,
		}); err != nil {
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

	vutils.SetRegionPublicHostName(iCtx.Region)
	iCtx.Region, err = g.octeliumC.CoreC().UpdateRegion(ctx, iCtx.Region)
	if err != nil {
		return err
	}

	if err := g.createUsersGroups(ctx, clusterCfg); err != nil {
		return err
	}

	if err := g.createSSHCA(ctx); err != nil {
		return err
	}

	if err := g.createSSHServiceSeedSecret(ctx); err != nil {
		return err
	}

	if err := g.createAESKey(ctx, init.aesKeyName); err != nil {
		return err
	}

	if _, err := jwkctl.NewJWKController(ctx, octeliumC, nil); err != nil {
		return err
	}

	if err := g.installComponents(ctx,
		region, &components.CommonOpts{
			K8sC:          g.k8sC,
			ClusterConfig: clusterCfg,
		}); err != nil {
		return err
	}

	if err := g.setNadConfig(ctx); err != nil {
		return err
	}

	if err := g.setConnInfoConfig(ctx); err != nil {
		return err
	}

	if err := g.installOcteliumResources(ctx, clusterCfg, iCtx.Region, true); err != nil {
		return err
	}

	if err := g.setInitClusterCertificate(ctx, clusterCfg); err != nil {
		return err
	}

	if err := g.installBuiltinPolicies(ctx); err != nil {
		return err
	}

	if err := g.setBootstrapSecret(ctx, initResources.Bootstrap); err != nil {
		return err
	}
	if err := g.moveClusterInitResources(ctx); err != nil {
		return err
	}
	if err := g.createInitAuthenticationToken(ctx); err != nil {
		return err
	}
	if err := g.completeInitialization(ctx, init); err != nil {
		return err
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

	_, err = createInitResource(ctx, crt, g.octeliumC.CoreC().GetSecret, g.octeliumC.CoreC().CreateSecret)
	if err != nil {
		return err
	}

	return nil
}

func getInstallationFromBootstrap(bs *cbootstrapv1.Config) (*corev1.ClusterConfig_Status_Installation, error) {
	spec := bs.GetSpec()
	if spec.GetSpiffe() == nil && spec.GetCni() == nil && spec.GetIngress() == nil {
		return nil, nil
	}

	ret := &corev1.ClusterConfig_Status_Installation{}

	if spec.GetSpiffe() != nil {
		ret.Spiffe = &corev1.ClusterConfig_Status_Installation_SPIFFE{}
		if err := pbutils.MarshalInto(ret.Spiffe, spec.GetSpiffe()); err != nil {
			return nil, err
		}
	}

	if spec.GetCni() != nil {
		ret.Cni = &corev1.ClusterConfig_Status_Installation_CNI{}
		if err := pbutils.MarshalInto(ret.Cni, spec.GetCni()); err != nil {
			return nil, err
		}
	}

	if spec.GetIngress() != nil {
		ret.Ingress = &corev1.ClusterConfig_Status_Installation_Ingress{}
		if err := pbutils.MarshalInto(ret.Ingress, spec.GetIngress()); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

const installationConfigMapName = "octelium-installation"
const installationConfigMapKey = "installation.json"

func (g *Genesis) setInstallationConfigMap(ctx context.Context, clusterCfg *corev1.ClusterConfig) error {

	installation := clusterCfg.Status.Installation
	if installation == nil {
		installation = &corev1.ClusterConfig_Status_Installation{}
	}

	val, err := pbutils.MarshalJSON(installation, true)
	if err != nil {
		return err
	}

	cm := &k8scorev1.ConfigMap{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      installationConfigMapName,
			Namespace: vutils.K8sNS,
			Labels: map[string]string{
				"app": "octelium",
			},
		},
		Data: map[string]string{
			installationConfigMapKey: string(val),
		},
	}

	zap.L().Debug("Setting the installation ConfigMap", zap.Any("cm", cm))

	if _, err := k8sutils.CreateOrUpdateConfigMap(ctx, g.k8sC, cm); err != nil {
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

	_, err = createInitResource(ctx, crt, g.octeliumC.CoreC().GetSecret, g.octeliumC.CoreC().CreateSecret)
	if err != nil {
		return err
	}

	return nil
}

func (g *Genesis) installOcteliumResources(ctx context.Context, clusterCfg *corev1.ClusterConfig, region *corev1.Region, isInit bool) error {
	zap.L().Debug("Installing Octelium resources")

	if err := k8sutils.WaitReadinessDeployment(ctx, g.k8sC, "octelium-nocturne"); err != nil {
		return err
	}

	zap.L().Debug("Creating system Namespaces and Services")

	if err := g.ensureNamespace(ctx, &corev1.Namespace{
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

	if err := g.ensureNamespace(ctx, &corev1.Namespace{
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

	if err := g.ensureNamespace(ctx, &corev1.Namespace{
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
					Image:              oc.GetImage(oc.DNSServer, ""),
					Type:               "dnsserver",
					ReadOnlyFileSystem: true,
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

		if err := g.ensureService(ctx, dnsService); err != nil {
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
					Type:               "apiserver",
					Image:              oc.GetImage(oc.APIServer, ""),
					ReadOnlyFileSystem: true,
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

		if err := g.ensureService(ctx, svc); err != nil {
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
					Type:               "apiserver",
					Image:              oc.GetImage(oc.AuthServer, ""),
					Args:               []string{"grpc"},
					ReadOnlyFileSystem: true,
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

		if err := g.ensureService(ctx, svc); err != nil {
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
					Image:              oc.GetImage(oc.AuthServer, ""),
					Args:               []string{"http"},
					ReadOnlyFileSystem: true,
					Type:               "authserver",
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

		if err := g.ensureService(ctx, svc); err != nil {
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
					Image:              oc.GetImage(oc.Portal, ""),
					ReadOnlyFileSystem: true,
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

		if err := g.ensureService(ctx, svc); err != nil {
			return err
		}
	}

	if !isInit {
		return nil
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

		if err := g.ensureService(ctx, svc); err != nil {
			return err
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name:        "essh.octelium",
				DisplayName: "Main Embedded SSH Server",
				Description: `An embedded SSH server used mainly for "octelium ssh" and "octelium cp" commands`,
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_SSH,
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Ssh{
						Ssh: &corev1.Service_Spec_Config_SSH{
							ESSHMode:                  true,
							EnableSubsystem:           true,
							EnableLocalPortForwarding: true,
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}

		if err := g.ensureService(ctx, svc); err != nil {
			return err
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name:        "socks5.octelium",
				DisplayName: "SOCKS5 Server for Embedded Access",
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_SOCKS5,
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Socks5{
						Socks5: &corev1.Service_Spec_Config_SOCKS5{
							IsEmbeddedMode: true,
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}

		if err := g.ensureService(ctx, svc); err != nil {
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

	_, err = createInitResource(ctx, &corev1.Config{
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
	}, g.octeliumC.CoreC().GetConfig, g.octeliumC.CoreC().CreateConfig)
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

	return k8sretry.Do(ctx, func(ctx context.Context) error {
		_, err := g.nadC.K8sCniCncfIoV1().NetworkAttachmentDefinitions(vutils.K8sNS).
			Create(ctx, nad, k8smetav1.CreateOptions{})
		if k8serr.IsAlreadyExists(err) {
			return nil
		}
		return err
	})
}

func (g *Genesis) initClusterConfig(ctx context.Context, bootstrap *cbootstrapv1.Config, domain string) (*corev1.ClusterConfig, error) {
	zap.L().Debug("Initializing Cluster configuration")
	if bootstrap.GetSpec() == nil {
		return nil, errors.Errorf("The bootstrap spec is required")
	}

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

	installation, err := getInstallationFromBootstrap(bootstrap)
	if err != nil {
		return nil, err
	}
	clusterCfg.Status.Installation = installation

	clusterCfg.Status.Network.V6RangePrefix = v6Prefix
	if err := clusterconfig.SetClusterSubnets(clusterCfg); err != nil {
		return nil, err
	}

	zap.L().Debug("Initialized ClusterConfig", zap.Any("cc", clusterCfg))

	return clusterCfg, nil
}

func (g *Genesis) initStorage(ctx context.Context, i *genesisutils.InstallCtx) error {
	if i == nil {
		return errors.Errorf("Nil Bootstrap")
	}
	passwords, err := g.resolveStoragePasswords(ctx, i.Bootstrap)
	if err != nil {
		return err
	}
	return g.initStorageWithPasswords(ctx, i, passwords)
}

func (g *Genesis) initStorageWithPasswords(ctx context.Context, i *genesisutils.InstallCtx, passwords *storagePasswords) error {
	zap.L().Debug("Initializing storage secrets")

	{
		info := i.Bootstrap.Spec.PrimaryStorage.GetPostgresql()
		password := passwords.postgres

		dataMap := map[string][]byte{
			"postgres-password": []byte(password),
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
		password := passwords.redis

		dataMap := map[string][]byte{
			"password": []byte(password),
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

	setStorageEnvironment(i.Bootstrap, passwords)

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

	_, err = createInitResource(ctx, &corev1.Secret{
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
	}, g.octeliumC.CoreC().GetSecret, g.octeliumC.CoreC().CreateSecret)
	if err != nil {
		return err
	}

	zap.L().Debug("Successfully created SSH CA Secret")

	return nil
}

func (g *Genesis) createSSHServiceSeedSecret(ctx context.Context) error {
	_, err := createInitResource(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name:           "sys:ssh-svc-seed",
			IsSystem:       true,
			IsSystemHidden: true,
			IsUserHidden:   true,
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{
				ValueBytes: []byte(utilrand.GetRandomBytesMust(32)),
			},
		},
	}, g.octeliumC.CoreC().GetSecret, g.octeliumC.CoreC().CreateSecret)
	if err != nil {
		if grpcerr.AlreadyExists(err) {
			return nil
		}
		return err
	}

	zap.L().Debug("Created SSH Service seed Secret")

	return nil
}

func (g *Genesis) createAESKey(ctx context.Context, name string) error {

	secretVal, err := utilrand.GetRandomBytes(32)
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: name,
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

	if _, err := createInitResource(ctx, secret, g.octeliumC.CoreC().GetSecret, g.octeliumC.CoreC().CreateSecret); err != nil {
		return err
	}

	return nil
}

func (g *Genesis) createInitAuthenticationToken(ctx context.Context) error {
	zap.L().Debug("Creating the initial root authentication token")
	if _, err := g.getInitAuthenticationToken(ctx); err == nil {
		return nil
	} else if !k8serr.IsNotFound(err) {
		return err
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  g.octeliumC,
		IsEmbedded: true,
	})

	cred, err := createInitResource(ctx, &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name:        "root-init",
			Description: `This is the initial authentication token used upon the Cluster installation. You might want to delete it once you have added your own Users and other resources`,
		},
		Spec: &corev1.Credential_Spec{
			User:        "root",
			Type:        corev1.Credential_Spec_AUTH_TOKEN,
			ExpiresAt:   pbutils.Timestamp(time.Now().Add(6 * 30 * 24 * time.Hour)),
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
	}, g.octeliumC.CoreC().GetCredential, func(ctx context.Context, cred *corev1.Credential, _ ...grpc.CallOption) (*corev1.Credential, error) {
		return adminSrv.CreateCredential(ctx, cred)
	})
	if err != nil {
		return err
	}

	if cred.GetStatus() == nil || cred.GetSpec().GetType() != corev1.Credential_Spec_AUTH_TOKEN ||
		cred.Spec.User != "root" || cred.Spec.IsDisabled || cred.Status.IsLocked ||
		(cred.Spec.ExpiresAt.IsValid() && !time.Now().Before(cred.Spec.ExpiresAt.AsTime())) {
		return errors.Errorf("The initial root Credential is invalid, disabled, locked or expired")
	}
	if cred.Status.UserRef.GetUid() == "" {
		return errors.Errorf("The initial root Credential has no User reference")
	}
	usr, err := g.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: cred.Status.UserRef.Uid})
	if err != nil {
		return err
	}
	if usr.GetMetadata().GetName() != "root" || usr.Metadata.IsSystem {
		return errors.Errorf("The initial root Credential does not reference the root User")
	}
	if cred.Status.TokenID == "" {
		cred.Status.TokenID = vutils.UUIDv4()
		cred.Status.LastRotationAt = pbutils.Now()
		cred.Status.TotalRotations++
		cred, err = g.octeliumC.CoreC().UpdateCredential(ctx, cred)
		if err != nil {
			return err
		}
	}
	jwkCtl, err := jwkctl.NewJWKController(ctx, g.octeliumC, nil)
	if err != nil {
		return err
	}
	tkn, err := jwkCtl.CreateCredential(cred)
	if err != nil {
		return err
	}

	secret := &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:        "init-token",
			Namespace:   vutils.K8sNS,
			Annotations: map[string]string{initializationIDKey: g.initializationID},
		},
		Data: map[string][]byte{
			"data": []byte(tkn),
		},
	}
	_, err = k8sretry.Create(ctx, secret,
		func(ctx context.Context) (*k8scorev1.Secret, error) {
			return g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, secret, k8smetav1.CreateOptions{})
		}, g.getInitAuthenticationToken)

	if err != nil {
		return err
	}

	zap.L().Debug("Successfully created the root User initial authentication token")

	return nil
}

func (g *Genesis) setDataPlaneNodeTaints(ctx context.Context) error {
	if ldflags.IsTest() {
		return nil
	}

	dataPlaneNodes, err := k8sretry.Read(ctx, func(ctx context.Context) (*k8scorev1.NodeList, error) {
		return g.k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{LabelSelector: vutils.NodeLabelDataPlane})
	})
	if err != nil {
		return err
	}

	if len(dataPlaneNodes.Items) == 0 {
		return errors.Errorf(
			"No Kubernetes node is labeled as an Octelium data-plane node. At least one node must be labeled via: kubectl label nodes <NODE_NAME> %s=",
			vutils.NodeLabelDataPlane)
	}

	nodeList, err := k8sretry.Read(ctx, func(ctx context.Context) (*k8scorev1.NodeList, error) {
		return g.k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s,!%s", vutils.NodeLabelDataPlane, vutils.NodeLabelControlPlane),
		})
	})
	if err != nil {
		return err
	}

	for _, item := range nodeList.Items {
		nodeName := item.Name

		if err := k8sretry.Do(ctx, func(ctx context.Context) error {
			node, err := g.k8sC.CoreV1().Nodes().Get(ctx, nodeName, k8smetav1.GetOptions{})
			if err != nil {
				return err
			}

			hasTaint := slices.ContainsFunc(node.Spec.Taints, func(taint k8scorev1.Taint) bool {
				return taint.Key == vutils.NodeTaintGatewayInit
			})

			if node.Labels == nil {
				node.Labels = make(map[string]string)
			}
			isRegistered := node.Labels[vutils.NodeLabelGatewayRegistered] == "true"
			if isRegistered {
				return nil
			}

			if hasTaint && !isRegistered {
				return nil
			}

			if !hasTaint {
				node.Spec.Taints = append(node.Spec.Taints, k8scorev1.Taint{
					Key:    vutils.NodeTaintGatewayInit,
					Value:  "true",
					Effect: k8scorev1.TaintEffectNoSchedule,
				})
			}

			delete(node.Labels, vutils.NodeLabelGatewayRegistered)

			if err := ctx.Err(); err != nil {
				return err
			}
			_, err = g.k8sC.CoreV1().Nodes().Update(ctx, node, k8smetav1.UpdateOptions{})
			return err
		}); err != nil {
			return errors.Wrapf(err, "Could not set the gateway-init taint on the node %s", nodeName)
		}

		zap.L().Debug("Set the gateway-init taint on the data-plane node",
			zap.String("node", nodeName))
	}

	zap.L().Info("Successfully set the gateway-init taint on the dedicated data-plane nodes",
		zap.Int("tainted", len(nodeList.Items)),
		zap.Int("dataPlaneNodes", len(dataPlaneNodes.Items)))

	return nil
}

func (g *Genesis) setNamespace(ctx context.Context) error {
	zap.L().Debug("Initializing the octelium k8s namespace")
	namespaces := g.k8sC.CoreV1().Namespaces()
	namespace, err := k8sretry.Read(ctx, func(ctx context.Context) (*k8scorev1.Namespace, error) {
		return namespaces.Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{})
	})
	if k8serr.IsNotFound(err) {
		desired := &k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS, Labels: map[string]string{"app": "octelium"}}}
		namespace, err = k8sretry.Create(ctx, desired,
			func(ctx context.Context) (*k8scorev1.Namespace, error) {
				return namespaces.Create(ctx, desired, k8smetav1.CreateOptions{})
			},
			func(ctx context.Context) (*k8scorev1.Namespace, error) {
				return namespaces.Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{})
			})
	}
	if err != nil {
		return err
	}
	if namespace.DeletionTimestamp != nil {
		return errors.Errorf("The octelium namespace is terminating. Refusing to initialize the Cluster")
	}
	return nil
}

func (g *Genesis) moveK8SSecret(ctx context.Context, secFrom *k8scorev1.Secret) error {
	sec := &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{Name: secFrom.Name, Namespace: vutils.K8sNS},
		Data:       secFrom.Data, StringData: secFrom.StringData, Type: secFrom.Type,
	}
	destination := g.k8sC.CoreV1().Secrets(vutils.K8sNS)
	existing, err := k8sretry.Create(ctx, sec,
		func(ctx context.Context) (*k8scorev1.Secret, error) {
			return destination.Create(ctx, sec, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*k8scorev1.Secret, error) {
			return destination.Get(ctx, sec.Name, k8smetav1.GetOptions{})
		})
	if err != nil {
		return err
	}
	if !equalInitializationSecrets(existing, sec) {
		return errors.Errorf("The existing bootstrap Secret differs from the initialization input")
	}
	source := g.k8sC.CoreV1().Secrets(secFrom.Namespace)
	return k8sretry.Delete(ctx, secFrom,
		func(ctx context.Context) (*k8scorev1.Secret, error) {
			return source.Get(ctx, secFrom.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, options k8smetav1.DeleteOptions) error {
			return source.Delete(ctx, secFrom.Name, options)
		})
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

	_, err = createInitResource(ctx, rootUser, g.octeliumC.CoreC().GetUser, g.octeliumC.CoreC().CreateUser)
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
		_, err = createInitResource(ctx, usr, g.octeliumC.CoreC().GetUser, g.octeliumC.CoreC().CreateUser)
		if err != nil {
			return err
		}

	}

	return nil
}

func (g *Genesis) loadClusterInitResources(ctx context.Context, ns string) (*LoadedClusterResource, error) {
	if ns == "" {
		ns = "default"
	}
	zap.L().Debug("Loading Cluster resources")
	ret := &LoadedClusterResource{}
	sec, err := g.getK8sSecret(ctx, ns, "octelium-init")
	if err != nil {
		return nil, err
	}
	g.inputBindingKey = sec.Data[initializationInputKey]

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

	sec, err := g.getK8sSecret(ctx, "default", "octelium-init")
	if k8serr.IsNotFound(err) {
		_, err = g.getK8sSecret(ctx, vutils.K8sNS, "octelium-init")
		return err
	}
	if err != nil {
		return err
	}

	return g.moveK8SSecret(ctx, sec)
}

func (g *Genesis) validateClusterNetwork(ctx context.Context, cc *corev1.ClusterConfig, bootstrap *cbootstrapv1.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var allocated []netip.Prefix
	values := []string{}
	if ucorev1.ToClusterConfig(cc).HasV4() {
		values = append(values, cc.Status.Network.GetClusterNetwork().GetV4())
	}
	if ucorev1.ToClusterConfig(cc).HasV6() {
		values = append(values, cc.Status.Network.GetClusterNetwork().GetV6())
	}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return errors.Wrap(err, "Invalid allocated Cluster network")
		}
		allocated = append(allocated, prefix)
	}
	for _, host := range []string{bootstrap.GetSpec().GetPrimaryStorage().GetPostgresql().GetHost(), bootstrap.GetSpec().GetSecondaryStorage().GetRedis().GetHost()} {
		if addr, err := netip.ParseAddr(host); err == nil {
			if err := checkNetworkOverlap(allocated, addr.Unmap().String(), "storage endpoint"); err != nil {
				return err
			}
		}
	}
	var lastErr error
	err := k8sretry.Wait(ctx, 500*time.Millisecond, 2*time.Minute, func(ctx context.Context) (bool, error) {
		lastErr = g.checkKubernetesNetwork(ctx, allocated)
		return lastErr == nil, lastErr
	})
	if err != nil && lastErr != nil {
		return errors.Wrapf(err, "Could not validate Cluster network: %s", lastErr)
	}
	return err
}

func (g *Genesis) checkKubernetesNetwork(ctx context.Context, allocated []netip.Prefix) error {
	nodes, err := g.k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, node := range nodes.Items {
		for _, cidr := range append([]string{node.Spec.PodCIDR}, node.Spec.PodCIDRs...) {
			if err := checkNetworkOverlap(allocated, cidr, "Kubernetes Pod CIDR on Node "+node.Name); err != nil {
				return err
			}
		}
		for _, addr := range node.Status.Addresses {
			if addr.Type == k8scorev1.NodeInternalIP || addr.Type == k8scorev1.NodeExternalIP {
				if err := checkNetworkOverlap(allocated, addr.Address, "Kubernetes Node "+node.Name); err != nil {
					return err
				}
			}
		}
	}
	cidrs, err := g.k8sC.NetworkingV1().ServiceCIDRs().List(ctx, k8smetav1.ListOptions{})
	if err != nil && !k8serr.IsNotFound(err) && !k8serr.IsMethodNotSupported(err) {
		return err
	}
	if err == nil {
		for _, cidr := range cidrs.Items {
			for _, value := range cidr.Spec.CIDRs {
				if err := checkNetworkOverlap(allocated, value, "Kubernetes ServiceCIDR "+cidr.Name); err != nil {
					return err
				}
			}
		}
	}
	services, err := g.k8sC.CoreV1().Services("").List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, service := range services.Items {
		for _, value := range append([]string{service.Spec.ClusterIP}, service.Spec.ClusterIPs...) {
			if value == k8scorev1.ClusterIPNone {
				continue
			}
			if err := checkNetworkOverlap(allocated, value, "Kubernetes Service "+service.Namespace+"/"+service.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkNetworkOverlap(allocated []netip.Prefix, value, source string) error {
	if value == "" {
		return nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, addrErr := netip.ParseAddr(value)
		if addrErr != nil {
			return errors.Errorf("Invalid network address %q from %s", value, source)
		}
		addr = addr.Unmap()
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return errors.Errorf("Invalid IPv4-mapped network %q from %s", value, source)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	for _, subnet := range allocated {
		if subnet.Overlaps(prefix) {
			return errors.Errorf("Cluster subnet %s overlaps %s %s", subnet, source, value)
		}
	}
	return nil
}

type storagePasswords struct {
	postgres string
	redis    string
}

func validatePasswordSecretReference(name, namespace, key string) error {
	if name == "" {
		return errors.New("name of passwordFromSecret is empty")
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return errors.Errorf("Invalid passwordFromSecret name %q: %s", name, strings.Join(errs, ", "))
	}
	if namespace != "" {
		if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
			return errors.Errorf("Invalid passwordFromSecret namespace %q: %s", namespace, strings.Join(errs, ", "))
		}
	}
	if key != "" {
		if errs := validation.IsConfigMapKey(key); len(errs) > 0 {
			return errors.Errorf("Invalid passwordFromSecret key %q: %s", key, strings.Join(errs, ", "))
		}
	}
	return nil
}

func (g *Genesis) resolveStoragePasswords(ctx context.Context, bs *cbootstrapv1.Config) (*storagePasswords, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if bs.GetSpec() == nil {
		return nil, errors.New("Nil Bootstrap")
	}
	pg := bs.Spec.GetPrimaryStorage().GetPostgresql()
	if pg == nil {
		return nil, errors.New("No Postgres info")
	}
	redis := bs.Spec.GetSecondaryStorage().GetRedis()
	if redis == nil {
		return nil, errors.New("No Redis info")
	}

	secrets := make(map[string]*k8scorev1.Secret)
	getPassword := func(name, namespace, key string) (string, error) {
		if err := validatePasswordSecretReference(name, namespace, key); err != nil {
			return "", err
		}
		if namespace == "" {
			namespace = "default"
		}
		identity := namespace + "/" + name
		secret := secrets[identity]
		if secret == nil {
			var err error
			secret, err = g.getK8sSecret(ctx, namespace, name)
			if err != nil {
				return "", err
			}
			secrets[identity] = secret
		}
		if key != "" {
			if len(secret.Data[key]) == 0 {
				return "", errors.Errorf("The passwordFromSecret %s key %q is missing or empty", identity, key)
			}
			return string(secret.Data[key]), nil
		}
		for _, key := range []string{"password", "data"} {
			if len(secret.Data[key]) > 0 {
				return string(secret.Data[key]), nil
			}
		}
		return "", errors.Errorf("The passwordFromSecret %s has no non-empty password or data key", identity)
	}

	ret := &storagePasswords{}
	var err error
	switch value := pg.PasswordType.(type) {
	case *cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password:
		if value != nil {
			ret.postgres = value.Password
		}
	case *cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_:
		if value == nil {
			return nil, errors.New("name of passwordFromSecret is empty")
		}
		ref := value.PasswordFromSecret
		ret.postgres, err = getPassword(ref.GetName(), ref.GetNamespace(), ref.GetKey())
		if err != nil {
			return nil, errors.Wrap(err, "Could not resolve the Postgres password")
		}
	}
	switch value := redis.PasswordType.(type) {
	case *cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password:
		if value != nil {
			ret.redis = value.Password
		}
	case *cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret_:
		if value == nil {
			return nil, errors.New("name of passwordFromSecret is empty")
		}
		ref := value.PasswordFromSecret
		ret.redis, err = getPassword(ref.GetName(), ref.GetNamespace(), ref.GetKey())
		if err != nil {
			return nil, errors.Wrap(err, "Could not resolve the Redis password")
		}
	}
	return ret, nil
}

func setStorageEnvironment(bootstrap *cbootstrapv1.Config, passwords *storagePasswords) {
	pg := bootstrap.Spec.PrimaryStorage.GetPostgresql()
	if ldflags.IsTest() {
		os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
		os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
		os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
		os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")
	} else {
		for key, value := range map[string]string{
			"OCTELIUM_POSTGRES_DATABASE": pg.Database,
			"OCTELIUM_POSTGRES_USERNAME": pg.Username,
			"OCTELIUM_POSTGRES_PASSWORD": passwords.postgres,
			"OCTELIUM_POSTGRES_HOST":     pg.Host,
		} {
			if value != "" {
				os.Setenv(key, value)
			}
		}
		if !pg.IsTLS {
			os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
		}
		if pg.Port != 0 {
			os.Setenv("OCTELIUM_POSTGRES_PORT", fmt.Sprintf("%d", pg.Port))
		}
	}
	redis := bootstrap.Spec.SecondaryStorage.GetRedis()
	for key, value := range map[string]string{
		"OCTELIUM_REDIS_USERNAME": redis.Username,
		"OCTELIUM_REDIS_PASSWORD": passwords.redis,
		"OCTELIUM_REDIS_HOST":     redis.Host,
	} {
		if value != "" {
			os.Setenv(key, value)
		}
	}
	if redis.Database != 0 {
		os.Setenv("OCTELIUM_REDIS_DATABASE", fmt.Sprintf("%d", redis.Database))
	}
	if redis.Port != 0 {
		os.Setenv("OCTELIUM_REDIS_PORT", fmt.Sprintf("%d", redis.Port))
	}
	if redis.IsTLS {
		os.Setenv("OCTELIUM_REDIS_USE_TLS", "true")
	}
}

type initializationDialer struct {
	ctx       context.Context
	tlsConfig *tls.Config
}

type initializationConn struct {
	net.Conn
	stop func() bool
}

func (c *initializationConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func (d *initializationDialer) dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	defer cancel()
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if d.tlsConfig == nil {
		conn, err = dialer.DialContext(ctx, network, address)
	} else {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: d.tlsConfig}).DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, err
	}
	return &initializationConn{Conn: conn, stop: context.AfterFunc(d.ctx, func() { conn.Close() })}, nil
}

func (d *initializationDialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(d.ctx, network, address, 0)
}

func (d *initializationDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return d.dial(d.ctx, network, address, timeout)
}

func (d *initializationDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address, 0)
}

func preflightInitializationStorage(ctx context.Context, bootstrap *cbootstrapv1.Config, passwords *storagePasswords) error {
	setStorageEnvironment(bootstrap, passwords)
	return k8sretry.Do(ctx, func(ctx context.Context) error {
		db, err := postgresutils.NewDBWithDialer(&initializationDialer{ctx: ctx})
		if err != nil {
			return errors.Wrap(err, "Could not configure PostgreSQL")
		}
		defer db.Close()
		if err := db.PingContext(ctx); err != nil {
			return errors.Wrap(err, "Could not connect to PostgreSQL before initialization")
		}
		opts := redisutils.NewOptions()
		opts.ContextTimeoutEnabled = true
		opts.Dialer = (&initializationDialer{ctx: ctx, tlsConfig: opts.TLSConfig}).DialContext
		redisC := redis.NewClient(opts)
		defer redisC.Close()
		stop := context.AfterFunc(ctx, func() { redisC.Close() })
		defer stop()
		if err := redisC.Ping(ctx).Err(); err != nil {
			return errors.Wrap(err, "Could not connect to Redis before initialization")
		}
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass('octelium_resources') IS NOT NULL`).Scan(&exists); err != nil {
			return err
		}
		if exists {
			var empty bool
			if err := db.QueryRowContext(ctx, `SELECT NOT EXISTS (SELECT 1 FROM octelium_resources)`).Scan(&empty); err != nil {
				return err
			}
			if !empty {
				return errors.New("The primary storage contains existing resources. Use octops upgrade instead of init")
			}
		}
		for _, pattern := range []string{"octelium:*", "rsc:*"} {
			var cursor uint64
			for {
				keys, next, err := redisC.Scan(ctx, cursor, pattern, 100).Result()
				if err != nil {
					return err
				}
				if len(keys) > 0 {
					return errors.New("The Redis database contains existing Octelium state. Refusing to reset it")
				}
				cursor = next
				if cursor == 0 {
					break
				}
			}
		}
		return nil
	})
}
