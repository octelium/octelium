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
	"slices"
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
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
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
	if err := g.setNamespace(ctx); err != nil {
		return err
	}
	init, err := g.prepareInitialization(ctx, initResources)
	if err != nil {
		return err
	}
	g.initializationID = init.id
	if init.complete {
		_, err := g.getInitAuthenticationToken(ctx)
		return err
	}

	if err := g.initStorage(ctx, &genesisutils.InstallCtx{Bootstrap: initResources.Bootstrap}); err != nil {
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

	if err := g.setInstallationConfigMap(ctx, clusterCfg); err != nil {
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

	if err := g.installOcteliumResources(ctx, clusterCfg, iCtx.Region); err != nil {
		return err
	}

	if err := g.setInitClusterCertificate(ctx, clusterCfg); err != nil {
		return err
	}

	if err := g.installBuiltinPolicies(ctx); err != nil {
		zap.L().Warn("Could not install builtin Policies", zap.Error(err))
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

		if err := genesisutils.CreateOrUpdateService(ctx, g.octeliumC, svc); err != nil {
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

	_, err := g.nadC.K8sCniCncfIoV1().NetworkAttachmentDefinitions(vutils.K8sNS).
		Create(ctx, nad, k8smetav1.CreateOptions{})
	if err != nil && !k8serr.IsAlreadyExists(err) {
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

	var err error

	getPassword := func(name, namespace, key string) (string, error) {
		if namespace == "" {
			namespace = "default"
		}
		if name == "" {
			return "", errors.Errorf("name of passwordFromSecret is empty")
		}
		var password string
		sec, err := g.k8sC.CoreV1().
			Secrets(namespace).
			Get(ctx, name, k8smetav1.GetOptions{})
		if err != nil {
			return "", err
		}

		if key != "" {
			password = string(sec.Data[key])
		}
		if password == "" {
			password = string(sec.Data["password"])
		}
		if password == "" {
			password = string(sec.Data["data"])
		}

		return password, nil
	}

	{
		info := i.Bootstrap.Spec.PrimaryStorage.GetPostgresql()

		var password string

		switch info.PasswordType.(type) {
		case *cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password:
			password = info.GetPassword()
		case *cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_:
			secSpec := info.GetPasswordFromSecret()

			password, err = getPassword(secSpec.Name, secSpec.Namespace, secSpec.Key)
			if err != nil {
				return err
			}
		}

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

		if ldflags.IsTest() {
			os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
			os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
			os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
			os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")

		} else {
			if info.Database != "" {
				os.Setenv("OCTELIUM_POSTGRES_DATABASE", info.Database)
			}

			if info.Username != "" {
				os.Setenv("OCTELIUM_POSTGRES_USERNAME", info.Username)
			}

			if password != "" {
				os.Setenv("OCTELIUM_POSTGRES_PASSWORD", password)
			}

			if !info.IsTLS {
				os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
			}

			if info.Host != "" {
				os.Setenv("OCTELIUM_POSTGRES_HOST", info.Host)
			}

			if info.Port != 0 {
				os.Setenv("OCTELIUM_POSTGRES_PORT", fmt.Sprintf("%d", info.Port))
			}
		}
	}

	{
		info := i.Bootstrap.Spec.SecondaryStorage.GetRedis()
		var password string

		switch info.PasswordType.(type) {
		case *cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password:
			password = info.GetPassword()
		case *cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret_:
			secSpec := info.GetPasswordFromSecret()
			password, err = getPassword(secSpec.Name, secSpec.Namespace, secSpec.Key)
			if err != nil {
				return err
			}
		}

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

		{
			if info.Database != 0 {
				os.Setenv("OCTELIUM_REDIS_DATABASE", fmt.Sprintf("%d", info.Database))
			}

			if info.Username != "" {
				os.Setenv("OCTELIUM_REDIS_USERNAME", info.Username)
			}

			if password != "" {
				os.Setenv("OCTELIUM_REDIS_PASSWORD", password)
			}

			if info.Host != "" {
				os.Setenv("OCTELIUM_REDIS_HOST", info.Host)
			}

			if info.Port != 0 {
				os.Setenv("OCTELIUM_REDIS_PORT", fmt.Sprintf("%d", info.Port))
			}

			if info.IsTLS {
				os.Setenv("OCTELIUM_REDIS_USE_TLS", "true")
			}
		}
	}

	// g.setDBEnvVars(i)

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

	_, err = g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:        "init-token",
			Namespace:   vutils.K8sNS,
			Annotations: map[string]string{initializationIDKey: g.initializationID},
		},
		Data: map[string][]byte{
			"data": []byte(tkn),
		},
	}, k8smetav1.CreateOptions{})
	if k8serr.IsAlreadyExists(err) {
		_, err = g.getInitAuthenticationToken(ctx)
	}
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

	dataPlaneNodes, err := g.k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{
		LabelSelector: vutils.NodeLabelDataPlane,
	})
	if err != nil {
		return err
	}

	if len(dataPlaneNodes.Items) == 0 {
		return errors.Errorf(
			"No Kubernetes node is labeled as an Octelium data-plane node. At least one node must be labeled via: kubectl label nodes <NODE_NAME> %s=",
			vutils.NodeLabelDataPlane)
	}

	nodeList, err := g.k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s,!%s",
			vutils.NodeLabelDataPlane, vutils.NodeLabelControlPlane),
	})
	if err != nil {
		return err
	}

	for _, item := range nodeList.Items {
		nodeName := item.Name

		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
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

			_, err = g.k8sC.CoreV1().Nodes().Update(ctx, node, k8smetav1.UpdateOptions{})
			return err
		}); err != nil {
			return errors.Errorf("Could not set the gateway-init taint on the node %s: %+v", nodeName, err)
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

	namespace, err := g.k8sC.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{})
	if err == nil {
		if namespace.DeletionTimestamp != nil {
			return errors.Errorf("The octelium namespace is terminating. Refusing to initialize the Cluster")
		}
		return nil
	} else if !k8serr.IsNotFound(err) {
		return err
	}

	_, err = g.k8sC.CoreV1().Namespaces().Create(ctx, &k8scorev1.Namespace{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: vutils.K8sNS,
			Labels: map[string]string{
				"app": "octelium",
			},
		},
	}, k8smetav1.CreateOptions{})
	if k8serr.IsAlreadyExists(err) {
		namespace, err = g.k8sC.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{})
		if err == nil && namespace.DeletionTimestamp != nil {
			return errors.Errorf("The octelium namespace is terminating. Refusing to initialize the Cluster")
		}
	}
	return err
}

func (g *Genesis) moveK8SSecret(ctx context.Context, secFrom *k8scorev1.Secret) error {
	sec := &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      secFrom.Name,
			Namespace: vutils.K8sNS,
		},
		Data:       secFrom.Data,
		StringData: secFrom.StringData,
		Type:       secFrom.Type,
	}
	_, err := g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, sec, k8smetav1.CreateOptions{})
	if k8serr.IsAlreadyExists(err) {
		existing, getErr := g.k8sC.CoreV1().Secrets(vutils.K8sNS).Get(ctx, sec.Name, k8smetav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if !equalInitializationSecrets(existing, sec) {
			return errors.Errorf("The existing bootstrap Secret differs from the initialization input")
		}
	} else if err != nil {
		return err
	}

	err = g.k8sC.CoreV1().Secrets(secFrom.Namespace).Delete(ctx, secFrom.Name, k8smetav1.DeleteOptions{
		Preconditions: &k8smetav1.Preconditions{UID: &secFrom.UID, ResourceVersion: &secFrom.ResourceVersion},
	})
	if k8serr.IsNotFound(err) {
		return nil
	}
	return err
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
	if k8serr.IsNotFound(err) {
		_, err = g.k8sC.CoreV1().Secrets(vutils.K8sNS).Get(ctx, "octelium-init", k8smetav1.GetOptions{})
		return err
	}
	if err != nil {
		return err
	}

	return g.moveK8SSecret(ctx, sec)
}
