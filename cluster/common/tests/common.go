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

package tests

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"time"

	"github.com/google/uuid"
	nadclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	fakenad "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/clusterconfig"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type FakeClient struct {
	K8sC      kubernetes.Interface
	OcteliumC octeliumc.ClientInterface
	NadC      nadclientset.Interface
}

func now() k8smetav1.Time {
	return k8smetav1.Time{
		time.Now(),
	}
}

func newFakeClient() *FakeClient {
	k8sC := fakek8s.NewSimpleClientset()
	k8sC.PrependReactor("*", "*", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		switch {
		case action.Matches("create", "secrets"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Secret)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(uuid.New().String())
		case action.Matches("create", "pods"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Pod)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(uuid.New().String())
		case action.Matches("create", "nodes"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Node)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(uuid.New().String())
		}
		return
	})

	return &FakeClient{
		K8sC: k8sC,
		NadC: fakenad.NewSimpleClientset(),
	}
}

func splitApiVersion(apiVersion string) (string, string) {
	ret := strings.Split(apiVersion, "/")
	if len(ret) >= 2 {
		return ret[0], ret[1]
	}

	if len(ret) == 1 {
		return ret[0], ""
	}

	return "", ""
}

type T struct {
	C      *FakeClient
	rscSrv *rscserver.Server
	dbName string
	opts   *Opts
}

type Opts struct {
	RscServerOpts       *rscserver.Opts
	PreCreatedResources []umetav1.ResourceObjectI
}

func InitLog() error {
	zapCfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
		Development:      true,
		Encoding:         "console",
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := zapCfg.Build()
	if err != nil {
		return err
	}

	zap.ReplaceGlobals(logger)

	return nil
}

func Initialize(o *Opts) (*T, error) {

	if o == nil {
		o = &Opts{}
	}

	if err := InitLog(); err != nil {
		return nil, err
	}

	/*
		zlgr := otelzap.New(logger, otelzap.WithMinLevel(zapcore.DebugLevel))
		otelzap.ReplaceGlobals(zlgr)
	*/

	dbName := fmt.Sprintf("octelium%s", utilrand.GetRandomStringLowercase(8))

	os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")

	os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
	os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
	os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")
	os.Setenv("OCTELIUM_TEST_RSCSERVER_PORT", fmt.Sprintf("%d", GetPort()))

	ldflags.PrivateRegistry = "false"
	ldflags.Mode = "production"
	ldflags.TestMode = "true"

	ctx := context.Background()
	c := newFakeClient()

	{
		_, err := c.K8sC.CoreV1().Namespaces().Create(ctx, &k8scorev1.Namespace{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name: "default",
			},
			Spec: k8scorev1.NamespaceSpec{},
		}, k8smetav1.CreateOptions{})
		if err != nil {
			return nil, err
		}
	}

	{
		db, err := postgresutils.NewDBWithNODB()
		if err != nil {
			return nil, err
		}
		if _, err := db.Exec(fmt.Sprintf("CREATE DATABASE %s;", dbName)); err != nil {
			return nil, err
		}
		if err := db.Close(); err != nil {
			return nil, err
		}
	}

	zap.L().Debug("Starting new rsc server")

	os.Setenv("OCTELIUM_POSTGRES_DATABASE", dbName)

	rscSrv, err := rscserver.NewServer(ctx, o.RscServerOpts)
	if err != nil {
		return nil, err
	}

	err = rscSrv.Run(ctx)
	if err != nil {
		return nil, err
	}

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	c.OcteliumC = octeliumC

	_, err = c.K8sC.CoreV1().Namespaces().Create(ctx, &k8scorev1.Namespace{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: "octelium",
		},
		Spec: k8scorev1.NamespaceSpec{},
	}, k8smetav1.CreateOptions{})

	if err != nil {
		return nil, err
	}

	clusterCfg := &corev1.ClusterConfig{
		ApiVersion: ucorev1.APIVersion,
		Kind:       ucorev1.KindClusterConfig,
		Metadata: &metav1.Metadata{
			Uid:             uuid.New().String(),
			ResourceVersion: uuid.New().String(),
			Name:            "default",
		},
		Spec: &corev1.ClusterConfig_Spec{},
		Status: &corev1.ClusterConfig_Status{
			Domain:  "example.com",
			Network: &corev1.ClusterConfig_Status_Network{},
		},
	}

	v6Prefix, err := utilrand.GetRandomBytes(4)
	if err != nil {
		return nil, err
	}

	clusterCfg.Status.Network.V6RangePrefix = v6Prefix

	if err := clusterconfig.SetClusterSubnets(clusterCfg); err != nil {
		return nil, err
	}

	_, err = rscSrv.CreateResource(ctx, clusterCfg, ucorev1.API, ucorev1.Version, ucorev1.KindClusterConfig)
	if err != nil {
		return nil, err
	}

	for _, rsc := range o.PreCreatedResources {
		api, version := splitApiVersion(rsc.GetApiVersion())
		_, err = rscSrv.CreateResource(ctx, rsc, api, version, rsc.GetKind())
		if err != nil {
			return nil, err
		}
	}

	{
		domain := clusterCfg.Status.Domain
		sans := []string{
			"localhost",
			fmt.Sprintf("*.%s", domain),
			fmt.Sprintf("*.local.%s", domain),
		}

		initCrt, err := utils_cert.GenerateSelfSignedCert(domain, sans, 3*time.Hour)
		if err != nil {
			return nil, err
		}

		crtPEM, err := initCrt.GetCertPEM()
		if err != nil {
			return nil, err
		}

		privPEM, err := initCrt.GetPrivateKeyPEM()
		if err != nil {
			return nil, err
		}

		crt := &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name:           vutils.ClusterCertSecretName,
				IsSystem:       true,
				IsSystemHidden: true,
				IsUserHidden:   true,
			},
			Spec:   &corev1.Secret_Spec{},
			Status: &corev1.Secret_Status{},
		}

		ucorev1.ToSecret(crt).SetCertificate(crtPEM, privPEM)

		_, err = octeliumC.CoreC().CreateSecret(ctx, crt)
		if err != nil {
			return nil, err
		}
	}

	{
		_, err = octeliumC.CoreC().CreateRegion(ctx, &corev1.Region{
			Metadata: &metav1.Metadata{
				Name: "default",
				SpecLabels: map[string]string{
					"has-workspace": "true",
				},
			},
			Spec:   &corev1.Region_Spec{},
			Status: &corev1.Region_Status{},
		})
		if err != nil {
			return nil, err
		}
	}

	{

		secretVal, err := utilrand.GetRandomBytes(32)
		if err != nil {
			return nil, err
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

		if _, err := octeliumC.CoreC().CreateSecret(ctx, secret); err != nil {
			return nil, err
		}
	}

	{
		ecdsaKey, err := utils_cert.GenerateECDSA()
		if err != nil {
			return nil, err
		}

		privPEM, err := ecdsaKey.GetPrivateKeyPEM()
		if err != nil {
			return nil, err
		}

		_, err = octeliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
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
			return nil, err
		}
	}

	_, err = c.OcteliumC.CoreC().CreateUser(ctx, &corev1.User{
		Metadata: &metav1.Metadata{
			Name: "root",
		},
		Spec: &corev1.User_Spec{
			Type: corev1.User_Spec_WORKLOAD,
		},
	})
	if err != nil {
		return nil, err
	}

	caRoot, err := utils_cert.GenerateCARoot()
	if err != nil {
		return nil, err
	}
	caRootCert, err := caRoot.GetCertPEM()
	if err != nil {
		return nil, err
	}

	caRootKey, err := caRoot.GetPrivateKeyPEM()
	if err != nil {
		return nil, err
	}

	sec := &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      "octelium-session",
			Namespace: "octelium",
			Annotations: map[string]string{
				"octelium.com/certificate-name": "octelium-session",
			},
		},
		Data: map[string][]byte{
			"tls.crt": []byte(caRootCert),
			"tls.key": []byte(caRootKey),
		},
	}

	_, err = c.K8sC.CoreV1().Secrets("octelium").Create(ctx, sec, k8smetav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	{

		attrs, err := pbutils.MessageToStruct(&cclusterv1.ClusterConnInfo{})
		if err != nil {
			return nil, err
		}
		_, err = octeliumC.CoreC().CreateConfig(ctx, &corev1.Config{
			Metadata: &metav1.Metadata{
				Name:     "sys:conn-info",
				IsSystem: true,
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
			return nil, err
		}
	}

	{

		_, err := c.OcteliumC.CoreC().CreateNamespace(ctx, &corev1.Namespace{
			Metadata: &metav1.Metadata{
				Name:     "default",
				IsSystem: true,
			},
			Spec:   &corev1.Namespace_Spec{},
			Status: &corev1.Namespace_Status{},
		})
		if err != nil {
			return nil, err
		}

		octeliumNs, err := c.OcteliumC.CoreC().CreateNamespace(ctx, &corev1.Namespace{
			Metadata: &metav1.Metadata{
				Name:     "octelium",
				IsSystem: true,
			},
			Spec:   &corev1.Namespace_Spec{},
			Status: &corev1.Namespace_Status{},
		})
		if err != nil {
			return nil, err
		}
		_, err = c.OcteliumC.CoreC().CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "dns.octelium",
			},
			Spec: &corev1.Service_Spec{
				Port: 53,

				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "dns://octelium-dnsserver.octelium.svc",
						},
					},
				},
			},
			Status: &corev1.Service_Status{
				NamespaceRef: umetav1.GetObjectReference(octeliumNs),
				Addresses: []*corev1.Service_Status_Address{
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv4: "1.1.1.1",
						},
					},
				},
			},
		})
		if err != nil {
			return nil, err
		}

		{
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{
					Name:         "api.octelium",
					IsSystem:     true,
					IsUserHidden: true,
					/*
						SpecLabels: map[string]string{
							"enable-public": "true",
						},
					*/
					SystemLabels: map[string]string{
						"octelium-apiserver": "true",
						"apiserver-path":     "/octelium.api.main.core",
					},
				},
				Spec: &corev1.Service_Spec{
					Port:     8080,
					IsPublic: true,
					Mode:     corev1.Service_Spec_GRPC,
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: octeliumNs.Metadata.Name,
						Uid:  octeliumNs.Metadata.Uid,
					},
				},
			}

			if _, err := octeliumC.CoreC().CreateService(ctx, svc); err != nil {
				return nil, err
			}
		}
	}

	return &T{
		C:      c,
		rscSrv: rscSrv,
		dbName: dbName,
		opts:   &Opts{},
	}, nil

}

func (t *T) Destroy() error {

	zap.L().Debug("Destroying test DB", zap.String("db", t.dbName))

	t.rscSrv.Stop()

	db, err := postgresutils.NewDB()
	if err != nil {
		return err
	}

	if _, err := db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s;", t.dbName)); err != nil {
		return err
	}

	return nil
}

func isPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}

	ln.Close()
	time.Sleep(100 * time.Millisecond)
	return true
}

func GetPort() int {
	for i := 0; i < 10000; i++ {
		p := utilrand.GetRandomRangeMath(20000, 65000)
		if isPortAvailable(p) {
			return p
		}
	}
	return 0
}
