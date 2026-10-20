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

package k8ssecretcontroller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/grpcerr"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func TestController(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		_, _ = fakeC.OcteliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{
			Name: "crt-ns-default",
		})
	}

	{
		k8sSec := &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      "cert-cluster",
				Namespace: "octelium",
			},
			Data: map[string][]byte{
				"tls.crt": utilrand.GetRandomBytesMust(200),
				"tls.key": utilrand.GetRandomBytesMust(200),
			},
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.NotNil(t, err)

	}

	{
		crt, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		k8sSec := &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      "cert-cluster",
				Namespace: "octelium",
			},
			Data: map[string][]byte{
				"tls.crt": crt.MustGetCertPEM(),
				"tls.key": crt.MustGetPrivateKeyPEM(),
			},
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.Nil(t, err)

		sec, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
			Name: "crt-ns-default",
		})
		assert.Nil(t, err)

		assert.Equal(t, "true", sec.Metadata.SystemLabels["octelium-cert"])
		assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
		assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())

	}

	{
		crt, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		ns := utilrand.GetRandomStringCanonical(8)
		k8sSec := &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      fmt.Sprintf("cert-ns-%s", ns),
				Namespace: "octelium",
			},
			Data: map[string][]byte{
				"tls.crt": crt.MustGetCertPEM(),
				"tls.key": crt.MustGetPrivateKeyPEM(),
			},
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.Nil(t, err)

		sec, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
			Name: fmt.Sprintf("crt-ns-%s", ns),
		})
		assert.Nil(t, err)

		assert.Equal(t, "true", sec.Metadata.SystemLabels["octelium-cert"])
		assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
		assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())

	}

	{

		crt, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		k8sSec := &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      "cert-cluster",
				Namespace: "octelium",
			},
			Data: map[string][]byte{
				"tls.crt": crt.MustGetCertPEM(),
				"tls.key": crt.MustGetPrivateKeyPEM(),
			},
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.Nil(t, err)

		{
			sec, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: "crt-ns-default",
			})
			assert.Nil(t, err)
			assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
			assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
		}

		crt, err = utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		k8sSec.Data = map[string][]byte{
			"tls.crt": crt.MustGetCertPEM(),
			"tls.key": crt.MustGetPrivateKeyPEM(),
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.Nil(t, err)

		{
			sec, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: "crt-ns-default",
			})
			assert.Nil(t, err)
			assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
			assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
		}
	}
}

func TestSetCertRouting(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		_, _ = fakeC.OcteliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{
			Name: vutils.ClusterCertSecretName,
		})
	}

	assertNoClusterCert := func() {
		_, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
			Name: vutils.ClusterCertSecretName,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	genK8sSecret := func(name, namespace string) *k8scorev1.Secret {
		return &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Data: map[string][]byte{
				"tls.crt": utilrand.GetRandomBytesMust(200),
				"tls.key": utilrand.GetRandomBytesMust(200),
			},
		}
	}

	{
		err := setCert(ctx, fakeC.OcteliumC, genK8sSecret("cert-cluster", "not-octelium"))
		assert.Nil(t, err, "%+v", err)
		assertNoClusterCert()
	}

	{
		err := setCert(ctx, fakeC.OcteliumC,
			genK8sSecret(utilrand.GetRandomStringCanonical(8), vutils.K8sNS))
		assert.Nil(t, err, "%+v", err)
		assertNoClusterCert()
	}

	{
		err := setCert(ctx, fakeC.OcteliumC, genK8sSecret("cert-ns-", vutils.K8sNS))
		assert.Nil(t, err, "%+v", err)
		assertNoClusterCert()
	}
}

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *fakeOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

type fakeCoreC struct {
	rcorev1.ResourceServiceClient
	secret    *corev1.Secret
	getErr    error
	createErr error
	updateErr error
	creates   int
	updates   int
}

func (c *fakeCoreC) GetSecret(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Secret, error) {
	if c.getErr != nil {
		return nil, c.getErr
	}
	if c.secret == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return c.secret, nil
}

func (c *fakeCoreC) CreateSecret(ctx context.Context,
	in *corev1.Secret, opts ...grpc.CallOption) (*corev1.Secret, error) {
	c.creates++
	c.secret = in
	return in, c.createErr
}

func (c *fakeCoreC) UpdateSecret(ctx context.Context,
	in *corev1.Secret, opts ...grpc.CallOption) (*corev1.Secret, error) {
	c.updates++
	c.secret = in
	return in, c.updateErr
}

type fakeSecretInformer struct {
	coreinformers.SecretInformer
	informer *fakeInformer
}

func (i *fakeSecretInformer) Informer() cache.SharedIndexInformer {
	return i.informer
}

type fakeInformer struct {
	cache.SharedIndexInformer
	handler cache.ResourceEventHandler
}

func (i *fakeInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	i.handler = handler
	return nil, nil
}

func newTstCertificate(t *testing.T) *k8scorev1.Secret {
	t.Helper()
	crt, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)
	return &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "cert-cluster", Namespace: vutils.K8sNS, ResourceVersion: "1"},
		Data: map[string][]byte{
			"tls.crt": crt.MustGetCertPEM(),
			"tls.key": crt.MustGetPrivateKeyPEM(),
		},
	}
}

func TestCertificateEvents(t *testing.T) {
	coreC := &fakeCoreC{}
	informer := &fakeSecretInformer{informer: &fakeInformer{}}
	NewController(nil, &fakeOcteliumC{coreC: coreC}, informer)
	handler := informer.informer.handler
	secret := newTstCertificate(t)
	handler.OnAdd(secret, false)
	assert.Equal(t, 1, coreC.creates)
	assert.Equal(t, vutils.ClusterCertSecretName, coreC.secret.Metadata.Name)
	assert.Equal(t, string(secret.Data["tls.key"]), ucorev1.ToSecret(coreC.secret).GetValueStr())
	old := secret
	secret = newTstCertificate(t)
	secret.ResourceVersion = "2"
	handler.OnUpdate(old, secret)
	assert.Equal(t, 1, coreC.updates)
	assert.Equal(t, string(secret.Data["tls.key"]), ucorev1.ToSecret(coreC.secret).GetValueStr())
	handler.OnAdd("secret", false)
	handler.OnUpdate("secret", secret)
	handler.OnUpdate(secret, "secret")
	handler.OnUpdate(secret, secret)
	assert.Equal(t, 1, coreC.updates)
	coreC.getErr = errors.New("could not get Secret")
	handler.OnAdd(secret, false)
	handler.OnUpdate(old, secret)
	assert.Equal(t, 1, coreC.updates)
}

func TestNamespaceCertificateUpdate(t *testing.T) {
	ctx := context.Background()
	coreC := &fakeCoreC{}
	c := &fakeOcteliumC{coreC: coreC}
	secret := newTstCertificate(t)
	secret.Name = "cert-ns-custom"
	assert.Nil(t, setCert(ctx, c, secret))
	assert.Equal(t, "crt-ns-custom", coreC.secret.Metadata.Name)
	assert.True(t, coreC.secret.Metadata.IsSystem)
	assert.True(t, coreC.secret.Metadata.IsUserHidden)
	assert.True(t, coreC.secret.Metadata.IsSystemHidden)
	assert.Equal(t, "true", coreC.secret.Metadata.SystemLabels["octelium-cert"])
	assert.Equal(t, 1, coreC.creates)
	secret.Data = newTstCertificate(t).Data
	assert.Nil(t, setCert(ctx, c, secret))
	assert.Equal(t, 1, coreC.updates)
	assert.Equal(t, string(secret.Data["tls.key"]), ucorev1.ToSecret(coreC.secret).GetValueStr())
}

func TestCertificateErrors(t *testing.T) {
	ctx := context.Background()
	errTst := errors.New("could not reconcile certificate")
	for _, name := range []string{"cert-cluster", "cert-ns-custom"} {
		t.Run(name, func(t *testing.T) {
			secret := newTstCertificate(t)
			secret.Name = name
			for _, coreC := range []*fakeCoreC{
				{getErr: errTst},
				{createErr: errTst},
				{secret: &corev1.Secret{Spec: &corev1.Secret_Spec{}, Status: &corev1.Secret_Status{}}, updateErr: errTst},
			} {
				assert.ErrorIs(t, setCert(ctx, &fakeOcteliumC{coreC: coreC}, secret), errTst)
			}
		})
	}
}

type countingCoreC struct {
	rcorev1.ResourceServiceClient
	gets int
}

func (c *countingCoreC) GetSecret(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Secret, error) {
	c.gets++
	return c.ResourceServiceClient.GetSecret(ctx, in, opts...)
}

func TestNamespaceCertificateValidation(t *testing.T) {
	ctx := context.Background()
	valid := newTstCertificate(t)
	other := newTstCertificate(t)
	cert := valid.Data["tls.crt"]
	key := valid.Data["tls.key"]

	for _, tc := range []struct {
		name string
		data map[string][]byte
	}{
		{"NilData", nil},
		{"EmptyData", map[string][]byte{}},
		{"MissingCertificate", map[string][]byte{"tls.key": key}},
		{"MissingPrivateKey", map[string][]byte{"tls.crt": cert}},
		{"EmptyCertificate", map[string][]byte{"tls.crt": {}, "tls.key": key}},
		{"EmptyPrivateKey", map[string][]byte{"tls.crt": cert, "tls.key": {}}},
		{"InvalidCertificate", map[string][]byte{"tls.crt": []byte("not a certificate"), "tls.key": key}},
		{"InvalidPrivateKey", map[string][]byte{"tls.crt": cert, "tls.key": []byte("not a private key")}},
		{"InvalidCertificateDER", map[string][]byte{
			"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
			"tls.key": key,
		}},
		{"InvalidPrivateKeyDER", map[string][]byte{
			"tls.crt": cert,
			"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("invalid")}),
		}},
		{"CertificateAsPrivateKey", map[string][]byte{"tls.crt": cert, "tls.key": cert}},
		{"Swapped", map[string][]byte{"tls.crt": key, "tls.key": cert}},
		{"MismatchedPair", map[string][]byte{"tls.crt": cert, "tls.key": other.Data["tls.key"]}},
		{"MismatchedLeaf", map[string][]byte{
			"tls.crt": append(append([]byte{}, other.Data["tls.crt"]...), cert...),
			"tls.key": key,
		}},
	} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/Existing%t", tc.name, existing), func(t *testing.T) {
				coreC := &fakeCoreC{}
				if existing {
					coreC.secret = &corev1.Secret{
						Metadata: &metav1.Metadata{Name: "crt-ns-custom", Uid: "secret-uid", ResourceVersion: "1"},
						Spec:     &corev1.Secret_Spec{},
						Status:   &corev1.Secret_Status{},
					}
					ucorev1.ToSecret(coreC.secret).SetCertificate(string(cert), string(key))
				}
				var original *corev1.Secret
				if existing {
					original = proto.Clone(coreC.secret).(*corev1.Secret)
				}
				countingC := &countingCoreC{ResourceServiceClient: coreC}
				secret := &k8scorev1.Secret{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "cert-ns-custom", Namespace: vutils.K8sNS},
					Data:       tc.data,
				}
				err := setCert(ctx, &fakeOcteliumC{coreC: countingC}, secret)
				assert.ErrorContains(t, err, "Could not load TLS certificate")
				assert.Zero(t, countingC.gets)
				assert.Zero(t, coreC.creates)
				assert.Zero(t, coreC.updates)
				if existing {
					assert.True(t, proto.Equal(original, coreC.secret))
				} else {
					assert.Nil(t, coreC.secret)
				}
			})
		}
	}
}

func TestNamespaceCertificateInvalidEvents(t *testing.T) {
	coreC := &fakeCoreC{}
	countingC := &countingCoreC{ResourceServiceClient: coreC}
	informer := &fakeSecretInformer{informer: &fakeInformer{}}
	NewController(nil, &fakeOcteliumC{coreC: countingC}, informer)
	handler := informer.informer.handler

	invalid := newTstCertificate(t)
	invalid.Name = "cert-ns-custom"
	invalid.Data["tls.key"] = []byte("not a private key")
	handler.OnAdd(invalid, false)
	assert.Nil(t, coreC.secret)
	assert.Zero(t, countingC.gets)
	assert.Zero(t, coreC.creates)
	assert.Zero(t, coreC.updates)

	valid := newTstCertificate(t)
	valid.Name = invalid.Name
	valid.ResourceVersion = "2"
	handler.OnUpdate(invalid, valid)
	assert.Equal(t, 1, coreC.creates)
	original := proto.Clone(coreC.secret).(*corev1.Secret)
	invalid = valid.DeepCopy()
	invalid.ResourceVersion = "3"
	invalid.Data["tls.key"] = newTstCertificate(t).Data["tls.key"]
	handler.OnUpdate(valid, invalid)
	assert.Equal(t, 1, countingC.gets)
	assert.Equal(t, 1, coreC.creates)
	assert.Zero(t, coreC.updates)
	assert.True(t, proto.Equal(original, coreC.secret))

	rotated := newTstCertificate(t)
	rotated.Name = valid.Name
	rotated.ResourceVersion = "4"
	handler.OnUpdate(invalid, rotated)
	assert.Equal(t, 2, countingC.gets)
	assert.Equal(t, 1, coreC.creates)
	assert.Equal(t, 1, coreC.updates)
	chain, key, err := ucorev1.ToSecret(coreC.secret).GetCertificateChainAndKey()
	assert.Nil(t, err)
	assert.Equal(t, rotated.Data["tls.crt"], chain)
	assert.Equal(t, rotated.Data["tls.key"], key)
}

func TestNamespaceCertificateValidationPersisted(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() { tst.Destroy() })
	octeliumC := tst.C.OcteliumC
	coreC := octeliumC.CoreC()

	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("Existing%t", existing), func(t *testing.T) {
			secret := newTstCertificate(t)
			ns := utilrand.GetRandomStringCanonical(8)
			secret.Name = "cert-ns-" + ns
			name := "crt-ns-" + ns
			var original *corev1.Secret
			if existing {
				assert.Nil(t, setCert(ctx, octeliumC, secret))
				original, err = coreC.GetSecret(ctx, &rmetav1.GetOptions{Name: name})
				if !assert.Nil(t, err, "%+v", err) {
					return
				}
			}

			for _, data := range []map[string][]byte{
				nil,
				{"tls.crt": secret.Data["tls.crt"], "tls.key": []byte("not a private key")},
				{"tls.crt": secret.Data["tls.crt"], "tls.key": newTstCertificate(t).Data["tls.key"]},
			} {
				invalid := secret.DeepCopy()
				invalid.Data = data
				assert.NotNil(t, setCert(ctx, octeliumC, invalid))
				current, err := coreC.GetSecret(ctx, &rmetav1.GetOptions{Name: name})
				if existing {
					assert.Nil(t, err, "%+v", err)
					assert.True(t, proto.Equal(original, current))
				} else {
					assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
				}
			}

			rotated := newTstCertificate(t)
			rotated.Name = secret.Name
			assert.Nil(t, setCert(ctx, octeliumC, rotated))
			current, err := coreC.GetSecret(ctx, &rmetav1.GetOptions{Name: name})
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			chain, key, err := ucorev1.ToSecret(current).GetCertificateChainAndKey()
			assert.Nil(t, err)
			assert.Equal(t, rotated.Data["tls.crt"], chain)
			assert.Equal(t, rotated.Data["tls.key"], key)
			_, err = tls.X509KeyPair(chain, key)
			assert.Nil(t, err)
			if existing {
				assert.Equal(t, original.Metadata.Uid, current.Metadata.Uid)
				assert.NotEqual(t, original.Metadata.ResourceVersion, current.Metadata.ResourceVersion)
			}
		})
	}
}

func TestNamespaceCertificateChain(t *testing.T) {
	ctx := context.Background()
	ca, err := utils_cert.GenerateCARoot()
	if !assert.Nil(t, err) {
		return
	}
	coreC := &fakeCoreC{}
	for i, tc := range []struct {
		name  string
		isRSA bool
		pkcs8 bool
	}{
		{"ECDSA", false, false},
		{"RSA", true, false},
		{"PKCS8", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, err := utils_cert.GenerateCertificateTmp("service.custom.example.com", ca, tc.isRSA)
			if !assert.Nil(t, err) {
				return
			}
			cert := append(leaf.MustGetCertPEM(), ca.MustGetCertPEM()...)
			key := leaf.MustGetPrivateKeyPEM()
			if tc.pkcs8 {
				der, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
				if !assert.Nil(t, err) {
					return
				}
				key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			}
			secret := &k8scorev1.Secret{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "cert-ns-custom", Namespace: vutils.K8sNS},
				Type:       k8scorev1.SecretTypeTLS,
				Data:       map[string][]byte{"tls.crt": cert, "tls.key": key},
			}
			assert.Nil(t, setCert(ctx, &fakeOcteliumC{coreC: coreC}, secret))
			assert.Equal(t, 1, coreC.creates)
			assert.Equal(t, i, coreC.updates)
			chain, storedKey, err := ucorev1.ToSecret(coreC.secret).GetCertificateChainAndKey()
			assert.Nil(t, err)
			assert.Equal(t, cert, chain)
			assert.Equal(t, key, storedKey)
			pair, err := tls.X509KeyPair(chain, storedKey)
			assert.Nil(t, err)
			assert.Len(t, pair.Certificate, 2)
		})
	}
}
