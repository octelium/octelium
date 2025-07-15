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
	"encoding/base64"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/ocrypto"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/pkg/errors"
)

func GetClientTLSCfg(ctx context.Context,
	svc *corev1.Service, svcCfg *corev1.Service_Spec_Config, secretMan *secretman.SecretManager, upstream *loadbalancer.Upstream) (*tls.Config, error) {

	if svcCfg == nil {
		svcCfg = svc.Spec.Config
	}

	var err error

	if ucorev1.ToService(svc).IsKubernetes() {
		return getMTLSCfgK8s(ctx, svc, svcCfg, secretMan)
	}

	if svcCfg != nil && svcCfg.ClientCertificate != nil && svcCfg.ClientCertificate.GetFromSecret() != "" {
		return getClientTLSCfgWithDeprecatedClientCert(ctx, svc, svcCfg, secretMan, upstream)
	}

	if svcCfg == nil || svcCfg.Tls == nil {
		return getGenTLSCfg(ctx, svc, secretMan, upstream)
	}

	ret := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: svcCfg.Tls.InsecureSkipVerify,
		ServerName:         upstream.SNIHost,
	}

	if len(svcCfg.Tls.TrustedCAs) > 0 {

		if svcCfg.Tls.AppendToSystemPool {
			ret.RootCAs, err = x509.SystemCertPool()
			if err != nil {
				return nil, err
			}
		} else {
			ret.RootCAs = x509.NewCertPool()
		}

		for _, caBytes := range svcCfg.Tls.TrustedCAs {
			ca, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(caBytes))
			if err != nil {
				return nil, err
			}

			ret.RootCAs.AddCert(ca)
		}

	}

	if svcCfg.Tls.ClientCertificate != nil && svcCfg.Tls.ClientCertificate.GetFromSecret() != "" {
		secret, err := secretMan.GetByName(ctx, svcCfg.Tls.ClientCertificate.GetFromSecret())
		if err != nil {
			return nil, err
		}

		if !vutils.IsCertReady(secret) {
			return nil, errors.Errorf("Secret %s is not a Certificate Secret", secret.Metadata.Name)
		}

		crt, err := ocrypto.GetTLSCertificate(secret)
		if err != nil {
			return nil, err
		}

		ret.Certificates = append(ret.Certificates, *crt)
	}

	return ret, nil
}

func getClientTLSCfgWithDeprecatedClientCert(ctx context.Context, svc *corev1.Service, svcCfg *corev1.Service_Spec_Config, secretMan *secretman.SecretManager, upstream *loadbalancer.Upstream) (*tls.Config, error) {

	if svcCfg == nil {
		svcCfg = svc.Spec.Config
	}
	if ucorev1.ToService(svc).IsKubernetes() {
		return getMTLSCfgK8s(ctx, svc, svcCfg, secretMan)
	}

	if svcCfg == nil ||
		svcCfg.ClientCertificate == nil ||
		svcCfg.ClientCertificate.GetFromSecret() == "" {
		return getGenTLSCfg(ctx, svc, secretMan, upstream)
	}

	secret, err := secretMan.GetByName(ctx, svcCfg.ClientCertificate.GetFromSecret())
	if err != nil {
		return nil, err
	}

	if !vutils.IsCertReady(secret) {
		return nil, errors.Errorf("Secret %s is not a Certificate Secret", secret.Metadata.Name)
	}

	crt, err := ocrypto.GetTLSCertificate(secret)
	if err != nil {
		return nil, err
	}

	ret := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			*crt,
		},
	}

	if len(svcCfg.ClientCertificate.TrustedCAs) > 0 {
		pool := x509.NewCertPool()

		for _, caBytes := range svcCfg.ClientCertificate.TrustedCAs {
			ca, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(caBytes))
			if err != nil {
				return nil, err
			}

			pool.AddCert(ca)
		}

		ret.RootCAs = pool
	}

	return ret, nil
}

func getMTLSCfgK8s(ctx context.Context, svc *corev1.Service, svcCfg *corev1.Service_Spec_Config, secretMan *secretman.SecretManager) (*tls.Config, error) {
	if svcCfg == nil || svcCfg.GetKubernetes() == nil {
		return nil, nil
	}

	k8sSpec := svcCfg.GetKubernetes()

	ret := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	switch k8sSpec.Type.(type) {
	case *corev1.Service_Spec_Config_Kubernetes_ClientCertificate:

		cfg := k8sSpec.GetClientCertificate()

		var pool *x509.CertPool

		if len(cfg.TrustedCAs) > 0 {
			pool = x509.NewCertPool()

			for _, caBytes := range cfg.TrustedCAs {
				ca, err := utils_cert.ParsePEMCertificate(caBytes)
				if err != nil {
					return nil, err
				}
				pool.AddCert(ca)
			}
		}

		ret.RootCAs = pool

		secret, err := secretMan.GetByName(ctx, cfg.GetFromSecret())
		if err != nil {
			return nil, err
		}

		if !vutils.IsCertReady(secret) {
			return nil, errors.Errorf("Secret %s is not a Certificate Secret", secret.Metadata.Name)
		}
		crt, err := ocrypto.GetTLSCertificate(secret)
		if err != nil {
			return nil, err
		}

		ret.Certificates = append(ret.Certificates, *crt)
	case *corev1.Service_Spec_Config_Kubernetes_BearerToken_:
		cfg := k8sSpec.GetBearerToken()

		var pool *x509.CertPool

		if len(cfg.TrustedCAs) > 0 {
			pool = x509.NewCertPool()

			for _, caBytes := range cfg.TrustedCAs {
				ca, err := utils_cert.ParsePEMCertificate(caBytes)
				if err != nil {
					return nil, err
				}
				pool.AddCert(ca)
			}
		}

		ret.RootCAs = pool
	case *corev1.Service_Spec_Config_Kubernetes_Kubeconfig_:
		kubeConfigSecret, err := secretMan.GetByName(ctx, k8sSpec.GetKubeconfig().GetFromSecret())
		if err != nil {
			return nil, err
		}
		kubeconfig, err := k8sutils.UnmarshalKubeConfigFromYAML(ucorev1.ToSecret(kubeConfigSecret).GetValueBytes())
		if err != nil {
			return nil, err
		}

		clstr := kubeconfig.GetCluster(k8sSpec.GetKubeconfig().Context)

		if clstr.Cluster.CertificateAuthorityData == "" {
			return nil, nil
		}

		ca, err := utils_cert.ParseBase64PEMCertificate(clstr.Cluster.CertificateAuthorityData)
		if err != nil {
			return nil, err
		}

		pool := x509.NewCertPool()
		pool.AddCert(ca)
		ret.RootCAs = pool

		usr := kubeconfig.GetUser(k8sSpec.GetKubeconfig().Context)

		if usr.User.ClientCertificateData != "" && usr.User.ClientKeyData != "" {
			crtPEM, err := base64.StdEncoding.DecodeString(usr.User.ClientCertificateData)
			if err != nil {
				return nil, err
			}

			keyPEM, err := base64.StdEncoding.DecodeString(usr.User.ClientKeyData)
			if err != nil {
				return nil, err
			}

			crt, err := tls.X509KeyPair(crtPEM, keyPEM)
			if err != nil {
				return nil, err
			}

			ret.Certificates = append(ret.Certificates, crt)
		}

	default:
		return nil, nil
	}

	return ret, nil
}

func getGenTLSCfg(ctx context.Context, svc *corev1.Service, secretMan *secretman.SecretManager, upstream *loadbalancer.Upstream) (*tls.Config, error) {
	if !upstream.IsUser {
		return nil, nil
	}
	switch upstream.URL.Scheme {
	case "https", "tls":
	default:
		return nil, nil
	}

	ret := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		ServerName: upstream.SNIHost,
	}

	return ret, nil
}
