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

package secretman

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type SecretManager struct {
	mu          sync.Mutex
	octeliumC   octeliumc.ClientInterface
	c           *cache.Cache
	vCache      *vcache.Cache
	secretNames []string
	oauth2ccMap struct {
		sync.Mutex
		oauth2ccMap map[string]*oauth2ClientCredentialsInfo
	}
}

type oauth2ClientCredentialsInfo struct {
	TokenSource oauth2.TokenSource
}

func New(ctx context.Context, octeliumC octeliumc.ClientInterface, vCache *vcache.Cache) (*SecretManager, error) {

	ret := &SecretManager{
		octeliumC: octeliumC,
		c:         cache.New(cache.NoExpiration, 10*time.Minute),
		vCache:    vCache,
	}

	ret.oauth2ccMap.oauth2ccMap = make(map[string]*oauth2ClientCredentialsInfo)

	return ret, nil
}

func (s *SecretManager) GetByName(ctx context.Context, name string) (*corev1.Secret, error) {
	if sI, ok := s.c.Get(name); ok {
		return sI.(*corev1.Secret), nil
	}

	ret, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: name})
	if err != nil {
		return nil, err
	}

	s.c.Set(ret.Metadata.Name, ret, 0)

	return ret, nil
}

func (s *SecretManager) Set(secret *corev1.Secret) {
	if !s.isInSecretNames(secret.Metadata.Name) {
		return
	}

	s.c.Set(secret.Metadata.Name, secret, 0)

	/*
		if s.oauth2CCSecret != nil && s.oauth2CCSecret.name == secret.Metadata.Name {
			defer func() error {
				zap.L().Debug("Setting oauth2 client credentials after Secret set")
				if err := s.setOAuth2ClientCredentialsSecret(context.Background()); err != nil {
					zap.L().Warn("Could not set oauth2 client credentials secret after Secret set", zap.Error(err))
				}
				return nil
			}()
		}
	*/
}

func (s *SecretManager) Delete(secret *corev1.Secret) {
	if !s.isInSecretNames(secret.Metadata.Name) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := len(s.secretNames) - 1; i >= 0; i-- {
		if s.secretNames[i] == secret.Metadata.Name {
			s.secretNames = append(s.secretNames[0:i], s.secretNames[i+1:]...)
		}
	}

	s.c.Delete(secret.Metadata.Name)
}

func (s *SecretManager) isInSecretNames(name string) bool {
	for _, cur := range s.secretNames {
		if cur == name {
			return true
		}
	}
	return false
}

func (s *SecretManager) ApplyService(ctx context.Context) error {
	zap.S().Debugf("Apply Service Secrets")
	s.mu.Lock()
	defer s.mu.Unlock()
	zap.S().Debugf("Initial secret names: %+v", s.secretNames)
	s.secretNames = nil

	s.c.Flush()

	svc := s.vCache.GetService()
	if svc == nil {
		return errors.Errorf("Nil Service in Vigil's cache")
	}

	doAppend := func(secretName string) {
		if !s.isInSecretNames(secretName) {
			s.secretNames = append(s.secretNames, secretName)
		}
	}

	doSetCfgSecrets := func(cfg *corev1.Service_Spec_Config) {
		if cfg == nil {
			return
		}
		if cfg.GetSsh() != nil {
			if cfg.GetSsh().Auth != nil &&
				cfg.GetSsh().Auth.GetPassword() != nil &&
				cfg.GetSsh().Auth.GetPassword().GetFromSecret() != "" {
				doAppend(cfg.GetSsh().Auth.GetPassword().GetFromSecret())
			}

			if cfg.GetSsh().Auth != nil && cfg.GetSsh().Auth.GetPrivateKey() != nil &&
				cfg.GetSsh().Auth.GetPrivateKey().GetFromSecret() != "" {
				doAppend(cfg.GetSsh().Auth.GetPrivateKey().GetFromSecret())
			}
		}

		if cfg.GetPostgres() != nil {
			if cfg.GetPostgres().Auth != nil &&
				cfg.GetPostgres().Auth.GetPassword() != nil &&
				cfg.GetPostgres().Auth.GetPassword().GetFromSecret() != "" {
				doAppend(cfg.GetPostgres().Auth.GetPassword().GetFromSecret())
			}
		}

		if cfg.GetHttp() != nil && cfg.GetHttp().GetAuth() != nil {
			authS := cfg.GetHttp().GetAuth()
			if authS.GetBearer() != nil && authS.GetBearer().GetFromSecret() != "" {
				doAppend(authS.GetBearer().GetFromSecret())
			}

			if authS.GetBasic() != nil && authS.GetBasic().GetPassword() != nil &&
				authS.GetBasic().GetPassword().GetFromSecret() != "" {
				doAppend(authS.GetBasic().GetPassword().GetFromSecret())
			}

			if authS.GetCustom() != nil && authS.GetCustom().GetValue() != nil &&
				authS.GetCustom().GetValue().GetFromSecret() != "" {
				doAppend(authS.GetCustom().GetValue().GetFromSecret())
			}

			if authS.GetSigv4() != nil && authS.GetSigv4().GetSecretAccessKey() != nil &&
				authS.GetSigv4().GetSecretAccessKey().GetFromSecret() != "" {
				doAppend(authS.GetSigv4().GetSecretAccessKey().GetFromSecret())
			}

			if authS.GetOauth2ClientCredentials() != nil &&
				authS.GetOauth2ClientCredentials().GetClientSecret() != nil &&
				authS.GetOauth2ClientCredentials().GetClientSecret().GetFromSecret() != "" {
				doAppend(authS.GetOauth2ClientCredentials().GetClientSecret().GetFromSecret())

				defer s.setOAuth2CCToken(ctx, &GetOAuth2CCTokenReq{
					ClientID:   authS.GetOauth2ClientCredentials().ClientID,
					TokenURL:   authS.GetOauth2ClientCredentials().TokenURL,
					Scopes:     authS.GetOauth2ClientCredentials().Scopes,
					SecretName: authS.GetOauth2ClientCredentials().GetClientSecret().GetFromSecret(),
				})
			}

		}

		if cfg.GetKubernetes() != nil {
			k8sC := svc.Spec.GetConfig().GetKubernetes()

			if k8sC.GetClientCertificate() != nil &&
				k8sC.GetClientCertificate().GetFromSecret() != "" {
				doAppend(k8sC.GetClientCertificate().GetFromSecret())
			}

			if k8sC.GetBearerToken() != nil &&
				k8sC.GetBearerToken().GetFromSecret() != "" {
				doAppend(k8sC.GetBearerToken().GetFromSecret())
			}

			if k8sC.GetKubeconfig() != nil && k8sC.GetKubeconfig().GetFromSecret() != "" {
				doAppend(k8sC.GetKubeconfig().GetFromSecret())
			}
		}
	}

	doSetCfgSecrets(svc.Spec.Config)
	if svc.Spec.DynamicConfig != nil {
		for _, cfg := range svc.Spec.DynamicConfig.Configs {
			doSetCfgSecrets(cfg)
		}
	}

	return s.setSecretNames(ctx)
}

func (s *SecretManager) setSecretNames(ctx context.Context) error {
	for _, name := range s.secretNames {
		secret, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: name})
		if err != nil {
			return err
		}
		s.c.Set(secret.Metadata.Name, secret, 0)
	}

	return nil
}

/*
func (s *SecretManager) setOAuth2ClientCredentialsSecret(ctx context.Context) error {
	if s.oauth2CCSecret == nil {
		return nil
	}
	s.oauth2CCSecret.Lock()
	defer s.oauth2CCSecret.Unlock()

	secret, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: s.oauth2CCSecret.name})
	if err != nil {
		return err
	}
	cfg := &clientcredentials.Config{
		ClientID:     s.oauth2CCSecret.clientID,
		ClientSecret: secret.GetValueStr(),
		TokenURL:     s.oauth2CCSecret.tokenURL,
		Scopes:       s.oauth2CCSecret.scopes,
	}

	s.oauth2CCSecret.TokenSource = cfg.TokenSource(context.Background())

	return nil
}
*/

func (s *SecretManager) GetOAuth2CCToken(ctx context.Context, req *GetOAuth2CCTokenReq) (string, error) {

	tkn, err := s.getOAuth2CCToken(ctx, req)
	if err == nil {
		return tkn, nil
	} else if errors.Is(err, errOAuth2CCNotFound) {
		return s.setOAuth2CCToken(ctx, req)
	} else {
		return "", err
	}
}

func (s *SecretManager) getOAuth2CCToken(ctx context.Context, req *GetOAuth2CCTokenReq) (string, error) {
	s.oauth2ccMap.Lock()
	defer s.oauth2ccMap.Unlock()
	ret, ok := s.oauth2ccMap.oauth2ccMap[req.getID()]
	if !ok {
		return "", errOAuth2CCNotFound
	}
	tkn, err := ret.TokenSource.Token()
	if err != nil {
		return "", err
	}
	return tkn.AccessToken, nil
}

var errOAuth2CCNotFound = errors.New("cc info not found")

func (s *SecretManager) setOAuth2CCToken(ctx context.Context, req *GetOAuth2CCTokenReq) (string, error) {
	s.oauth2ccMap.Lock()
	defer s.oauth2ccMap.Unlock()
	secret, err := s.GetByName(ctx, req.SecretName)
	if err != nil {
		return "", err
	}
	cfg := &clientcredentials.Config{
		ClientID:     req.ClientID,
		ClientSecret: ucorev1.ToSecret(secret).GetValueStr(),
		TokenURL:     req.TokenURL,
		Scopes:       req.Scopes,
	}

	tknSrc := cfg.TokenSource(context.Background())
	s.oauth2ccMap.oauth2ccMap[req.getID()] = &oauth2ClientCredentialsInfo{
		TokenSource: tknSrc,
	}

	tkn, err := tknSrc.Token()
	if err != nil {
		return "", err
	}

	return tkn.AccessToken, nil
}

type GetOAuth2CCTokenReq struct {
	ClientID   string
	SecretName string
	TokenURL   string
	Scopes     []string
}

func (r *GetOAuth2CCTokenReq) getID() string {
	shaHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", r.ClientID, r.SecretName, r.TokenURL)))
	return base64.StdEncoding.EncodeToString(shaHash[:16])
}
