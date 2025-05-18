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

package k8sutils

import (
	"gopkg.in/yaml.v3"
)

type KubeConfig struct {
	APIVersion     string              `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind           string              `json:"kind,omitempty" yaml:"kind,omitempty"`
	Preferences    struct{}            `json:"preferences" yaml:"preferences"`
	Clusters       []KubeConfigCluster `json:"clusters,omitempty" yaml:"clusters,omitempty"`
	Users          []KubeConfigUser    `json:"users,omitempty" yaml:"users,omitempty"`
	Contexts       []KubeConfigContext `json:"contexts,omitempty" yaml:"contexts,omitempty"`
	CurrentContext string              `json:"current-context,omitempty" yaml:"current-context,omitempty"`
}

type KubeConfigCluster struct {
	Name    string                  `json:"name,omitempty" yaml:"name,omitempty"`
	Cluster KubeConfigClusterConfig `json:"cluster,omitempty" yaml:"cluster,omitempty"`
}

type KubeConfigClusterConfig struct {
	Server                   string `json:"server,omitempty"`
	CertificateAuthorityData string `json:"certificate-authority-data,omitempty" yaml:"certificate-authority-data,omitempty"`
}

type KubeConfigUser struct {
	Name string               `json:"name,omitempty" yaml:"name,omitempty"`
	User KubeConfigUserConfig `json:"user,omitempty" yaml:"user,omitempty"`
}

type KubeConfigUserConfig struct {
	Token                 string `json:"token,omitempty" yaml:"token,omitempty"`
	ClientCertificateData string `json:"client-certificate-data,omitempty" yaml:"client-certificate-data,omitempty"`
	ClientKeyData         string `json:"client-key-data,omitempty" yaml:"client-key-data,omitempty"`
}

type KubeConfigContext struct {
	Name    string                  `json:"name"`
	Context KubeConfigContextConfig `json:"context"`
}

type KubeConfigContextConfig struct {
	Cluster string `json:"cluster"`
	User    string `json:"user"`
}

func UnmarshalKubeConfigFromYAML(in []byte) (*KubeConfig, error) {
	ret := &KubeConfig{}
	if err := yaml.Unmarshal(in, ret); err != nil {
		return nil, err
	}

	return ret, nil
}

func (i *KubeConfig) MarshalToYAML() ([]byte, error) {

	return yaml.Marshal(i)

}

func (i *KubeConfig) GetCluster(context string) *KubeConfigCluster {
	ctx := i.GetContext(context)
	if ctx == nil {
		return nil
	}

	for _, itm := range i.Clusters {
		if itm.Name == ctx.Context.Cluster {
			return &itm
		}
	}

	return nil
}

func (i *KubeConfig) GetUser(context string) *KubeConfigUser {
	ctx := i.GetContext(context)
	if ctx == nil {
		return nil
	}

	for _, itm := range i.Users {
		if itm.Name == ctx.Context.User {
			return &itm
		}
	}

	return nil
}

func (i *KubeConfig) GetContext(context string) *KubeConfigContext {

	if context != "" {
		for _, itm := range i.Contexts {
			if itm.Name == context {
				return &itm
			}
		}
	} else if i.CurrentContext != "" {
		for _, itm := range i.Contexts {
			if itm.Name == i.CurrentContext {
				return &itm
			}
		}
	}

	return nil
}
