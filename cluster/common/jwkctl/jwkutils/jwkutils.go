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

package jwkutils

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

func CreateJWKSecret(ctx context.Context, octeliumC octeliumc.ClientInterface) (*corev1.Secret, error) {

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	privPEM, err := utils_cert.GetPrivateKeyPEM(priv)
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("sys:root-secret-%s", utilrand.GetRandomStringLowercase(8)),
			SystemLabels: map[string]string{
				"octelium-root-secret": "true",
				"type":                 "ed25519",
			},
			IsSystem:       true,
			IsSystemHidden: true,
			IsUserHidden:   true,
		},

		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},

		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{
				ValueBytes: privPEM,
			},
		},
	}

	return octeliumC.CoreC().CreateSecret(ctx, secret)
}
