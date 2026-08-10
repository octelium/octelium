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

package harness

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
)

func (h *H) Name() string {
	return utilrand.GetRandomStringCanonical(8)
}

func (h *H) CreateService(t *testing.T, svc *corev1.Service) *corev1.Service {
	t.Helper()

	if svc.Metadata == nil {
		svc.Metadata = &metav1.Metadata{}
	}
	if svc.Metadata.Name == "" {
		svc.Metadata.Name = h.Name()
	}

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.CreateService(ctx, svc)
	if err != nil {
		t.Fatalf("Could not create the Service %s: %+v", svc.Metadata.Name, err)
	}

	t.Cleanup(func() {
		h.deleteQuietly(t, "Service", ret.Metadata.Name, func(ctx context.Context) error {
			_, err := h.coreC.DeleteService(ctx, &metav1.DeleteOptions{Uid: ret.Metadata.Uid})
			return err
		})
	})

	zap.L().Debug("Created Service fixture", zap.String("name", ret.Metadata.Name))
	return ret
}

func (h *H) CreateUser(t *testing.T, usr *corev1.User) *corev1.User {
	t.Helper()

	if usr.Metadata == nil {
		usr.Metadata = &metav1.Metadata{}
	}
	if usr.Metadata.Name == "" {
		usr.Metadata.Name = h.Name()
	}

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.CreateUser(ctx, usr)
	if err != nil {
		t.Fatalf("Could not create the User %s: %+v", usr.Metadata.Name, err)
	}

	t.Cleanup(func() {
		h.deleteQuietly(t, "User", ret.Metadata.Name, func(ctx context.Context) error {
			_, err := h.coreC.DeleteUser(ctx, &metav1.DeleteOptions{Uid: ret.Metadata.Uid})
			return err
		})
	})

	zap.L().Debug("Created User fixture", zap.String("name", ret.Metadata.Name))
	return ret
}

func (h *H) CreateWorkloadUser(t *testing.T,
	authz *corev1.User_Spec_Authorization) *corev1.User {
	t.Helper()

	return h.CreateUser(t, &corev1.User{
		Spec: &corev1.User_Spec{
			Type:          corev1.User_Spec_WORKLOAD,
			Authorization: authz,
		},
	})
}

type CredentialOpts struct {
	User        string
	Type        corev1.Credential_Spec_Type
	SessionType corev1.Session_Status_Type
	ExpiresIn   time.Duration
}

func (h *H) CreateCredential(t *testing.T, o CredentialOpts) *corev1.Credential {
	t.Helper()

	expiresIn := o.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 24 * time.Hour
	}

	ctx, cancel := h.opCtx(t)
	defer cancel()

	cred, err := h.coreC.CreateCredential(ctx, &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name: o.User + "-" + utilrand.GetRandomStringCanonical(4),
		},
		Spec: &corev1.Credential_Spec{
			Type:        o.Type,
			User:        o.User,
			SessionType: o.SessionType,
			ExpiresAt:   pbutils.Timestamp(time.Now().Add(expiresIn)),
		},
	})
	if err != nil {
		t.Fatalf("Could not create a Credential for the User %s: %+v", o.User, err)
	}

	t.Cleanup(func() {
		h.deleteQuietly(t, "Credential", cred.Metadata.Name, func(ctx context.Context) error {
			_, err := h.coreC.DeleteCredential(ctx, &metav1.DeleteOptions{Uid: cred.Metadata.Uid})
			return err
		})
	})

	return cred
}

func (h *H) CredentialToken(t *testing.T, cred *corev1.Credential) *corev1.CredentialToken {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	tkn, err := h.coreC.GenerateCredentialToken(ctx,
		&corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
	if err != nil {
		t.Fatalf("Could not generate a token for the Credential %s: %+v",
			cred.Metadata.Name, err)
	}

	return tkn
}

func (h *H) UpdateService(t *testing.T, svc *corev1.Service) *corev1.Service {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.UpdateService(ctx, svc)
	if err != nil {
		t.Fatalf("Could not update the Service %s: %+v", svc.Metadata.Name, err)
	}

	return ret
}

func (h *H) UpdateUser(t *testing.T, usr *corev1.User) *corev1.User {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.UpdateUser(ctx, usr)
	if err != nil {
		t.Fatalf("Could not update the User %s: %+v", usr.Metadata.Name, err)
	}

	return ret
}

func (h *H) ClusterConfig(t *testing.T) *corev1.ClusterConfig {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
	if err != nil {
		t.Fatalf("Could not get the ClusterConfig: %+v", err)
	}

	return ret
}

func (h *H) UpdateClusterConfig(t *testing.T, cc *corev1.ClusterConfig) *corev1.ClusterConfig {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.UpdateClusterConfig(ctx, cc)
	if err != nil {
		t.Fatalf("Could not update the ClusterConfig: %+v", err)
	}

	return ret
}

func (h *H) deleteQuietly(t *testing.T, kind, name string, fn func(ctx context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := fn(ctx); err != nil {
		if grpcerr.IsNotFound(err) {
			return
		}
		zap.L().Warn("Could not clean up fixture",
			zap.String("kind", kind), zap.String("name", name), zap.Error(err))
	}
}
