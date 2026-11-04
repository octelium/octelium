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
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"k8s.io/client-go/util/retry"
)

func (g *Genesis) ensureNamespace(ctx context.Context, desired *corev1.Namespace) error {
	if desired.GetMetadata().GetName() == "" {
		return errors.Errorf("Namespace name is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	desired = proto.Clone(desired).(*corev1.Namespace)
	if desired.Spec == nil {
		desired.Spec = &corev1.Namespace_Spec{}
	}
	if desired.Status == nil {
		desired.Status = &corev1.Namespace_Status{}
	}
	_, err := createInitResource(ctx, desired, g.octeliumC.CoreC().GetNamespace, g.octeliumC.CoreC().CreateNamespace)
	return err
}

func (g *Genesis) ensureService(ctx context.Context, desired *corev1.Service) error {
	if desired.GetMetadata().GetName() == "" {
		return errors.Errorf("Service name is required")
	}
	desired = proto.Clone(desired).(*corev1.Service)
	if desired.Spec == nil {
		desired.Spec = &corev1.Service_Spec{}
	}
	if desired.Status == nil {
		desired.Status = &corev1.Service_Status{}
	}
	srv := admin.NewServer(&admin.Opts{OcteliumC: g.octeliumC, IsEmbedded: true})
	err := retry.OnError(retry.DefaultRetry, grpcerr.IsResourceChanged, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		created := false
		existing, err := createInitResource(ctx, desired, g.octeliumC.CoreC().GetService,
			func(ctx context.Context, service *corev1.Service, _ ...grpc.CallOption) (*corev1.Service, error) {
				result, err := srv.DoCreateService(ctx, service, service.Metadata.IsSystem)
				created = err == nil
				return result, err
			})
		if err != nil {
			return err
		}
		if created || !desired.Metadata.IsSystem {
			return nil
		}
		if !existing.GetMetadata().GetIsSystem() {
			return errors.Errorf("Service %s is not a system Service. Refusing to replace it", desired.Metadata.Name)
		}
		updated := proto.Clone(existing).(*corev1.Service)
		updated.Spec = proto.Clone(desired.Spec).(*corev1.Service_Spec)
		if updated.Status == nil {
			updated.Status = &corev1.Service_Status{}
		}
		updated.Status.ManagedService = nil
		if desired.Status.ManagedService != nil {
			updated.Status.ManagedService = proto.Clone(desired.Status.ManagedService).(*corev1.Service_Status_ManagedService)
		}
		mergeServiceMetadata(updated.Metadata, desired.Metadata)
		if proto.Equal(existing, updated) {
			return nil
		}
		_, err = g.octeliumC.CoreC().UpdateService(ctx, updated)
		return err
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func mergeServiceMetadata(existing, desired *metav1.Metadata) {
	if existing.DisplayName == "" {
		existing.DisplayName = desired.DisplayName
	}
	if existing.Description == "" {
		existing.Description = desired.Description
	}
	existing.IsUserHidden = desired.IsUserHidden
	existing.IsSystemHidden = desired.IsSystemHidden
	for key, value := range desired.SystemLabels {
		if existing.SystemLabels == nil {
			existing.SystemLabels = make(map[string]string)
		}
		existing.SystemLabels[key] = value
	}
}
