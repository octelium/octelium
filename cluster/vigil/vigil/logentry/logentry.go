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

package logentry

import (
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type InitializeLogEntryOpts struct {
	StartTime       time.Time
	ReqCtx          *corev1.RequestContext
	IsAuthenticated bool
	IsAuthorized    bool
	ConnectionID    string
	SessionID       string
	Sequence        int64
	Reason          *corev1.AccessLog_Entry_Common_Reason
}

func InitializeLogEntry(opts *InitializeLogEntryOpts) *corev1.AccessLog {
	logE := vutils.GenerateLog()
	i := opts.ReqCtx

	if i == nil {
		return nil
	}

	logE.Metadata.ActorRef = umetav1.GetObjectReference(i.Session)
	logE.Metadata.TargetRef = umetav1.GetObjectReference(i.Service)

	logE.Entry = &corev1.AccessLog_Entry{
		Common: &corev1.AccessLog_Entry_Common{
			StartedAt: pbutils.Timestamp(opts.StartTime.UTC()),
			EndedAt:   pbutils.Now(),
			Status: func() corev1.AccessLog_Entry_Common_Status {
				switch {
				case opts.IsAuthorized:
					return corev1.AccessLog_Entry_Common_ALLOWED
				default:
					return corev1.AccessLog_Entry_Common_DENIED
				}
			}(),
			Mode:        i.Service.Spec.Mode,
			IsPublic:    i.Service.Spec.IsPublic,
			IsAnonymous: i.Service.Spec.IsAnonymous,

			Reason: opts.Reason,

			UserRef:      umetav1.GetObjectReference(i.User),
			SessionRef:   umetav1.GetObjectReference(i.Session),
			DeviceRef:    umetav1.GetObjectReference(i.Device),
			ServiceRef:   umetav1.GetObjectReference(i.Service),
			NamespaceRef: i.Service.Status.NamespaceRef,
			RegionRef: &metav1.ObjectReference{
				ApiVersion: ucorev1.APIVersion,
				Kind:       ucorev1.KindRegion,
				Name:       vutils.GetMyRegionName(),
				Uid:        vutils.GetMyRegionUID(),
			},
			ConnectionID: opts.ConnectionID,
			SessionID:    opts.SessionID,
			Sequence:     opts.Sequence,
		},
		Info: &corev1.AccessLog_Entry_Info{},
	}

	return logE
}
