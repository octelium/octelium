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

package common

import (
	"regexp"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
)

func MetadataFrom(req *metav1.Metadata) *metav1.Metadata {
	return &metav1.Metadata{
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Labels:      req.Labels,
		Annotations: req.Annotations,
		Tags:        req.Tags,
		PicURL:      req.PicURL,
	}
}

func MetadataUpdate(to *metav1.Metadata, from *metav1.Metadata) {
	to.DisplayName = from.DisplayName
	to.Description = from.Description
	to.Labels = from.Labels
	to.Annotations = from.Annotations
	to.SpecLabels = from.SpecLabels
	to.PicURL = from.PicURL
	to.Tags = from.Tags
}

var rgxName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)

func CheckGetOrDeleteOptions(req geTorDeleteI) error {

	if req.GetName() != "" && !rgxName.MatchString(req.GetName()) {
		return serr.InvalidArg("Invalid name: %s", req.GetName())
	}

	if req.GetUid() != "" && !govalidator.IsUUIDv4(req.GetUid()) {
		return serr.InvalidArg("Invalid UID: %s", req.GetUid())
	}

	if req.GetUid() != "" && req.GetName() != "" {
		return serr.InvalidArg("Either the UID or the name must be used")
	}

	if req.GetUid() == "" && req.GetName() == "" {
		return serr.InvalidArg("Both the UID and the name are empty")
	}

	return nil
}

type geTorDeleteI interface {
	GetName() string
	GetUid() string
}

func GetNamespace(ns string) string {
	if ns == "" {
		return "default"
	}
	return ns
}
