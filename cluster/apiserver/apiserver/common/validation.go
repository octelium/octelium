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
	"github.com/microcosm-cc/bluemonday"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
)

var httpMethods = []string{"GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT", "OPTIONS", "TRACE", "HEAD"}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func sanitize(arg string) string {
	p := bluemonday.NewPolicy()

	return p.Sanitize(arg)
}

func ValidateDuration(d *metav1.Duration) error {
	if d == nil {
		return nil
	}

	seconds := umetav1.ToDuration(d).ToSeconds()

	if seconds < 1 {
		return errors.Errorf("duration cannot be shorter than 1 second")
	}
	if seconds > 60*60*24*30*12*100 {
		return errors.Errorf("Duration is too big")
	}

	return nil
}
