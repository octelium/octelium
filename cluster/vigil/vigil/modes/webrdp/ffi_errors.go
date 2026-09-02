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

package webrdp

import "github.com/pkg/errors"

var (
	errCredsspUnavailable = errors.New("webrdp secretless RDP requires cgo and the webrdp_credssp build tag")
	errCredsspKDCRequired = errors.New("CredSSP requires Kerberos KDC access")
	errCredsspAuthFailed  = errors.New("CredSSP authentication failed")
)
