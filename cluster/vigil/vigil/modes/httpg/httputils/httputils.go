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

package httputils

import (
	"net/http"
	"strings"
)

func GetHeaders(arg map[string][]string) map[string]string {
	ret := make(map[string]string, len(arg))

	for k, v := range arg {
		key := strings.ToLower(k)
		if len(v) < 1 {
			ret[key] = ""
		} else {
			ret[key] = v[0]
		}
	}

	return ret
}

func IsHTMLPage(req *http.Request) bool {

	return strings.Contains(req.Header.Get("Accept"), "text/html") && req.Method == "GET"
}
