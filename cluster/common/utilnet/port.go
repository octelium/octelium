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

package utilnet

import "github.com/pkg/errors"

func GetPortFromScheme(arg string) (int, error) {
	if arg == "" {
		return 0, errors.Errorf("Please provide port in the url")
	}
	switch arg {
	case "http", "ws", "h2c":
		return 80, nil
	case "https", "wss":
		return 443, nil
	case "ssh":
		return 22, nil
	case "dns":
		return 53, nil
	case "postgres", "postgresql":
		return 5432, nil
	case "redis":
		return 6379, nil
	case "mysql":
		return 3306, nil
	case "mongodb":
		return 27017, nil
	case "rdp":
		return 3389, nil
	case "amqp":
		return 5672, nil
	case "ftp":
		return 21, nil
	case "dot":
		return 853, nil
	default:
		return 0, errors.Errorf("Unknown scheme %s. Please provide port number", arg)
	}
}
