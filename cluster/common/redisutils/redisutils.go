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

package redisutils

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/pkg/utils/ldflags"
)

func NewClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr: func() string {
			if ldflags.IsTest() {
				return "localhost:6379"
			}

			port, _ := strconv.Atoi(os.Getenv("OCTELIUM_REDIS_PORT"))
			if port == 0 {
				port = 6379
			}
			return net.JoinHostPort(os.Getenv("OCTELIUM_REDIS_HOST"), fmt.Sprintf("%d", port))
		}(),
		Username: os.Getenv("OCTELIUM_REDIS_USERNAME"),
		Password: func() string {
			if ldflags.IsTest() {
				return ""
			} else {
				return os.Getenv("OCTELIUM_REDIS_PASSWORD")
			}
		}(),
		DB: func() int {
			if os.Getenv("OCTELIUM_REDIS_DATABASE") == "" {
				return 0
			} else {
				db, err := strconv.Atoi(os.Getenv("OCTELIUM_REDIS_DATABASE"))
				if err == nil {
					return db
				}
				return 0
			}
		}(),
		TLSConfig: func() *tls.Config {
			if os.Getenv("OCTELIUM_REDIS_USE_TLS") == "true" {
				return &tls.Config{
					MinVersion: tls.VersionTLS12,
				}
			}
			return nil
		}(),
	})
}
