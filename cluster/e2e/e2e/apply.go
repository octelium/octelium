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

package e2e

const cfg1 = `
kind: User
metadata:
  name: john
spec:
  type: HUMAN
  email: john@example.com
  groups: ["admins"]
---
kind: User
metadata:
  name: microservice1
spec:
  type: WORKLOAD
  groups: ["admins"]
---
kind: Group
metadata:
  name: admins
spec:
  authorization:
    policies: ["allow-all"]
---
kind: Namespace
metadata:
  name: production
spec: {}
---
kind: Namespace
metadata:
  name: development
spec:
  authorization:
    policies: ["allow-all"]
---
kind: Service
metadata:
  name: nginx
spec:
  mode: WEB
  isPublic: true
  config:
    upstream:
      container:
        image: nginx
        port: 80
---
kind: Service
metadata:
  name: google
spec:
  mode: WEB
  isPublic: true
  config:
    upstream:
      url: https://www.google.com
---
kind: Service
metadata:
  name: nginx-anonymous
spec:
  mode: WEB
  isPublic: true
  isAnonymous: true
  config:
    upstream:
      container:
        image: nginx
        port: 80
---
kind: Service
metadata:
  name: pg
spec:
  mode: TCP
  port: 5432
  config:
    upstream:
      container:
        image: postgres
        port: 5432
        env:
          - name: POSTGRES_PASSWORD
            value: password
---
kind: Service
metadata:
  name: pg.production
spec:
  mode: TCP
  port: 5432
  config:
    upstream:
      container:
        image: postgres
        port: 5432
        env:
          - name: POSTGRES_PASSWORD
            value: password
---
kind: Service
metadata:
  name: postgres-main
spec:
  mode: POSTGRES
  port: 5432
  config:
    upstream:
      url: postgres://octelium-pg-postgresql.default.svc
    postgres:
      user: octelium
      database: octelium
      auth:
        password:
          fromSecret: pg
---
kind: Service
metadata:
  name: essh
spec:
  mode: SSH
  config:
    ssh:
      eSSHMode: true
---
kind: Service
metadata:
  name: redis
spec:
  mode: TCP
  port: 6379
  config:
    upstream:
      container:
        image: redis
        port: 6379
---
kind: Service
metadata:
  name: ws-echo
spec:
  mode: WEB
  isPublic: true
  port: 80
  config:
    upstream:
      url: http://localhost:16000
      user: root
---
kind: Service
metadata:
  name: nats
spec:
  mode: TCP
  config:
    upstream:
      container:
        image: nats
        port: 4222
`
