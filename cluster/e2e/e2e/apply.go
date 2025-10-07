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
---
kind: Service
metadata:
  name: mariadb
spec:
  mode: MYSQL
  config:
    upstream:
      container:
        image: mariadb
        port: 3306
        env:
          - name: MARIADB_ROOT_PASSWORD
            value: password
    mysql:
      user: root
      database: mysql
      auth:
        password:
          fromSecret: password
---
kind: Service
metadata:
  name: minio
spec:
  mode: HTTP
  config:
    upstream:
      container:
        image: minio/minio
        port: 9000
        args: ["server", "/data"]
        env:
          - name: MINIO_ROOT_USER
            value: octelium_minio
          - name: MINIO_ROOT_PASSWORD
            value: password
    http:
      auth:
        sigv4:
          accessKeyID: octelium_minio
          secretAccessKey:
            fromSecret: password
          service: s3
          region: us-east-1
---
kind: Service
metadata:
  name: opensearch
spec:
  mode: HTTP
  config:
    upstream:
      container:
        image: opensearchproject/opensearch:latest
        port: 9200
        env:
          - name: discovery.type
            value: single-node
          - name: OPENSEARCH_INITIAL_ADMIN_PASSWORD
            value: Password_123456
---
kind: Service
metadata:
  name: mcp-echo
spec:
  mode: HTTP
  isPublic: true
  port: 80
  config:
    upstream:
      url: http://localhost:16001
      user: root
---
kind: Service
metadata:
  name: clickhouse
spec:
  mode: TCP
  config:
    upstream:
      container:
        image: clickhouse/clickhouse-server
        port: 9000
        env:
          - name: CLICKHOUSE_USER
            value: octelium
          - name: CLICKHOUSE_PASSWORD
            value: password
---
kind: Service
metadata:
  name: ollama
spec:
  port: 11434
  mode: HTTP
  isPublic: true
  config:
    upstream:
      container:
        port: 11434
        image: ollama/ollama
        resourceLimit:
          cpu:
            millicores: 6000
          memory:
            megabytes: 12000
---
kind: Service
metadata:
  name: mongo
spec:
  mode: TCP
  config:
    upstream:
      container:
        image: mongo
        port: 27017
        env:
          - name: MONGO_INITDB_ROOT_USERNAME
            value: octelium
          - name: MONGO_INITDB_ROOT_PASSWORD
            value: password
`
