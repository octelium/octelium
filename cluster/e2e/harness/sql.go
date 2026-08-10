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

package harness

import (
	"database/sql"
	"testing"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const SQLConnectBudget = 60 * time.Second

func (h *H) OpenSQL(t *testing.T, driver, dsn string) *sql.DB {
	t.Helper()

	db, err := ConnectSQL(driver, dsn, SQLConnectBudget)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	t.Cleanup(func() { db.Close() })
	return db
}

func ConnectSQL(driver, dsn string, budget time.Duration) (*sql.DB, error) {
	deadline := time.Now().Add(budget)

	var lastErr error
	for time.Now().Before(deadline) {
		db, err := sql.Open(driver, dsn)
		if err == nil {
			if err = db.Ping(); err == nil {
				return db, nil
			}
			db.Close()
		}

		lastErr = err
		zap.L().Debug("Retrying connection to db", zap.String("driver", driver), zap.Error(err))
		time.Sleep(time.Second)
	}

	return nil, errors.Errorf("Could not connect to the %s database after %s: %+v",
		driver, budget, lastErr)
}
