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

package celengine

import (
	"context"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

type opaEngine struct {
	c *cache.Cache
}

type opaOpts struct {
}

func newOPAEngine(ctx context.Context, opts *opaOpts) (*opaEngine, error) {
	return &opaEngine{
		c: cache.New(24*time.Hour, 10*time.Minute),
	}, nil
}

func (e *opaEngine) EvalPolicy(ctx context.Context, script string, input map[string]any) (bool, error) {
	if script == "" {
		return false, nil
	}
	pq, err := e.getOrSetPQ(ctx, script)
	if err != nil {
		return false, err
	}

	// startedAt := time.Now()
	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, err
	}

	/*
		zap.L().Debug("OPA evaluation done",
			zap.Float32("time microsec", float32(time.Since(startedAt).Nanoseconds())/1000),
			zap.String("script", script),
		)
	*/

	if len(rs) < 1 || len(rs[0].Expressions) < 1 {
		return false, nil
	}

	for _, exp := range rs[0].Expressions {
		if exp.Text == "data.octelium.condition.match" {
			ret, _ := exp.Value.(bool)
			return ret, nil
		}
	}

	return false, nil
}

func (e *opaEngine) AddPolicy(ctx context.Context, script string) error {

	_, err := e.getOrSetPQ(ctx, script)
	return err
}

func (e *opaEngine) getOrSetPQ(ctx context.Context, script string) (*rego.PreparedEvalQuery, error) {

	if len(script) > 20000 {
		return nil, errors.Errorf("OPA script is too long")
	}

	key := getKey(script)
	cacheI, ok := e.c.Get(key)
	if ok {
		return cacheI.(*rego.PreparedEvalQuery), nil
	}

	// startedAt := time.Now()
	rg := rego.New(
		rego.Query("data.octelium.condition.match"),
		rego.Module("octelium.condition", script),
	)

	pq, err := rg.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	e.c.Set(key, &pq, cache.DefaultExpiration)
	/*
		zap.L().Debug("OPA preparation done",
			zap.Float32("time microsec", float32(time.Since(startedAt).Nanoseconds())/1000),
			zap.String("script", script),
		)
	*/

	return &pq, nil
}
