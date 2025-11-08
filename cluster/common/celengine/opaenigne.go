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
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

type opaEngine struct {
	c *cache.Cache
}

type opaOpts struct {
}

func newOPAEngine(_ context.Context, _ *opaOpts) (*opaEngine, error) {
	return &opaEngine{
		c: cache.New(24*time.Hour, 10*time.Minute),
	}, nil
}

func (e *opaEngine) EvalPolicy(ctx context.Context, script string, input map[string]any) (bool, error) {

	res, err := e.doEvalPolicy(ctx, script, input, "condition", "match")
	if err != nil {
		return false, nil
	}

	return res.(bool), nil
}

func (e *opaEngine) AddPolicy(ctx context.Context, script string) error {

	_, err := e.getOrSetPQ(ctx, script, "condition", "match")
	return err
}

func (e *opaEngine) getOrSetPQ(ctx context.Context, script string, mod, qry string) (*rego.PreparedEvalQuery, error) {

	if len(script) > 20000 {
		return nil, errors.Errorf("OPA script is too long")
	}

	key := getKey(script)
	cacheI, ok := e.c.Get(key)
	if ok {
		return cacheI.(*rego.PreparedEvalQuery), nil
	}

	rg := rego.New(
		rego.Query(fmt.Sprintf("data.octelium.%s.%s", mod, qry)),
		rego.Module(fmt.Sprintf("octelium.%s", mod), script),
	)

	pq, err := rg.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	e.c.Set(key, &pq, cache.DefaultExpiration)

	return &pq, nil
}

func (e *opaEngine) doEvalPolicy(ctx context.Context, script string, input map[string]any, mod, qry string) (any, error) {
	if script == "" {
		return nil, errors.Errorf("Rego script is empty")
	}
	pq, err := e.getOrSetPQ(ctx, script, mod, qry)
	if err != nil {
		return nil, err
	}

	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	if len(rs) < 1 || len(rs[0].Expressions) < 1 {
		return nil, errors.Errorf("No expressions")
	}

	expr := fmt.Sprintf("data.octelium.%s.%s", mod, qry)
	for _, exp := range rs[0].Expressions {
		if exp.Text == expr {
			return exp.Value, nil
		}
	}

	return nil, errors.Errorf("Could not find %s", expr)
}
