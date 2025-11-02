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
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine/cellib"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

type CELEngine struct {
	c         *cache.Cache
	env       *cel.Env
	opaEngine *opaEngine
}

type Opts struct {
}

func New(ctx context.Context, opts *Opts) (*CELEngine, error) {

	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("ctx", decls.Dyn),
			decls.NewVar("attrs", decls.Dyn),
		),
		cellib.CELLib(),
		// cel.OptionalTypes(),
	)
	if err != nil {
		return nil, err
	}

	opaEngine, err := newOPAEngine(ctx, &opaOpts{})
	if err != nil {
		return nil, err
	}

	return &CELEngine{
		c:         cache.New(24*time.Hour, 10*time.Minute),
		env:       env,
		opaEngine: opaEngine,
	}, nil
}

func (e *CELEngine) EvalPolicy(ctx context.Context, exp string, input map[string]any) (bool, error) {
	prg, err := e.getOrSetProg(ctx, exp, cel.BoolType)
	if err != nil {
		return false, err
	}

	out, _, err := prg.ContextEval(ctx, input)
	if err != nil {
		return false, err
	}

	return out.Value().(bool), nil
}

func (e *CELEngine) EvalPolicyString(ctx context.Context, exp string, input map[string]any) (string, error) {
	prg, err := e.getOrSetProg(ctx, exp, cel.StringType)
	if err != nil {
		return "", err
	}

	out, _, err := prg.ContextEval(ctx, input)
	if err != nil {
		return "", err
	}

	return out.Value().(string), nil
}

func (e *CELEngine) EvalPolicyMapStrAny(ctx context.Context, exp string, input map[string]any) (map[string]any, error) {
	prg, err := e.getOrSetProg(ctx, exp, cel.StringType)
	if err != nil {
		return nil, err
	}

	out, _, err := prg.ContextEval(ctx, input)
	if err != nil {
		return nil, err
	}

	res, ok := convertCelToGo(out).(map[string]any)
	if !ok {
		return nil, errors.Errorf("Could not assert cel val to map[string]any")
	}

	return res, nil
}

func (e *CELEngine) AddPolicy(ctx context.Context, exp string) error {
	_, err := e.getOrSetProg(ctx, exp, cel.BoolType)
	return err
}

func (e *CELEngine) AddPolicyString(ctx context.Context, exp string) error {
	_, err := e.getOrSetProg(ctx, exp, cel.StringType)
	return err
}

func (e *CELEngine) getOrSetProg(_ context.Context, exp string, typ *types.Type) (cel.Program, error) {
	if len(exp) > 10000 {
		return nil, errors.Errorf("Expression is too long")
	}

	key := getKey(exp)
	cacheI, ok := e.c.Get(key)
	if ok {
		return cacheI.(cel.Program), nil
	}

	// startedAt := time.Now()
	ast, iss := e.env.Compile(exp)
	if iss.Err() != nil {
		return nil, errors.Errorf("Could not compile CEL expression: %s: %s", exp, iss.Err())
	}

	/*
		if !reflect.DeepEqual(ast.OutputType(), typ) {
			return nil, errors.Errorf("Invalid result type of CEL expression: %s. Output is: %s. Required is: %s",
				exp, ast.OutputType().String(), typ.String())
		}
	*/

	prg, err := e.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, err
	}

	e.c.Set(key, prg, cache.DefaultExpiration)
	/*
		zap.L().Debug("CEL expression compilation done",
			zap.Float32("time microsec", float32(time.Since(startedAt).Nanoseconds())/1000),
			zap.String("expression", exp),
		)
	*/
	return prg, nil
}

func getKey(script string) string {
	hsh := sha256.Sum256([]byte(script))
	return fmt.Sprintf("%x", hsh[:24])
}

func (e *CELEngine) EvalCondition(ctx context.Context, condition *corev1.Condition, inputMap map[string]any) (bool, error) {
	return e.doEvalCondition(ctx, condition, inputMap)
}

func (e *CELEngine) doEvalCondition(ctx context.Context, condition *corev1.Condition, inputMap map[string]any) (bool, error) {
	if condition == nil {
		return false, nil
	}

	var didMatch bool

	switch condition.Type.(type) {

	case *corev1.Condition_MatchAny:
		if !condition.GetMatchAny() {
			return false, nil
		}
		didMatch = true
	case *corev1.Condition_Match:
		res, err := e.isConditionMatched(ctx, inputMap, condition.GetMatch())
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
		didMatch = true
	case *corev1.Condition_Not:
		res, err := e.isConditionNotMatched(ctx, inputMap, condition.GetNot())
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
		didMatch = true
	case *corev1.Condition_All_:
		res, err := e.isConditionMatchedAll(ctx, condition.GetAll(), inputMap)
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
		didMatch = true
	case *corev1.Condition_Any_:
		res, err := e.isConditionMatchedAny(ctx, condition.GetAny(), inputMap)
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
		didMatch = true
	case *corev1.Condition_None_:
		res, err := e.isConditionMatchedNone(ctx, condition.GetNone(), inputMap)
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
		didMatch = true
	case *corev1.Condition_Opa:
		switch condition.GetOpa().Type.(type) {
		case *corev1.Condition_OPA_Inline:
			res, err := e.opaEngine.EvalPolicy(ctx, condition.GetOpa().GetInline(), inputMap)
			if err != nil {
				return false, err
			}
			if !res {
				return false, nil
			}
			didMatch = true
		}
	}

	return didMatch, nil
}

func (s *CELEngine) isConditionMatchedAll(ctx context.Context, condition *corev1.Condition_All, input map[string]any) (bool, error) {

	if condition == nil || len(condition.Of) == 0 {
		return false, nil
	}

	for _, condition := range condition.Of {
		isMatched, err := s.doEvalCondition(ctx, condition, input)
		if err != nil {
			return false, err
		}
		if !isMatched {
			return false, nil
		}
	}

	return true, nil
}

func (s *CELEngine) isConditionMatchedAny(ctx context.Context, condition *corev1.Condition_Any, input map[string]any) (bool, error) {

	if condition == nil || len(condition.Of) == 0 {
		return false, nil
	}

	for _, condition := range condition.Of {
		isMatched, err := s.doEvalCondition(ctx, condition, input)
		if err != nil {
			return false, err
		}

		if isMatched {
			return true, nil
		}
	}

	return false, nil
}

func (s *CELEngine) isConditionMatched(ctx context.Context, input map[string]any, exp string) (bool, error) {

	if len(exp) == 0 {
		return false, nil
	}

	return s.EvalPolicy(ctx, exp, input)
}

func (s *CELEngine) isConditionNotMatched(ctx context.Context, input map[string]any, exp string) (bool, error) {

	if len(exp) == 0 {
		return false, nil
	}

	match, err := s.EvalPolicy(ctx, exp, input)
	if err != nil {
		return false, err
	}
	return !match, nil
}

func (s *CELEngine) isConditionMatchedNone(ctx context.Context, condition *corev1.Condition_None, input map[string]any) (bool, error) {

	if condition == nil || len(condition.Of) == 0 {
		return false, nil
	}

	for _, condition := range condition.Of {
		isMatched, err := s.doEvalCondition(ctx, condition, input)
		if err != nil {
			return false, err
		}

		if isMatched {
			return false, nil
		}
	}

	return true, nil
}

func convertCelToGo(val ref.Val) any {
	if val == nil {
		return nil
	}

	switch val.Type() {
	case types.StringType:
		return string(val.(types.String))
	case types.IntType:
		return int64(val.(types.Int))
	case types.UintType:
		return uint64(val.(types.Uint))
	case types.DoubleType:
		return float64(val.(types.Double))
	case types.BoolType:
		return bool(val.(types.Bool))
	case types.BytesType:
		return []byte(val.(types.Bytes))
	case types.NullType:
		return nil
	case types.MapType:
		m := val.(traits.Mapper)
		result := make(map[string]any)
		it := m.Iterator()
		for it.HasNext() == types.True {
			key := it.Next()
			keyStr := convertCelToGo(key)
			value := m.Get(key)
			if keyString, ok := keyStr.(string); ok {
				result[keyString] = convertCelToGo(value)
			}
		}
		return result
	case types.ListType:
		l := val.(traits.Lister)
		size := int(l.Size().(types.Int))
		result := make([]any, size)
		for i := 0; i < size; i++ {
			result[i] = convertCelToGo(l.Get(types.Int(i)))
		}
		return result
	default:
		if v, ok := val.(interface{ Value() any }); ok {
			underlying := v.Value()
			if celVal, isCelVal := underlying.(ref.Val); isCelVal {
				return convertCelToGo(celVal)
			}
			return underlying
		}
		return val
	}
}
