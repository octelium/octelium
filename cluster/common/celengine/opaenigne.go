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

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

type opaEngine struct {
	c    *cache.Cache
	caps *ast.Capabilities
}

type opaOpts struct {
}

func newOPAEngine(_ context.Context, _ *opaOpts) (*opaEngine, error) {
	return &opaEngine{
		c:    cache.New(24*time.Hour, 10*time.Minute),
		caps: getOPACapabilities(),
	}, nil
}

var ErrOPAUndefined = errors.New("OPA decision undefined")

func (e *opaEngine) EvalPolicy(ctx context.Context, script string, input map[string]any) (bool, error) {
	res, err := e.doEvalPolicy(ctx, script, input, "condition", "match")
	if err != nil {
		if errors.Is(err, ErrOPAUndefined) {
			return false, nil
		}
		return false, err
	}

	b, ok := res.(bool)
	if !ok {
		return false, errors.Errorf("OPA policy rule must return a boolean, got %T", res)
	}

	return b, nil
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
		rego.Capabilities(e.caps),
		rego.StrictBuiltinErrors(true),
	)

	pq, err := rg.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	e.c.Set(key, &pq, cache.DefaultExpiration)

	return &pq, nil
}

func (e *opaEngine) doEvalPolicy(ctx context.Context,
	script string, input map[string]any, mod, qry string) (any, error) {
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

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, ErrOPAUndefined
	}

	if len(rs) > 1 || len(rs[0].Expressions) > 1 {
		return nil, errors.Errorf("OPA evaluation produced ambiguous results")
	}

	return rs[0].Expressions[0].Value, nil
}

var opaAllowedBuiltins = map[string]struct{}{
	"eq": {}, "equal": {}, "neq": {}, "lt": {}, "lte": {}, "gt": {}, "gte": {},
	"assign": {}, "internal.member_2": {}, "internal.member_3": {},

	"plus": {}, "minus": {}, "mul": {}, "div": {}, "rem": {},
	"round": {}, "ceil": {}, "floor": {}, "abs": {},
	"numbers.range": {}, "numbers.range_step": {},
	"bits.and": {}, "bits.or": {}, "bits.xor": {}, "bits.negate": {},
	"bits.lsh": {}, "bits.rsh": {},

	"count": {}, "sum": {}, "product": {}, "max": {}, "min": {},
	"sort": {}, "all": {}, "any": {},

	"array.concat": {}, "array.reverse": {}, "array.slice": {},
	"and": {}, "or": {}, "intersection": {}, "union": {},
	"object.get": {}, "object.keys": {}, "object.remove": {},
	"object.union": {}, "object.union_n": {}, "object.filter": {}, "object.subset": {},
	"json.filter": {}, "json.remove": {}, "json.patch": {},

	"concat": {}, "contains": {}, "startswith": {}, "endswith": {},
	"indexof": {}, "indexof_n": {}, "substring": {},
	"lower": {}, "upper": {}, "replace": {}, "strings.replace_n": {},
	"split": {}, "trim": {}, "trim_left": {}, "trim_right": {},
	"trim_prefix": {}, "trim_suffix": {}, "trim_space": {},
	"sprintf": {}, "format_int": {}, "strings.reverse": {}, "strings.count": {},
	"strings.any_prefix_match": {}, "strings.any_suffix_match": {},

	"regex.match": {}, "regex.is_valid": {}, "regex.split": {},
	"regex.find_n": {}, "regex.find_all_string_submatch_n": {},
	"regex.replace": {}, "regex.template_match": {}, "regex.globs_match": {},
	"glob.match": {}, "glob.quote_meta": {},

	"to_number": {}, "type_name": {},
	"is_number": {}, "is_string": {}, "is_boolean": {},
	"is_array": {}, "is_set": {}, "is_object": {}, "is_null": {},

	"base64.encode": {}, "base64.decode": {}, "base64.is_valid": {},
	"base64url.encode": {}, "base64url.encode_no_pad": {}, "base64url.decode": {},
	"hex.encode": {}, "hex.decode": {},
	"urlquery.encode": {}, "urlquery.decode": {},
	"urlquery.encode_object": {}, "urlquery.decode_object": {},
	"json.marshal": {}, "json.unmarshal": {}, "json.is_valid": {},
	"yaml.marshal": {}, "yaml.unmarshal": {}, "yaml.is_valid": {},

	"crypto.hmac.md5": {}, "crypto.hmac.sha1": {},
	"crypto.hmac.sha256": {}, "crypto.hmac.sha512": {}, "crypto.hmac.equal": {},
	"crypto.md5": {}, "crypto.sha1": {}, "crypto.sha256": {},
	"crypto.x509.parse_certificates":            {},
	"crypto.x509.parse_and_verify_certificates": {},
	"io.jwt.decode":                             {}, "io.jwt.decode_verify": {},
	"io.jwt.verify_hs256": {}, "io.jwt.verify_hs384": {}, "io.jwt.verify_hs512": {},
	"io.jwt.verify_rs256": {}, "io.jwt.verify_rs384": {}, "io.jwt.verify_rs512": {},
	"io.jwt.verify_es256": {}, "io.jwt.verify_es384": {}, "io.jwt.verify_es512": {},
	"io.jwt.verify_ps256": {}, "io.jwt.verify_ps384": {}, "io.jwt.verify_ps512": {},
	"io.jwt.encode_sign": {}, "io.jwt.encode_sign_raw": {},

	"time.now_ns": {}, "time.parse_ns": {}, "time.parse_rfc3339_ns": {},
	"time.parse_duration_ns": {}, "time.date": {}, "time.clock": {},
	"time.weekday": {}, "time.add_date": {}, "time.diff": {}, "time.format": {},

	"net.cidr_contains": {}, "net.cidr_contains_matches": {},
	"net.cidr_intersects": {}, "net.cidr_merge": {}, "net.cidr_is_valid": {},

	"semver.compare": {}, "semver.is_valid": {},

	"http.send": {},

	"rand.intn":    {},
	"uuid.rfc4122": {},
}

func getOPACapabilities() *ast.Capabilities {

	caps := ast.CapabilitiesForThisVersion()

	filtered := make([]*ast.Builtin, 0, len(caps.Builtins))
	for _, b := range caps.Builtins {
		if _, ok := opaAllowedBuiltins[b.Name]; ok {
			filtered = append(filtered, b)
		}
	}
	caps.Builtins = filtered

	return caps
}
