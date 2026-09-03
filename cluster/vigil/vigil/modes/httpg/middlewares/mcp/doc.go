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

package mcp

import (
	"encoding/json"
	"sort"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/pkg/errors"
)

const (
	methodToolsCall     = "tools/call"
	methodToolsList     = "tools/list"
	methodResourcesRead = "resources/read"
	methodPromptsGet    = "prompts/get"
)

const (
	paramsKey    = "params"
	argumentsKey = "arguments"
	resultKey    = "result"
)

const (
	maxDocDepth = 24
	maxDocParts = 4096
)

type doc struct {
	method string

	root    map[string]json.RawMessage
	changed bool
}

func newDoc(method string, body []byte) (*doc, error) {
	root := make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, errors.Errorf("Could not parse the MCP request body")
	}

	return &doc{
		method: method,
		root:   root,
	}, nil
}

func (d *doc) isChanged() bool {
	return d.changed
}

func (d *doc) bytes() ([]byte, error) {
	return json.Marshal(d.root)
}

type textPart struct {
	scope corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope
	text  string
	set   func(string) error
}

func hasScope(scopes []corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope,
	arg corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope, isResponse bool) bool {
	if len(scopes) == 0 {
		if isResponse {
			return arg == corev1.Service_Spec_Config_MCP_Plugin_Guardrail_TOOL_RESULTS
		}
		return arg == corev1.Service_Spec_Config_MCP_Plugin_Guardrail_TOOL_ARGUMENTS
	}

	for _, scope := range scopes {
		if scope == corev1.Service_Spec_Config_MCP_Plugin_Guardrail_ALL || scope == arg {
			return true
		}
	}

	return false
}

func (d *doc) requestParts(
	scopes []corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope) []*textPart {

	if d.method != methodToolsCall ||
		!hasScope(scopes, corev1.Service_Spec_Config_MCP_Plugin_Guardrail_TOOL_ARGUMENTS,
			false) {
		return nil
	}

	raw, ok := d.root[paramsKey]
	if !ok {
		return nil
	}

	params := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil
	}

	args, ok := params[argumentsKey]
	if !ok {
		return nil
	}

	var val any
	if err := json.Unmarshal(args, &val); err != nil {
		return nil
	}

	apply := func() error {
		updated, err := json.Marshal(val)
		if err != nil {
			return err
		}
		params[argumentsKey] = updated

		raw, err := json.Marshal(params)
		if err != nil {
			return err
		}
		d.root[paramsKey] = raw
		d.changed = true

		return nil
	}

	setSelf := func(updated string) error {
		val = updated
		return nil
	}

	var ret []*textPart
	walkTextParts(val, 0,
		corev1.Service_Spec_Config_MCP_Plugin_Guardrail_TOOL_ARGUMENTS,
		apply, setSelf, &ret)

	return ret
}

func walkTextParts(val any, depth int,
	scope corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope,
	apply func() error, setSelf func(string) error, ret *[]*textPart) {

	if depth > maxDocDepth || len(*ret) >= maxDocParts {
		return
	}

	switch cur := val.(type) {
	case string:
		*ret = append(*ret, &textPart{
			scope: scope,
			text:  cur,
			set: func(updated string) error {
				if err := setSelf(updated); err != nil {
					return err
				}
				return apply()
			},
		})
	case map[string]any:
		keys := make([]string, 0, len(cur))
		for key := range cur {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, k := range keys {
			key := k
			walkTextParts(cur[key], depth+1, scope, apply, func(updated string) error {
				cur[key] = updated
				return nil
			}, ret)
		}
	case []any:
		for i := range cur {
			idx := i
			walkTextParts(cur[idx], depth+1, scope, apply, func(updated string) error {
				cur[idx] = updated
				return nil
			}, ret)
		}
	}
}
