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

package llm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

const (
	maxTransToolInputBytes = 1024 * 1024
	maxTransBlocks         = 4096
	maxTransImageBytes     = 16 * 1024 * 1024
)

type transError struct {
	status  int
	message string
}

func (e *transError) Error() string {
	return e.message
}

func (e *transError) text() string {
	return fmt.Sprintf("Octelium: %s", e.message)
}

func transUnsupported(format string, args ...any) *transError {
	return &transError{
		status:  http.StatusBadRequest,
		message: errors.Errorf(format, args...).Error(),
	}
}

func transInvalidResponse(format string, args ...any) *transError {
	return &transError{
		status:  http.StatusBadGateway,
		message: errors.Errorf(format, args...).Error(),
	}
}

func transInternal(format string, args ...any) *transError {
	return &transError{
		status:  http.StatusInternalServerError,
		message: errors.Errorf(format, args...).Error(),
	}
}

func toTransError(err error) *transError {
	if err == nil {
		return nil
	}

	var ret *transError
	if errors.As(err, &ret) {
		return ret
	}

	return &transError{
		status:  http.StatusBadRequest,
		message: err.Error(),
	}
}

func transObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	ret := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &ret); err != nil {
		return nil, errors.Errorf("Could not parse a JSON object")
	}
	return ret, nil
}

func transString(raw json.RawMessage, key string) (string, error) {
	var ret string
	if err := json.Unmarshal(raw, &ret); err != nil {
		return "", errors.Errorf("The `%s` field is not a string", key)
	}
	return ret, nil
}

func transBool(raw json.RawMessage, key string) (bool, error) {
	var ret bool
	if err := json.Unmarshal(raw, &ret); err != nil {
		return false, errors.Errorf("The `%s` field is not a boolean", key)
	}
	return ret, nil
}

func transUint(raw json.RawMessage, key string) (uint64, error) {
	var ret uint64
	if err := json.Unmarshal(raw, &ret); err != nil {
		return 0, errors.Errorf("The `%s` field is not a positive integer", key)
	}
	return ret, nil
}

func transFloat(raw json.RawMessage, key string) (float64, error) {
	var ret float64
	if err := json.Unmarshal(raw, &ret); err != nil {
		return 0, errors.Errorf("The `%s` field is not a number", key)
	}
	return ret, nil
}

func transStrings(raw json.RawMessage, key string) ([]string, error) {
	if len(raw) > 0 && raw[0] == '"' {
		ret, err := transString(raw, key)
		if err != nil {
			return nil, err
		}
		return []string{ret}, nil
	}

	var ret []string
	if err := json.Unmarshal(raw, &ret); err != nil {
		return nil, errors.Errorf("The `%s` field is not a list of strings", key)
	}
	return ret, nil
}

func transArray(raw json.RawMessage, key string) ([]json.RawMessage, error) {
	var ret []json.RawMessage
	if err := json.Unmarshal(raw, &ret); err != nil {
		return nil, errors.Errorf("The `%s` field is not a list", key)
	}
	if len(ret) > maxTransBlocks {
		return nil, errors.Errorf("The `%s` field carries too many entries", key)
	}
	return ret, nil
}

func transType(obj map[string]json.RawMessage) (string, error) {
	raw, ok := obj["type"]
	if !ok {
		return "", nil
	}
	return transString(raw, "type")
}

func transIsNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

type transFields struct {
	known   map[string]struct{}
	ignored map[string]struct{}
}

func newTransFields(known, ignored []string) *transFields {
	ret := &transFields{
		known:   make(map[string]struct{}, len(known)),
		ignored: make(map[string]struct{}, len(ignored)),
	}

	for _, cur := range known {
		ret.known[cur] = struct{}{}
	}
	for _, cur := range ignored {
		ret.ignored[cur] = struct{}{}
	}

	return ret
}

func (f *transFields) check(obj map[string]json.RawMessage, scope string) error {
	var unknown []string

	for key, raw := range obj {
		if _, ok := f.known[key]; ok {
			continue
		}
		if _, ok := f.ignored[key]; ok {
			continue
		}
		if transIsNull(raw) {
			continue
		}
		unknown = append(unknown, key)
	}

	if len(unknown) == 0 {
		return nil
	}

	sort.Strings(unknown)

	return transUnsupported("the %s carries fields that cannot be translated: %s",
		scope, strings.Join(unknown, ", "))
}

func transDataURL(arg string) (string, string, bool) {
	rest, ok := strings.CutPrefix(arg, "data:")
	if !ok {
		return "", "", false
	}

	meta, data, ok := strings.Cut(rest, ",")
	if !ok {
		return "", "", false
	}

	mediaType, ok := strings.CutSuffix(meta, ";base64")
	if !ok || mediaType == "" {
		return "", "", false
	}

	return mediaType, data, true
}

func transBlocksText(blocks []*transBlock) string {
	var parts []string
	for _, block := range blocks {
		if block.kind != transBlockText {
			continue
		}
		parts = append(parts, block.text)
	}

	return strings.Join(parts, "\n")
}

func marshalRaw(arg any) (json.RawMessage, error) {
	ret, err := json.Marshal(arg)
	if err != nil {
		return nil, errors.Errorf("Could not serialize the translated request")
	}
	return ret, nil
}

func transToolInput(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) > maxTransToolInputBytes {
		return nil, transUnsupported("a tool call carries arguments that are too large")
	}

	var val any
	if err := json.Unmarshal(raw, &val); err != nil {
		return nil, transUnsupported("a tool call carries arguments that are not valid JSON")
	}

	if _, ok := val.(map[string]any); !ok {
		return nil, transUnsupported("a tool call carries arguments that are not a JSON object")
	}

	return raw, nil
}

func transToolArguments(arg string) (json.RawMessage, error) {
	if arg == "" {
		return json.RawMessage(`{}`), nil
	}

	return transToolInput(json.RawMessage(arg))
}

func setRawField(root map[string]json.RawMessage, key string, val any) error {
	raw, err := marshalRaw(val)
	if err != nil {
		return err
	}
	root[key] = raw
	return nil
}

func sseEvent(name string, payload []byte) []byte {
	var ret []byte
	if name != "" {
		ret = append(ret, "event: "...)
		ret = append(ret, name...)
		ret = append(ret, '\n')
	}
	ret = append(ret, "data: "...)
	ret = append(ret, payload...)
	ret = append(ret, '\n', '\n')

	return ret
}

func sseEventOf(name string, val any) ([]byte, error) {
	payload, err := json.Marshal(val)
	if err != nil {
		return nil, errors.Errorf("Could not serialize a translated stream event")
	}

	return sseEvent(name, payload), nil
}
