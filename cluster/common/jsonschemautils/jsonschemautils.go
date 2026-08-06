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

package jsonschemautils

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/kaptinlin/jsonschema"
	"github.com/pkg/errors"
)

const (
	MaxSchemaBytes = 256 * 1024

	defaultMaxCacheEntries = 512
)

var errRemoteRefDisabled = errors.Errorf("remote JSON Schema references are disabled")

func NewCompiler() *jsonschema.Compiler {
	c := jsonschema.NewCompiler()

	c.Loaders = map[string]func(url string) (io.ReadCloser, error){}
	for _, scheme := range []string{"http", "https", "file", "ftp"} {
		c.RegisterLoader(scheme, denyLoader)
	}

	return c
}

func denyLoader(url string) (io.ReadCloser, error) {
	return nil, errRemoteRefDisabled
}

func Compile(raw []byte) (*jsonschema.Schema, error) {
	if err := checkNoExternalRefs(raw); err != nil {
		return nil, err
	}

	return NewCompiler().Compile(raw)
}

func checkNoExternalRefs(raw []byte) error {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}

	var rootID string
	if m, ok := doc.(map[string]any); ok {
		if v, ok := m["$id"].(string); ok {
			rootID, _, _ = strings.Cut(v, "#")
		}
	}

	return walkRefs(doc, rootID)
}

func walkRefs(node any, rootID string) error {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			if key == "$ref" || key == "$dynamicRef" {
				ref, ok := val.(string)
				if !ok {
					continue
				}

				u, err := url.Parse(ref)
				if err != nil {
					return errors.Errorf("invalid %s %q", key, ref)
				}

				if u.Scheme == "" {
					continue
				}

				if base, _, _ := strings.Cut(ref, "#"); rootID != "" && base == rootID {
					continue
				}

				return errors.Errorf(
					"%s %q points outside the schema; only self-contained schemas are supported",
					key, ref)
			}

			if err := walkRefs(val, rootID); err != nil {
				return err
			}
		}
	case []any:
		for _, val := range v {
			if err := walkRefs(val, rootID); err != nil {
				return err
			}
		}
	}

	return nil
}

type Cache struct {
	mu         sync.RWMutex
	entries    map[string]*cacheEntry
	maxEntries int
}

type cacheEntry struct {
	schema *jsonschema.Schema
	err    error
}

func NewCache() *Cache {
	return &Cache{
		entries:    make(map[string]*cacheEntry),
		maxEntries: defaultMaxCacheEntries,
	}
}

func (c *Cache) Compile(raw []byte) (*jsonschema.Schema, error) {
	if len(raw) > MaxSchemaBytes {
		return nil, errors.Errorf("JSON Schema is larger than the %d byte limit", MaxSchemaBytes)
	}

	key := fmt.Sprintf("%x", sha256.Sum256(raw))

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if ok {
		return entry.schema, entry.err
	}

	schema, err := Compile(raw)
	entry = &cacheEntry{schema: schema, err: err}

	c.mu.Lock()
	if len(c.entries) >= c.maxEntries {
		c.entries = make(map[string]*cacheEntry)
	}
	c.entries[key] = entry
	c.mu.Unlock()

	return schema, err
}
