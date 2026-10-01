// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resources

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"gopkg.in/yaml.v3"
)

func LoadCoreResources(fPath string) ([]umetav1.ResourceObjectI, error) {
	return LoadResources(fPath, ucorev1.NewObject)
}

func LoadResources(fPath string, newObjFn func(kind string) (umetav1.ResourceObjectI, error)) ([]umetav1.ResourceObjectI, error) {
	var ret []umetav1.ResourceObjectI

	if err := walkResourceFiles(fPath, func(r io.Reader, path string) error {
		itms, err := loadResources(r, path, newObjFn)
		if err != nil {
			return err
		}

		ret = append(ret, itms...)
		return nil
	}); err != nil {
		return nil, err
	}

	return ret, nil
}

func ValidateCoreResources(fPath string) ([]umetav1.ResourceObjectI, []error, error) {
	return ValidateResources(fPath, ucorev1.NewObject)
}

func ValidateResources(fPath string,
	newObjFn func(kind string) (umetav1.ResourceObjectI, error)) ([]umetav1.ResourceObjectI, []error, error) {
	var ret []umetav1.ResourceObjectI
	var validationErrs []error

	if err := walkResourceFiles(fPath, func(r io.Reader, path string) error {
		itms, errs := validateResources(r, path, newObjFn)

		ret = append(ret, itms...)
		validationErrs = append(validationErrs, errs...)
		return nil
	}); err != nil {
		return nil, nil, err
	}

	return ret, validationErrs, nil
}

func walkResourceFiles(fPath string, fn func(r io.Reader, path string) error) error {
	if fPath == "" {
		return nil
	}

	if fPath == "-" {
		return fn(os.Stdin, "stdin")
	}

	pathInfo, err := os.Stat(fPath)
	if err != nil {
		return err
	}

	switch {
	case pathInfo.Mode().IsRegular():
		f, err := os.Open(fPath)
		if err != nil {
			return err
		}
		defer f.Close()

		return fn(f, fPath)

	case pathInfo.IsDir():

		return filepath.Walk(fPath,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.IsDir() {
					return nil
				}

				if !info.Mode().IsRegular() {
					return nil
				}

				switch strings.ToLower(filepath.Ext(path)) {
				case ".yaml", ".yml":
				default:
					return nil
				}

				zap.L().Debug("getting resources", zap.String("path", path))

				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()

				return fn(f, path)
			})

	default:
		return errors.Errorf("The path %s is neither a regular file nor a directory", fPath)
	}
}

func loadResources(r io.Reader, path string, newObjFn func(kind string) (umetav1.ResourceObjectI, error)) ([]umetav1.ResourceObjectI, error) {
	d := yaml.NewDecoder(r)
	var ret []umetav1.ResourceObjectI

	idx := 0

	for {
		itemMap := make(map[string]any)
		err := d.Decode(&itemMap)

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, errors.Errorf("Could not decode yaml item in %s: %s", path, err)
		}

		idx += 1

		if itemMap == nil {
			continue
		}

		obj, err := unmarshalResource(itemMap, newObjFn, getItemPath(path, idx))
		if err != nil {
			zap.L().Debug("Could not unmarshal for item", zap.Any("item", itemMap), zap.Error(err))

			itemMapYAML, _ := yaml.Marshal(itemMap)

			return nil, errors.Errorf("Could not parse the Resource at %s:\n%s\nError: %+v",
				getItemPath(path, idx), string(itemMapYAML), err)
		}

		ret = append(ret, obj)
	}

	return ret, nil
}

func validateResources(r io.Reader, path string,
	newObjFn func(kind string) (umetav1.ResourceObjectI, error)) ([]umetav1.ResourceObjectI, []error) {
	d := yaml.NewDecoder(r)
	var ret []umetav1.ResourceObjectI
	var validationErrs []error

	for {
		var node yaml.Node
		err := d.Decode(&node)

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			validationErrs = append(validationErrs,
				errors.Errorf("Could not decode yaml item in %s: %s", path, err))
			break
		}

		obj, errs := validateResource(&node, path, newObjFn)
		if len(errs) > 0 {
			validationErrs = append(validationErrs, errs...)
			continue
		}

		if obj != nil {
			ret = append(ret, obj)
		}
	}

	return ret, validationErrs
}

func validateResource(node *yaml.Node, path string,
	newObjFn func(kind string) (umetav1.ResourceObjectI, error)) (umetav1.ResourceObjectI, []error) {

	if len(node.Content) != 1 {
		return nil, nil
	}

	rootNode := node.Content[0]

	itemMap := make(map[string]any)
	if err := node.Decode(&itemMap); err != nil {
		return nil, []error{errors.Errorf("Could not decode yaml item at %s: %s",
			getNodePath(path, rootNode), err)}
	}

	if itemMap == nil {
		return nil, nil
	}

	newObj := func() (umetav1.ResourceObjectI, error) {
		kind, ok := itemMap["kind"].(string)
		if !ok {
			return nil, errors.Errorf("Could not find kind")
		}

		return newObjFn(kind)
	}

	obj, err := newObj()
	if err != nil {
		return nil, []error{getValidationErr(itemMap, getNodePath(path, rootNode), err)}
	}

	err = pbutils.UnmarshalFromMapStrict(itemMap, obj)
	if err == nil {
		return obj, nil
	}

	nodeErrs := getNodeErrs(newObj, rootNode, itemMap, func(arg any) map[string]any {
		ret, _ := arg.(map[string]any)
		return ret
	})
	if len(nodeErrs) == 0 {
		return nil, []error{getValidationErr(itemMap, getNodePath(path, rootNode), err)}
	}

	var ret []error
	for _, nodeErr := range nodeErrs {
		ret = append(ret, getValidationErr(itemMap, getNodePath(path, nodeErr.node), nodeErr.err))
	}

	return nil, ret
}

type nodeErr struct {
	node *yaml.Node
	err  error
}

// getNodeErrs finds the deepest YAML nodes that cause the strict unmarshal to fail.
// Every child of the node is strictly unmarshaled in isolation, wrapped by wrapFn inside its parent
// fields up to the root, and the children that fail are then searched recursively in the same way.
// This keeps protojson as the only judge of validity while mapping its errors to the YAML source.
func getNodeErrs(newObj func() (umetav1.ResourceObjectI, error),
	node *yaml.Node, val any, wrapFn func(arg any) map[string]any) []*nodeErr {

	if node.Kind == yaml.AliasNode {
		node = node.Alias
	}

	var ret []*nodeErr

	checkChild := func(keyNode, valNode *yaml.Node, childVal any, childWrapFn func(arg any) map[string]any) {
		obj, err := newObj()
		if err != nil {
			return
		}

		err = pbutils.UnmarshalFromMapStrict(childWrapFn(childVal), obj)
		if err == nil {
			return
		}

		childErrs := getNodeErrs(newObj, valNode, childVal, childWrapFn)
		if len(childErrs) == 0 {
			childErrs = []*nodeErr{
				{
					node: keyNode,
					err:  err,
				},
			}
		}

		ret = append(ret, childErrs...)
	}

	switch v := val.(type) {
	case map[string]any:
		if node.Kind != yaml.MappingNode {
			return nil
		}

		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			childVal, ok := v[key]
			if !ok {
				continue
			}

			checkChild(node.Content[i], node.Content[i+1], childVal, func(arg any) map[string]any {
				return wrapFn(map[string]any{key: arg})
			})
		}
	case []any:
		if node.Kind != yaml.SequenceNode {
			return nil
		}

		for i, childNode := range node.Content {
			if i >= len(v) {
				break
			}

			checkChild(childNode, childNode, v[i], func(arg any) map[string]any {
				return wrapFn([]any{arg})
			})
		}
	}

	return ret
}

func getValidationErr(in map[string]any, itemPath string, err error) error {
	kind, _ := in["kind"].(string)
	md, _ := in["metadata"].(map[string]any)
	name, _ := md["name"].(string)

	if kind == "" || name == "" {
		return errors.Errorf("Invalid Resource at %s: %s", itemPath, getErrMessage(err))
	}

	return errors.Errorf("Invalid %s `%s` at %s: %s", kind, name, itemPath, getErrMessage(err))
}

// protojson errors refer to positions in the JSON generated from the YAML item and not to the YAML source.
// Note that the "proto: " prefix deliberately uses either regular or non-breaking spaces.
var protoErrPositionRegex = regexp.MustCompile(`^proto:[\s\x{00a0}]*\(line \d+:\d+\):[\s\x{00a0}]*`)

func getErrMessage(err error) string {
	return protoErrPositionRegex.ReplaceAllString(err.Error(), "")
}

func getNodePath(path string, node *yaml.Node) string {
	return fmt.Sprintf("%s:%d:%d", path, node.Line, node.Column)
}

func getItemPath(path string, idx int) string {
	if idx <= 1 {
		return path
	}

	return fmt.Sprintf("%s (document %d)", path, idx)
}

func unmarshalResource(in map[string]any,
	newObjFn func(kind string) (umetav1.ResourceObjectI, error), itemPath string) (umetav1.ResourceObjectI, error) {

	var err error
	var obj umetav1.ResourceObjectI
	kind, ok := in["kind"].(string)
	if !ok {
		return nil, errors.Errorf("Could not find kind")
	}

	obj, err = newObjFn(kind)
	if err != nil {
		return nil, err
	}

	strictErr := pbutils.UnmarshalFromMapStrict(in, obj)
	if strictErr == nil {
		return obj, nil
	}

	zap.L().Debug("Could not strictly unmarshal item",
		zap.Any("item", in), zap.Error(strictErr))

	obj, err = newObjFn(kind)
	if err != nil {
		return nil, err
	}

	if err := pbutils.UnmarshalFromMap(in, obj); err != nil {
		return nil, err
	}

	cliutils.LineWarn("Unknown field in the %s Resource at %s: %s\n", kind, itemPath, strictErr)

	return obj, nil
}
