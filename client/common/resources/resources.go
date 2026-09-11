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
	var err error
	if fPath == "" {
		return ret, nil
	}

	if fPath == "-" {
		return loadResources(os.Stdin, "stdin", newObjFn)
	}

	pathInfo, err := os.Stat(fPath)
	if err != nil {
		return nil, err
	}

	switch {
	case pathInfo.Mode().IsRegular():
		f, err := os.Open(fPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		ret, err = loadResources(f, fPath, newObjFn)
		if err != nil {
			return nil, err
		}

	case pathInfo.IsDir():

		if err := filepath.Walk(fPath,
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

				fileRet, err := loadResources(f, path, newObjFn)
				if err != nil {
					return err
				}

				ret = append(ret, fileRet...)

				return nil
			}); err != nil {
			return nil, err
		}

	default:
		return nil, errors.Errorf("The path %s is neither a regular file nor a directory", fPath)
	}

	return ret, nil
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
