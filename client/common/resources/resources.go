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
	"io"
	"os"
	"path/filepath"

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
		return loadResources(os.Stdin, newObjFn)
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

		ret, err = loadResources(f, newObjFn)
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

				zap.S().Debugf("getting resources from the file: %s", path)

				f, err := os.Open(path)
				if err != nil {
					return err
				}

				fileRet, err := loadResources(f, newObjFn)
				if err != nil {
					return err
				}

				ret = append(ret, fileRet...)

				return nil
			}); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func loadResources(r io.Reader, newObjFn func(kind string) (umetav1.ResourceObjectI, error)) ([]umetav1.ResourceObjectI, error) {
	d := yaml.NewDecoder(r)
	var ret []umetav1.ResourceObjectI

	for {
		itemMap := make(map[string]any)
		err := d.Decode(&itemMap)

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, errors.Errorf("Could not decode yaml item: %s", err)
		}

		if itemMap == nil {
			continue
		}

		obj, err := unmarshalResource(itemMap, newObjFn)
		if err != nil {
			zap.L().Debug("Could not unmarshal for item", zap.Any("item", itemMap), zap.Error(err))

			itemMapYAML, _ := yaml.Marshal(itemMap)

			cliutils.LineWarn("Could not parse Resource:\n%s\nError: %+v.\n Skipping this object\n", string(itemMapYAML), err)
		} else {
			ret = append(ret, obj)
		}
	}

	return ret, nil
}

func unmarshalResource(in map[string]any, newObjFn func(kind string) (umetav1.ResourceObjectI, error)) (umetav1.ResourceObjectI, error) {

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

	if err := pbutils.UnmarshalFromMap(in, obj); err != nil {
		return nil, err
	}

	return obj, nil
}
