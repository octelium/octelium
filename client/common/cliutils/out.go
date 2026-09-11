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

package cliutils

import (
	"github.com/octelium/octelium/pkg/common/pbutils"
	"google.golang.org/protobuf/proto"

	"github.com/pkg/errors"
)

func OutFormatPrint(outType string, dat proto.Message) ([]byte, error) {

	switch outType {
	case "json":
		return pbutils.MarshalJSON(dat, true)
	case "yaml", "yml", "":
		return pbutils.MarshalYAML(dat)
	default:
		return nil, getInvalidOutFormatErr(outType)
	}
}

func ValidateOutFormat(outType string) error {
	switch outType {
	case "json", "yaml", "yml", "":
		return nil
	default:
		return getInvalidOutFormatErr(outType)
	}
}

func getInvalidOutFormatErr(outType string) error {
	return errors.Errorf("Invalid output format: %s. It must be either `json` or `yaml`", outType)
}
