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

package loginicon

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"unicode/utf8"

	"github.com/pkg/errors"
)

const (
	MaxInlineSize = 32 * 1024
	MaxSize       = 128 * 1024
)

const (
	contentTypeSVG  = "image/svg+xml"
	contentTypePNG  = "image/png"
	contentTypeJPEG = "image/jpeg"
	contentTypeWebP = "image/webp"
)

func GetContentType(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.Errorf("The icon is empty")
	}

	if len(data) > MaxSize {
		return "", errors.Errorf("The icon is too large: %d bytes. The maximum size is %d bytes",
			len(data), MaxSize)
	}

	switch contentType := http.DetectContentType(data); contentType {
	case contentTypePNG, contentTypeJPEG, contentTypeWebP:
		return contentType, nil
	}

	if isSVG(data) {
		return contentTypeSVG, nil
	}

	return "", errors.Errorf("Unsupported icon format. Only SVG, PNG, JPEG and WebP icons are supported")
}

func GetDataURL(data []byte) (string, error) {
	contentType, err := GetContentType(data)
	if err != nil {
		return "", err
	}

	return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

func isSVG(data []byte) bool {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return false
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false

	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}

		switch t := token.(type) {
		case xml.StartElement:
			return t.Name.Local == "svg"
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				return false
			}
		}
	}
}
