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
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 50"><rect width="200" height="50" fill="red"/></svg>`

const testWebP = "UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA=="

func getTestImage() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.Set(1, 1, color.RGBA{R: 255, A: 255})
	return img
}

func getTestPNG(t *testing.T) []byte {
	var buf bytes.Buffer
	assert.Nil(t, png.Encode(&buf, getTestImage()))
	return buf.Bytes()
}

func getTestJPEG(t *testing.T) []byte {
	var buf bytes.Buffer
	assert.Nil(t, jpeg.Encode(&buf, getTestImage(), nil))
	return buf.Bytes()
}

func getTestGIF(t *testing.T) []byte {
	var buf bytes.Buffer
	assert.Nil(t, gif.Encode(&buf, getTestImage(), nil))
	return buf.Bytes()
}

func TestGetContentType(t *testing.T) {
	webp, err := base64.StdEncoding.DecodeString(testWebP)
	assert.Nil(t, err)

	for _, tc := range []struct {
		data        []byte
		contentType string
	}{
		{data: getTestPNG(t), contentType: "image/png"},
		{data: getTestJPEG(t), contentType: "image/jpeg"},
		{data: webp, contentType: "image/webp"},
		{data: []byte(testSVG), contentType: "image/svg+xml"},
		{data: []byte(`<svg/>`), contentType: "image/svg+xml"},
		{data: []byte("\n\t  " + testSVG + "\n"), contentType: "image/svg+xml"},
		{data: []byte("\xef\xbb\xbf" + testSVG), contentType: "image/svg+xml"},
		{data: []byte(`<?xml version="1.0" encoding="UTF-8"?>` + testSVG), contentType: "image/svg+xml"},
		{data: []byte(`<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!-- Generator: Adobe Illustrator -->
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
	<!ENTITY ns_svg "http://www.w3.org/2000/svg">
]>
<svg version="1.1" xmlns="&ns_svg;" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4"/></svg>`),
			contentType: "image/svg+xml"},
		{data: []byte(`<svg:svg xmlns:svg="http://www.w3.org/2000/svg"/>`), contentType: "image/svg+xml"},
		{data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
			contentType: "image/svg+xml"},
	} {
		contentType, err := GetContentType(tc.data)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, tc.contentType, contentType)
	}

	for _, data := range [][]byte{
		nil,
		{},
		[]byte(" "),
		[]byte("hello"),
		[]byte("<html><body><svg/></body></html>"),
		[]byte("text<svg/>"),
		[]byte("<svgx/>"),
		[]byte("<!-- <svg/> -->"),
		[]byte(`<?xml version="1.0" encoding="ISO-8859-1"?><svg/>`),
		[]byte("<svg>\xff</svg>"),
		[]byte(`{"svg": true}`),
		[]byte("<script>alert(1)</script>"),
		[]byte("%PDF-1.7"),
		getTestGIF(t),
		[]byte("BM" + strings.Repeat("\x00", 64)),
	} {
		_, err := GetContentType(data)
		assert.NotNil(t, err, "%q", data)
	}

	{
		data := append(getTestPNG(t), make([]byte, MaxSize)...)
		_, err := GetContentType(data[:MaxSize])
		assert.Nil(t, err)

		_, err = GetContentType(data[:MaxSize+1])
		assert.NotNil(t, err)
	}

	{
		data := []byte("<svg>" + strings.Repeat(" ", MaxSize) + "</svg>")
		_, err := GetContentType(data)
		assert.NotNil(t, err)
	}
}

func TestGetDataURL(t *testing.T) {
	{
		data := getTestPNG(t)
		ret, err := GetDataURL(data)
		assert.Nil(t, err)

		encoded, found := strings.CutPrefix(ret, "data:image/png;base64,")
		assert.True(t, found)

		decoded, err := base64.StdEncoding.DecodeString(encoded)
		assert.Nil(t, err)
		assert.Equal(t, data, decoded)
	}

	{
		ret, err := GetDataURL([]byte(testSVG))
		assert.Nil(t, err)
		assert.Equal(t,
			"data:image/svg+xml;base64,"+base64.StdEncoding.EncodeToString([]byte(testSVG)), ret)
	}

	{
		ret, err := GetDataURL([]byte("<html/>"))
		assert.NotNil(t, err)
		assert.Equal(t, "", ret)
	}
}
