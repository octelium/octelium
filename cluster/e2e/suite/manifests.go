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

package suite

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
)

//go:embed testdata/manifests/*.yaml
var manifestFS embed.FS

type manifestVars struct {
	WSEchoPort int
	MCPPort    int
}

func renderManifests(t *testing.T, vars manifestVars) (string, []string) {
	t.Helper()

	dir, err := os.MkdirTemp("", "octelium-e2e-manifests-*")
	if err != nil {
		t.Fatalf("Could not create the manifest directory: %+v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	entries, err := fs.Glob(manifestFS, "testdata/manifests/*.yaml")
	if err != nil {
		t.Fatalf("Could not enumerate the manifests: %+v", err)
	}
	if len(entries) == 0 {
		t.Fatal("No manifests were embedded")
	}

	var names []string
	for _, entry := range entries {
		content, err := manifestFS.ReadFile(entry)
		if err != nil {
			t.Fatalf("Could not read the manifest %s: %+v", entry, err)
		}

		name := filepath.Base(entry)

		tmpl, err := template.New(name).Parse(string(content))
		if err != nil {
			t.Fatalf("Could not parse the manifest %s: %+v", name, err)
		}

		var b strings.Builder
		if err := tmpl.Execute(&b, vars); err != nil {
			t.Fatalf("Could not render the manifest %s: %+v", name, err)
		}

		if err := os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o644); err != nil {
			t.Fatalf("Could not write the manifest %s: %+v", name, err)
		}

		names = append(names, name)
	}

	return dir, names
}
