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

package printer

import (
	"os"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
)

/*
func Print(headers []string, rows [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.Header(headers)

	table.Bulk(rows)
	table.Render()
}
*/

type Printer struct {
	table *tablewriter.Table
}

func NewPrinter(headers ...string) *Printer {
	ret := &Printer{}

	{

		colorCfg := renderer.ColorizedConfig{
			Header: renderer.Tint{
				FG: renderer.Colors{color.FgWhite, color.Bold},
			},
			Column: renderer.Tint{
				FG: renderer.Colors{color.FgWhite},
			},

			Border:    renderer.Tint{FG: renderer.Colors{color.FgWhite}},
			Separator: renderer.Tint{FG: renderer.Colors{color.FgWhite}},
		}

		ret.table = tablewriter.NewTable(os.Stdout,
			tablewriter.WithRenderer(renderer.NewColorized(colorCfg))) // tablewriter.WithRenderer(renderer.NewColorized(colorCfg)),

	}

	/*
		ret.table.Header(headers)
		hdrColor := []tablewriter.Colors{}
		for i := 0; i < len(headers); i++ {
			hdrColor = append(hdrColor, tablewriter.Colors{tablewriter.Bold})
		}
		ret.table.SetHeaderColor(hdrColor...)
		ret.table.SetBorder(false)
	*/

	ret.table.Header(headers)

	return ret
}

func (p *Printer) AppendRow(row ...string) {
	p.table.Append(row)
}

func (p *Printer) AppendAndRenderRow(row ...string) {
	p.table.Append(row)
	p.table.Render()
}

func (p *Printer) Render() {
	p.table.Render()
}
