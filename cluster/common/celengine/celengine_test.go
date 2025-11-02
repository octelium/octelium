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

package celengine

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestEvalPolicyAny(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv, err := New(ctx, &Opts{})
	assert.Nil(t, err)

	reqCtx := &corev1.RequestContext{
		User: tests.GenUser(nil),
	}

	res, err := srv.EvalPolicyMapStrAny(ctx,
		`{"upstream": {"url": "https://" + ctx.user.metadata.name + ".example.com"}}`, map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		})
	assert.Nil(t, err)

	cfg := &corev1.Service_Spec_Config{}

	err = pbutils.UnmarshalFromMap(res, cfg)
	assert.Nil(t, err)

	assert.Equal(t, fmt.Sprintf("https://%s.example.com", reqCtx.User.Metadata.Name), cfg.Upstream.GetUrl())
}
