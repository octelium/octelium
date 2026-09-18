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

package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
)

const (
	maxTransContinuationBytes = 16 * 1024
	maxTransContinuations     = 32

	transContinuationTimeout = 2 * time.Second
	transContinuationMinutes = 30
)

type transContinuation struct {
	octeliumC octeliumc.ClientInterface
	svcUID    string
}

func newTransContinuation(octeliumC octeliumc.ClientInterface,
	svcUID string) *transContinuation {
	return &transContinuation{
		octeliumC: octeliumC,
		svcUID:    svcUID,
	}
}

func (c *transContinuation) isEnabled() bool {
	return c != nil && c.octeliumC != nil
}

func (c *transContinuation) key(reqCtx *middlewares.RequestContext,
	plan *transPlan, callID string) []byte {

	var sessionUID string
	if reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.Session != nil {
		sessionUID = reqCtx.DownstreamInfo.Session.Metadata.Uid
	}

	return vutils.Sha256Sum([]byte(fmt.Sprintf("llm:tc:%s\x00%s\x00%d\x00%s\x00%s",
		c.svcUID, sessionUID, plan.toProtocol, plan.model, callID)))
}

func (c *transContinuation) store(ctx context.Context,
	reqCtx *middlewares.RequestContext, plan *transPlan, blocks []*transBlock) {

	if !c.isEnabled() {
		return
	}

	var count int
	for _, block := range blocks {
		if block.kind != transBlockToolCall ||
			block.toolSignature == "" || block.toolCallID == "" {
			continue
		}
		if len(block.toolSignature) > maxTransContinuationBytes {
			continue
		}

		count++
		if count > maxTransContinuations {
			return
		}

		c.set(ctx, c.key(reqCtx, plan, block.toolCallID), block.toolSignature)
	}
}

func (c *transContinuation) set(ctx context.Context, key []byte, val string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx),
		transContinuationTimeout)
	defer cancel()

	if _, err := c.octeliumC.CacheC().SetCache(ctx, &rcachev1.SetCacheRequest{
		Key:  key,
		Data: []byte(val),
		Duration: &metav1.Duration{
			Type: &metav1.Duration_Minutes{Minutes: transContinuationMinutes},
		},
	}); err != nil {
		zap.L().Debug("Could not store the LLM translation continuation",
			zap.Error(err))
	}
}

func (c *transContinuation) restore(ctx context.Context,
	reqCtx *middlewares.RequestContext, plan *transPlan, req *transRequest) {

	if !c.isEnabled() {
		return
	}

	var count int
	for i := len(req.messages) - 1; i >= 0; i-- {
		msg := req.messages[i]
		if msg.role != roleAssistant || !msg.hasKind(transBlockToolCall) {
			continue
		}

		for _, block := range msg.blocks {
			if block.kind != transBlockToolCall ||
				block.toolSignature != "" || block.toolCallID == "" {
				continue
			}

			count++
			if count > maxTransContinuations {
				return
			}

			block.toolSignature = c.get(ctx, c.key(reqCtx, plan, block.toolCallID))
		}

		return
	}
}

func (c *transContinuation) get(ctx context.Context, key []byte) string {
	ctx, cancel := context.WithTimeout(ctx, transContinuationTimeout)
	defer cancel()

	resp, err := c.octeliumC.CacheC().GetCache(ctx, &rcachev1.GetCacheRequest{
		Key: key,
	})
	if err != nil {
		if !grpcerr.IsNotFound(err) {
			zap.L().Debug("Could not read the LLM translation continuation",
				zap.Error(err))
		}
		return ""
	}

	if resp == nil || len(resp.Data) == 0 ||
		len(resp.Data) > maxTransContinuationBytes {
		return ""
	}

	return string(resp.Data)
}
