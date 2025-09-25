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

package session

import (
	"time"

	"github.com/karrick/tparse/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/spf13/cobra"
)

const example = `
  octeliumctl update session --expire-in 3month usr1-linux-uvc4
  octeliumctl update sess --approve usr1-linux-uvc4
  octeliumctl update sess --reject usr1-linux-uvc4
  `

var Cmd = &cobra.Command{
	Use:     "session",
	Short:   "Update a Session",
	Example: example,
	Aliases: []string{"sess"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

type args struct {
	Approve   bool
	Reject    bool
	ExpiresIn string
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Approve, "approve", false, "Approve the Session")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Reject, "reject", false, "Reject the Session")
	Cmd.PersistentFlags().StringVar(&cmdArgs.ExpiresIn, "expire-in", "", "Set the duration after which the Session expires (e.g. `2hours`, `30days`, `6hours`, `1week`)")
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	conn, err := client.GetGRPCClientConn(cmd.Context(), i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := corev1.NewMainServiceClient(conn)

	sess, err := c.GetSession(ctx, &metav1.GetOptions{
		Name: i.FirstArg(),
	})
	if err != nil {
		return err
	}

	switch {
	case cmdArgs.Approve:
		sess.Spec.State = corev1.Session_Spec_ACTIVE
	case cmdArgs.Reject:
		sess.Spec.State = corev1.Session_Spec_REJECTED
	}

	if cmdArgs.ExpiresIn != "" {
		t, err := tparse.AddDuration(time.Now(), cmdArgs.ExpiresIn)
		if err != nil {
			return err
		}
		sess.Spec.ExpiresAt = pbutils.Timestamp(t)
	}

	_, err = c.UpdateSession(ctx, sess)
	if err != nil {
		return err
	}

	cliutils.LineNotify("Session %s successfully updated\n", i.FirstArg())

	return nil
}
