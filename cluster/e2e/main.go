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

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type globalArgs struct {
	Scenario  string
	StatePath string
}

type testArgs struct {
	Run         string
	Timeout     string
	Verbose     bool
	ArtifactDir string
	Parallel    int
}

var gArgs globalArgs
var tArgs testArgs

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)

	if err := rootCmd.Execute(); err != nil {
		zap.L().Fatal("e2e failed", zap.Error(err))
	}
}

var rootCmd = &cobra.Command{
	Use:           "octelium-e2e",
	Short:         "Provision an environment for the Octelium end-to-end suite and run it",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&gArgs.Scenario, "scenario", "k3s-flannel",
		fmt.Sprintf("The environment to run against. One of: %s",
			strings.Join(scenario.IDs(), ", ")))
	rootCmd.PersistentFlags().StringVar(&gArgs.StatePath, "state", "",
		"Path to the file the stages use to hand state to each other")

	testCmd.Flags().StringVar(&tArgs.Run, "run", "",
		"Only run tests matching this regular expression, as `go test -run`")
	testCmd.Flags().StringVar(&tArgs.Timeout, "timeout", "90m",
		"Wall-clock budget for the whole suite")
	testCmd.Flags().BoolVar(&tArgs.Verbose, "verbose", true, "Stream per-test output")
	testCmd.Flags().StringVar(&tArgs.ArtifactDir, "artifacts", "",
		"Directory to write failure diagnostics into")
	testCmd.Flags().IntVar(&tArgs.Parallel, "parallel", 0,
		"Maximum number of tests to run concurrently. 0 leaves the go test default")

	rootCmd.AddCommand(listCmd, provisionCmd, prepareCmd, installCmd, testCmd, teardownCmd, allCmd)
}

func ctxWithSignals() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func newRunner(loadState bool) (*scenario.Runner, error) {
	s, err := scenario.Get(gArgs.Scenario)
	if err != nil {
		return nil, err
	}

	return scenario.NewRunner(s, &scenario.RunnerOpts{
		StatePath: gArgs.StatePath,
		LoadState: loadState,
	})
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List the available scenarios",
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, id := range scenario.IDs() {
			s, err := scenario.Get(id)
			if err != nil {
				return err
			}

			var caps []string
			for _, c := range s.Caps {
				caps = append(caps, string(c))
			}

			fmt.Printf("%-16s %s\n", id, s.Description)
			fmt.Printf("%-16s provisioner=%s cni=%s nodes=%d caps=[%s]\n\n",
				"", s.Provisioner.Name(), s.CNI, s.Topology.Nodes, strings.Join(caps, " "))
		}
		return nil
	},
}

var provisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Bring up the Kubernetes cluster the scenario runs on",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := ctxWithSignals()
		defer cancel()

		r, err := newRunner(false)
		if err != nil {
			return err
		}

		return r.Provision(ctx)
	},
}

var prepareCmd = &cobra.Command{
	Use:   "prepare",
	Short: "Install the Cluster's dependencies: storage, Multus and telemetry",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := ctxWithSignals()
		defer cancel()

		r, err := newRunner(true)
		if err != nil {
			return err
		}

		return r.Prepare(ctx)
	},
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the Octelium Cluster and wait for it to come up",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := ctxWithSignals()
		defer cancel()

		r, err := newRunner(true)
		if err != nil {
			return err
		}

		return r.Install(ctx)
	},
}

var teardownCmd = &cobra.Command{
	Use:   "teardown",
	Short: "Remove the cluster and the state file",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := ctxWithSignals()
		defer cancel()

		r, err := newRunner(true)
		if err != nil {
			return err
		}

		return r.Teardown(ctx)
	},
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run the end-to-end suite against an installed Cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := ctxWithSignals()
		defer cancel()

		r, err := newRunner(true)
		if err != nil {
			return err
		}

		return runSuite(ctx, r)
	},
}

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Run every stage: provision, prepare, install and test",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := ctxWithSignals()
		defer cancel()

		r, err := newRunner(false)
		if err != nil {
			return err
		}

		if err := r.Provision(ctx); err != nil {
			return err
		}
		if err := r.Prepare(ctx); err != nil {
			return err
		}
		if err := r.Install(ctx); err != nil {
			return err
		}

		return runSuite(ctx, r)
	},
}

func runSuite(ctx context.Context, r *scenario.Runner) error {
	pkg := "./tests/..."

	cmdArgs := []string{"test", "-tags", "e2e", "-count=1"}
	if tArgs.Verbose {
		cmdArgs = append(cmdArgs, "-v")
	}
	if tArgs.Timeout != "" {
		cmdArgs = append(cmdArgs, "-timeout", tArgs.Timeout)
	}
	if tArgs.Parallel > 0 {
		cmdArgs = append(cmdArgs, fmt.Sprintf("-parallel=%d", tArgs.Parallel))
	}
	cmdArgs = append(cmdArgs, pkg)
	if tArgs.Run != "" {
		cmdArgs = append(cmdArgs, "-run", tArgs.Run)
	}

	cmd := exec.CommandContext(ctx, "go", cmdArgs...)
	cmd.Dir = moduleDir()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("%s=%s", scenario.StatePathEnv, r.StatePath()))

	if tArgs.ArtifactDir != "" {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("%s=%s", harness.ArtifactDirEnv, tArgs.ArtifactDir))
	}

	zap.L().Info("Running the e2e suite",
		zap.String("scenario", r.Scenario.ID),
		zap.Strings("args", cmdArgs),
		zap.String("dir", cmd.Dir))

	return cmd.Run()
}

func moduleDir() string {
	if val := os.Getenv("OCTELIUM_E2E_DIR"); val != "" {
		return val
	}

	for _, candidate := range []string{"cluster/e2e", "."} {
		if _, err := os.Stat(candidate + "/go.mod"); err == nil {
			return candidate
		}
	}

	return "."
}
