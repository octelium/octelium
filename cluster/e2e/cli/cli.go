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

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const ModuleDirEnv = "OCTELIUM_E2E_DIR"

type Opts struct {
	Name  string
	Short string

	DefaultScenario string

	TestPackage string

	ModuleDir           string
	ModuleDirCandidates []string
}

func (o *Opts) setDefaults() {
	if o.Name == "" {
		o.Name = "octelium-e2e"
	}
	if o.Short == "" {
		o.Short = "Provision an environment for the Octelium end-to-end suite and run it"
	}
	if o.DefaultScenario == "" {
		o.DefaultScenario = "k3s-flannel"
	}
	if o.TestPackage == "" {
		o.TestPackage = "./tests/..."
	}
	if len(o.ModuleDirCandidates) == 0 {
		o.ModuleDirCandidates = []string{"cluster/e2e", "."}
	}
}

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

type app struct {
	opts  Opts
	gArgs globalArgs
	tArgs testArgs
}

func Main(o Opts) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)

	if err := Execute(o); err != nil {
		zap.L().Fatal("e2e failed", zap.Error(err))
	}
}

func Execute(o Opts) error {
	o.setDefaults()
	return (&app{opts: o}).rootCmd().Execute()
}

func (a *app) rootCmd() *cobra.Command {
	ret := &cobra.Command{
		Use:           a.opts.Name,
		Short:         a.opts.Short,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	ret.PersistentFlags().StringVar(&a.gArgs.Scenario, "scenario", a.opts.DefaultScenario,
		fmt.Sprintf("The environment to run against. One of: %s",
			strings.Join(scenario.IDs(), ", ")))
	ret.PersistentFlags().StringVar(&a.gArgs.StatePath, "state", "",
		"Path to the file the stages use to hand state to each other")

	testCmd := a.testCmd()

	testCmd.Flags().StringVar(&a.tArgs.Run, "run", "",
		"Only run tests matching this regular expression, as `go test -run`")
	testCmd.Flags().StringVar(&a.tArgs.Timeout, "timeout", "90m",
		"Wall-clock budget for the whole suite")
	testCmd.Flags().BoolVar(&a.tArgs.Verbose, "verbose", true, "Stream per-test output")
	testCmd.Flags().StringVar(&a.tArgs.ArtifactDir, "artifacts", "",
		"Directory to write failure diagnostics into")
	testCmd.Flags().IntVar(&a.tArgs.Parallel, "parallel", 0,
		"Maximum number of tests to run concurrently. 0 leaves the go test default")

	ret.AddCommand(a.listCmd(), a.provisionCmd(), a.prepareCmd(),
		a.installCmd(), testCmd, a.teardownCmd(), a.allCmd())

	return ret
}

func ctxWithSignals() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func (a *app) newRunner(loadState bool) (*scenario.Runner, error) {
	s, err := scenario.Get(a.gArgs.Scenario)
	if err != nil {
		return nil, err
	}

	return scenario.NewRunner(s, &scenario.RunnerOpts{
		StatePath: a.gArgs.StatePath,
		LoadState: loadState,
	})
}

func (a *app) stageCmd(use, short string, loadState bool,
	fn func(ctx context.Context, r *scenario.Runner) error) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := ctxWithSignals()
			defer cancel()

			r, err := a.newRunner(loadState)
			if err != nil {
				return err
			}

			return fn(ctx, r)
		},
	}
}

func (a *app) listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the available scenarios",
		RunE: func(cmd *cobra.Command, args []string) error {
			ids := scenario.IDs()
			for _, spec := range scenario.Specs() {
				if !slices.Contains(ids, spec.ID()) {
					ids = append(ids, spec.ID())
				}
			}

			for _, id := range ids {
				s, err := scenario.Get(id)
				if err != nil {
					fmt.Printf("%-22s %s\n\n", id, err)
					continue
				}
				printScenario(id, s)
			}

			return nil
		},
	}
}

func (a *app) provisionCmd() *cobra.Command {
	return a.stageCmd("provision", "Bring up the Kubernetes cluster the scenario runs on",
		false, func(ctx context.Context, r *scenario.Runner) error {
			return r.Provision(ctx)
		})
}

func (a *app) prepareCmd() *cobra.Command {
	return a.stageCmd("prepare", "Install the Cluster's dependencies: storage, Multus and telemetry",
		true, func(ctx context.Context, r *scenario.Runner) error {
			return r.Prepare(ctx)
		})
}

func (a *app) installCmd() *cobra.Command {
	return a.stageCmd("install", "Install the Octelium Cluster and wait for it to come up",
		true, func(ctx context.Context, r *scenario.Runner) error {
			return r.Install(ctx)
		})
}

func (a *app) teardownCmd() *cobra.Command {
	return a.stageCmd("teardown", "Remove the cluster and the state file",
		true, func(ctx context.Context, r *scenario.Runner) error {
			return r.Teardown(ctx)
		})
}

func (a *app) testCmd() *cobra.Command {
	return a.stageCmd("test", "Run the end-to-end suite against an installed Cluster",
		true, a.runSuite)
}

func (a *app) allCmd() *cobra.Command {
	return a.stageCmd("all", "Run every stage: provision, prepare, install and test",
		false, func(ctx context.Context, r *scenario.Runner) error {
			if err := r.Provision(ctx); err != nil {
				return err
			}
			if err := r.Prepare(ctx); err != nil {
				return err
			}
			if err := r.Install(ctx); err != nil {
				return err
			}

			return a.runSuite(ctx, r)
		})
}

func (a *app) runSuite(ctx context.Context, r *scenario.Runner) error {
	cmdArgs := []string{"test", "-tags", "e2e", "-count=1"}
	if a.tArgs.Verbose {
		cmdArgs = append(cmdArgs, "-v")
	}
	if a.tArgs.Timeout != "" {
		cmdArgs = append(cmdArgs, "-timeout", a.tArgs.Timeout)
	}
	if a.tArgs.Parallel > 0 {
		cmdArgs = append(cmdArgs, fmt.Sprintf("-parallel=%d", a.tArgs.Parallel))
	}
	cmdArgs = append(cmdArgs, a.opts.TestPackage)
	if a.tArgs.Run != "" {
		cmdArgs = append(cmdArgs, "-run", a.tArgs.Run)
	}

	cmd := exec.CommandContext(ctx, "go", cmdArgs...)
	cmd.Dir = a.moduleDir()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("%s=%s", scenario.StatePathEnv, r.StatePath()))

	if a.tArgs.ArtifactDir != "" {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("%s=%s", harness.ArtifactDirEnv, a.tArgs.ArtifactDir))
	}

	zap.L().Info("Running the e2e suite",
		zap.String("scenario", r.Scenario.ID),
		zap.Strings("args", cmdArgs),
		zap.String("dir", cmd.Dir))

	return cmd.Run()
}

func (a *app) moduleDir() string {
	if a.opts.ModuleDir != "" {
		return a.opts.ModuleDir
	}

	if val := os.Getenv(ModuleDirEnv); val != "" {
		return val
	}

	for _, candidate := range a.opts.ModuleDirCandidates {
		if _, err := os.Stat(candidate + "/go.mod"); err == nil {
			return candidate
		}
	}

	return "."
}

func printScenario(id string, s *scenario.Scenario) {
	var caps []string
	for _, c := range s.Caps {
		caps = append(caps, string(c))
	}

	fmt.Printf("%-22s %s\n", id, s.Description)
	fmt.Printf("%-22s provisioner=%s cni=%s nodes=%d caps=[%s]\n\n",
		"", s.Provisioner.Name(), s.CNI, s.Topology.Nodes, strings.Join(caps, " "))
}
