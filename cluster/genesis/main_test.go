package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenesisShutdown(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_GENESIS_SHUTDOWN") == "true" {
		initCmd = &cobra.Command{Use: "init", RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Println("genesis-ready")
			<-cmd.Context().Done()
			fmt.Println("genesis-cancelled")
			return nil
		}}
		os.Args = []string{"genesis", "init"}
		main()
		return
	}
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGenesisShutdown$")
			command.Env = append(os.Environ(), "OCTELIUM_TEST_GENESIS_SHUTDOWN=true")
			stdout, err := command.StdoutPipe()
			require.NoError(t, err)
			command.Stderr = os.Stderr
			require.NoError(t, command.Start())
			var lines []string
			ready := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					line := scanner.Text()
					lines = append(lines, line)
					if line == "genesis-ready" {
						close(ready)
					}
				}
			}()
			select {
			case <-ready:
			case <-ctx.Done():
				command.Wait()
				t.Fatal("The genesis command did not start")
			}
			require.NoError(t, command.Process.Signal(sig))
			<-done
			require.NoError(t, command.Wait())
			assert.Contains(t, strings.Join(lines, "\n"), "genesis-cancelled")
		})
	}
}
