// Package benchexec is the shared subprocess-execution seam for the
// US-008 pipeline helper binaries (cmd/benchops, cmd/benchjanitor).
// The helpers keep all conditional/loop/state-machine logic in Go and
// use this interface for transport, so every workflow step is a thin
// invocation and every loop is unit-testable with a fake runner.
package benchexec

import (
	"io"
	"os/exec"
)

// Runner abstracts subprocess execution.
type Runner interface {
	// Output runs a command and returns its stdout; stderr passes
	// through to the configured stderr writer.
	Output(name string, arguments ...string) ([]byte, error)
	// Run runs a command in a directory, streaming stdout and stderr
	// through.
	Run(directory, name string, arguments ...string) error
}

// ExecRunner is the real subprocess-backed Runner.
type ExecRunner struct {
	Stdout io.Writer
	Stderr io.Writer
}

// Output implements Runner.
func (r ExecRunner) Output(name string, arguments ...string) ([]byte, error) {
	command := exec.Command(name, arguments...)
	command.Stderr = r.Stderr
	return command.Output()
}

// Run implements Runner.
func (r ExecRunner) Run(directory, name string, arguments ...string) error {
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Stdout = r.Stdout
	command.Stderr = r.Stderr
	return command.Run()
}
