package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"
)

const (
	wstestPath          = "/opt/pypy/bin/wstest"
	wstestDigest        = "sha256:d8acff20961f3fc8d396944e4d38f3d06ddb11301f123670f557d6284b6ea632"
	pypyPath            = "/opt/pypy/bin/pypy"
	pypyDigest          = "sha256:14c4d94ca4b7feee06acf12cf7d74e3e6fc63114d2886e5f0c45afce84250a6c"
	maximumChildOutput  = int64(16 << 20)
	maximumChildRuntime = 180 * time.Second
	copySignalTimeout   = 60 * time.Second
	maximumReportFile   = int64(64 << 20)
	maximumReportBytes  = int64(256 << 20)
	expectedReportFiles = 4
	reportsPath         = "/reports"
)

var (
	tokenPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reportNamePattern = regexp.MustCompile(`^[a-z0-9_]+\.(?:html|json)$`)
)

type runnerContract struct {
	role       string
	configPath string
	arguments  []string
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "copy-reports" {
		os.Exit(runReportCopy(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stderr))
}

func runReportCopy(arguments []string, input io.Reader, output, lifecycle io.Writer) int {
	if len(arguments) != 1 || arguments[0] != "copy-reports" {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED report-copy-arguments")
		return 2
	}
	role, rolePresent := os.LookupEnv("AUTOBAHN_RUNNER_ROLE")
	token, tokenPresent := os.LookupEnv("AUTOBAHN_RUNNER_TOKEN")
	contract, contractErr := fixedContract(role)
	if !rolePresent || !tokenPresent || contractErr != nil || !tokenPattern.MatchString(token) {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED report-copy-environment")
		return 2
	}
	if err := readCopySignal(input, token); err != nil {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED report-copy-signal")
		return 1
	}
	if digest, err := digestRegular(wstestPath, 1<<20); err != nil || digest != wstestDigest {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED report-copy-wstest")
		return 2
	}
	if digest, err := digestRegular(pypyPath, 32<<20); err != nil || digest != pypyDigest {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED report-copy-interpreter")
		return 2
	}
	if _, err := digestRegular(contract.configPath, 1<<20); err != nil {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED report-copy-config")
		return 2
	}
	if err := writeReportArchive(reportsPath, output); err != nil {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED report-copy-files")
		return 1
	}
	fmt.Fprintf(lifecycle, "RUNNER_REPORTS_COMPLETE role=%s files=%d maximum_bytes=%d\n", role, expectedReportFiles, maximumReportBytes)
	return 0
}

func writeReportArchive(directory string, output io.Writer) error {
	root, err := os.Lstat(directory)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return errors.New("report root is not a real directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != expectedReportFiles {
		return errors.New("report root does not contain exactly four entries")
	}
	names := make([]string, 0, len(entries))
	var aggregate int64
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Base(name) != name || !reportNamePattern.MatchString(name) {
			return errors.New("report entry name is not fixed and safe")
		}
		path := filepath.Join(directory, name)
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximumReportFile || reportLinkCount(info) != 1 {
			return errors.New("report entry is not one bounded regular file")
		}
		if aggregate > maximumReportBytes-info.Size() {
			return errors.New("report entries exceed the aggregate bound")
		}
		aggregate += info.Size()
		names = append(names, name)
	}
	sort.Strings(names)
	archive := tar.NewWriter(output)
	for _, name := range names {
		path := filepath.Join(directory, name)
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximumReportFile || reportLinkCount(before) != 1 {
			return errors.New("report entry changed before streaming")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, opened) || reportLinkCount(opened) != 1 {
			_ = file.Close()
			return errors.New("report entry identity changed before streaming")
		}
		header := &tar.Header{Name: name, Mode: 0o400, Size: before.Size(), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := archive.WriteHeader(header); err != nil {
			_ = file.Close()
			return err
		}
		written, copyErr := io.CopyN(archive, file, before.Size())
		afterFD, fdErr := file.Stat()
		afterPath, pathErr := os.Lstat(path)
		closeErr := file.Close()
		if copyErr != nil || written != before.Size() || fdErr != nil || pathErr != nil || closeErr != nil || !os.SameFile(before, afterFD) || !os.SameFile(afterFD, afterPath) || afterFD.Size() != before.Size() || afterFD.ModTime() != before.ModTime() || reportLinkCount(afterFD) != 1 || reportLinkCount(afterPath) != 1 {
			return errors.New("report entry changed while streaming")
		}
	}
	afterEntries, err := os.ReadDir(directory)
	if err != nil || len(afterEntries) != len(names) {
		return errors.New("report entry set changed while streaming")
	}
	for index, entry := range afterEntries {
		if entry.Name() != names[index] {
			return errors.New("report entry set changed while streaming")
		}
	}
	return archive.Close()
}

func reportLinkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 1
}

func run(arguments []string, input io.Reader, lifecycle io.Writer) int {
	if len(arguments) != 0 {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED arguments")
		return 2
	}
	role, rolePresent := os.LookupEnv("AUTOBAHN_RUNNER_ROLE")
	token, tokenPresent := os.LookupEnv("AUTOBAHN_RUNNER_TOKEN")
	contract, err := fixedContract(role)
	if !rolePresent || !tokenPresent || err != nil || !tokenPattern.MatchString(token) {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED environment")
		return 2
	}
	if digest, err := digestRegular(wstestPath, 1<<20); err != nil || digest != wstestDigest {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED wstest")
		return 2
	}
	if digest, err := digestRegular(pypyPath, 32<<20); err != nil || digest != pypyDigest {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED interpreter")
		return 2
	}
	configDigest, err := digestRegular(contract.configPath, 1<<20)
	if err != nil {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED config")
		return 2
	}

	copySignal := make(chan error, 1)
	go func() { copySignal <- readCopySignal(input, token) }()
	output := newBoundedDigestWriter(lifecycle, maximumChildOutput)
	command := exec.Command(wstestPath, contract.arguments...)
	command.Env = []string{
		"HOME=/nonexistent", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
		"PATH=/opt/pypy/bin:/usr/bin:/bin", "PYTHONHASHSEED=0", "PYTHONUNBUFFERED=1", "TZ=UTC",
	}
	command.Stdin = nil
	command.Stdout = output
	command.Stderr = output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		fmt.Fprintln(lifecycle, "RUNNER_DENIED child-start")
		return 1
	}
	fmt.Fprintf(lifecycle, "RUNNER_READY role=%s config=%s wstest=%s interpreter=%s\n", contract.role, configDigest, wstestDigest, pypyDigest)
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	timeout := time.NewTimer(maximumChildRuntime)
	defer timeout.Stop()

	if contract.role == "fuzzingserver" {
		select {
		case signalErr := <-copySignal:
			if signalErr != nil {
				terminateAndWait(command, waited)
				fmt.Fprintln(lifecycle, "RUNNER_DENIED copy-signal")
				return 1
			}
			terminateAndWait(command, waited)
			fmt.Fprintln(lifecycle, "RUNNER_COPY_COMPLETE role=fuzzingserver child=controller-stopped")
			return 0
		case childErr := <-waited:
			writeChildExit(lifecycle, contract.role, childErr, output)
			return awaitCopySignal(copySignal, lifecycle, contract.role, 1)
		case <-timeout.C:
			terminateAndWait(command, waited)
			fmt.Fprintln(lifecycle, "RUNNER_DENIED child-timeout")
			return 1
		}
	}

	select {
	case childErr := <-waited:
		writeChildExit(lifecycle, contract.role, childErr, output)
		code := 0
		if childErr != nil {
			code = 1
		}
		return awaitCopySignal(copySignal, lifecycle, contract.role, code)
	case signalErr := <-copySignal:
		terminateAndWait(command, waited)
		if signalErr != nil {
			fmt.Fprintln(lifecycle, "RUNNER_DENIED copy-signal")
		} else {
			fmt.Fprintln(lifecycle, "RUNNER_DENIED premature-copy-signal")
		}
		return 1
	case <-timeout.C:
		terminateAndWait(command, waited)
		fmt.Fprintln(lifecycle, "RUNNER_DENIED child-timeout")
		return 1
	}
}

func fixedContract(role string) (runnerContract, error) {
	switch role {
	case "fuzzingclient":
		return runnerContract{role: role, configPath: "/config/fuzzingclient.json", arguments: []string{"--mode", role, "--spec", "/config/fuzzingclient.json"}}, nil
	case "fuzzingserver":
		return runnerContract{role: role, configPath: "/config/fuzzingserver.json", arguments: []string{"--mode", role, "--spec", "/config/fuzzingserver.json"}}, nil
	default:
		return runnerContract{}, errors.New("invalid fixed runner role")
	}
}

func readCopySignal(input io.Reader, expected string) error {
	data, err := io.ReadAll(io.LimitReader(input, 67))
	if err != nil || string(data) != expected+"\n" {
		return errors.New("copy signal differs")
	}
	return nil
}

func awaitCopySignal(signal <-chan error, lifecycle io.Writer, role string, childCode int) int {
	timer := time.NewTimer(copySignalTimeout)
	defer timer.Stop()
	select {
	case err := <-signal:
		if err != nil {
			fmt.Fprintln(lifecycle, "RUNNER_DENIED copy-signal")
			return 1
		}
		fmt.Fprintf(lifecycle, "RUNNER_COPY_COMPLETE role=%s child=exited\n", role)
		return childCode
	case <-timer.C:
		fmt.Fprintln(lifecycle, "RUNNER_DENIED copy-timeout")
		return 1
	}
}

func terminateAndWait(command *exec.Cmd, waited <-chan error) {
	if command == nil || command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	select {
	case <-waited:
		return
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		<-waited
	}
}

func writeChildExit(lifecycle io.Writer, role string, err error, output *boundedDigestWriter) {
	code := 0
	if err != nil {
		code = 1
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		}
	}
	digest, bytes := output.receipt()
	fmt.Fprintf(lifecycle, "RUNNER_CHILD_EXIT role=%s code=%d output=%s bytes=%d\n", role, code, digest, bytes)
}

func digestRegular(path string, maximum int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return "", errors.New("not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	if err != nil || written != info.Size() {
		return "", errors.New("file changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

type boundedDigestWriter struct {
	mu      sync.Mutex
	output  io.Writer
	hash    hash.Hash
	limit   int64
	written int64
}

func newBoundedDigestWriter(output io.Writer, limit int64) *boundedDigestWriter {
	return &boundedDigestWriter{output: output, hash: sha256.New(), limit: limit}
}

func (w *boundedDigestWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if int64(len(data)) > w.limit-w.written {
		return 0, errors.New("child output exceeds bound")
	}
	if _, err := w.output.Write(data); err != nil {
		return 0, err
	}
	_, _ = w.hash.Write(data)
	w.written += int64(len(data))
	return len(data), nil
}

func (w *boundedDigestWriter) receipt() (string, int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return "sha256:" + hex.EncodeToString(w.hash.Sum(nil)), w.written
}
