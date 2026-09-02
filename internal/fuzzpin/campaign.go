package fuzzpin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// RunRecord is one execution of a target's replay command.
type RunRecord struct {
	Run          int    `json:"run"`
	Command      string `json:"command"`
	Dir          string `json:"dir"`
	Exit         int    `json:"exit"`
	ExitText     string `json:"exit_text"`
	DeadlineHit  bool   `json:"deadline_hit"`
	WallSeconds  float64 `json:"wall_seconds"`
	LogPath      string `json:"log_path"`
	OutcomeLines []string `json:"outcome_lines"`
	OutcomeDigest string `json:"outcome_digest"`
}

// CampaignResult is a target's executed campaign: two runs of the same replay
// command whose normalized outcomes must be byte-identical. A replay command
// nobody ran is a string; this is the record that one was run.
type CampaignResult struct {
	Target      string      `json:"target"`
	Runs        []RunRecord `json:"runs"`
	Reproduced  bool        `json:"reproduced"`
	Failure     string      `json:"failure,omitempty"`
}

// cargoOutcomeLine matches cargo test's per-test result lines and the suite
// summary. These are the normalized observable: timings are excluded on
// purpose, because wall time is a property of the host, not of the campaign.
var cargoOutcomeLine = regexp.MustCompile(`^test [^ ]+ \.\.\. (ok|FAILED|ignored)$|^test result: `)

// normalizeOutcome extracts the host-independent outcome lines from a cargo
// test log: every per-test verdict plus the summary with its timing stripped.
func normalizeOutcome(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if !cargoOutcomeLine.MatchString(trimmed) {
			continue
		}
		if strings.HasPrefix(trimmed, "test result: ") {
			// "finished in 0.85s" is a host measurement, not an outcome.
			if idx := strings.Index(trimmed, "; finished in "); idx >= 0 {
				trimmed = trimmed[:idx]
			}
		}
		lines = append(lines, trimmed)
	}
	sort.Strings(lines)
	return lines
}

func digestLines(lines []string) string {
	hasher := sha256.New()
	for _, line := range lines {
		fmt.Fprintf(hasher, "%s\n", line)
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

// RunCampaign executes a target's replay command `runs` times, capturing each
// run's combined output to the target's artifact directory and reading each
// exit code from the real process state.
//
// The liveness guard is the target's declared WALL-CLOCK deadline (F005): a
// run that exceeds it is killed and recorded as a deadline hit, which fails
// the campaign. The deterministic case count is work, never the guard.
func RunCampaign(root string, target Target, runs int) CampaignResult {
	result := CampaignResult{Target: target.ID}
	if len(target.Replay.Command) == 0 {
		result.Failure = "no replay command declared"
		return result
	}
	deadline := time.Duration(target.Campaign.LivenessGuard.DeadlineSeconds) * time.Second
	if deadline <= 0 {
		result.Failure = "no positive wall-clock deadline declared; refusing to run unbounded"
		return result
	}
	artifactDir := filepath.Join(root, target.Artifacts.Dir)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		result.Failure = fmt.Sprintf("artifact dir: %v", err)
		return result
	}

	for run := 1; run <= runs; run++ {
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		cmd := exec.CommandContext(ctx, target.Replay.Command[0], target.Replay.Command[1:]...)
		cmd.Dir = filepath.Join(root, target.Replay.Dir)
		started := time.Now()
		combined, runErr := cmd.CombinedOutput()
		elapsed := time.Since(started)
		deadlineHit := ctx.Err() == context.DeadlineExceeded
		cancel()

		exit, exitText := completedExit(cmd.ProcessState, runErr)
		logPath := filepath.Join(artifactDir, fmt.Sprintf("%s-run%d.log", target.ID, run))
		header := fmt.Sprintf(
			"# target=%s run=%d\n# dir=%s\n# command=%s\n# wall_clock_deadline_seconds=%d\n# %s\n# deadline_hit=%t\n\n",
			target.ID, run, target.Replay.Dir, strings.Join(target.Replay.Command, " "),
			target.Campaign.LivenessGuard.DeadlineSeconds, exitText, deadlineHit)
		if err := os.WriteFile(logPath, append([]byte(header), combined...), 0o644); err != nil {
			result.Failure = fmt.Sprintf("write artifact: %v", err)
			return result
		}
		outcome := normalizeOutcome(string(combined))
		rel, _ := filepath.Rel(root, logPath)
		result.Runs = append(result.Runs, RunRecord{
			Run:           run,
			Command:       strings.Join(target.Replay.Command, " "),
			Dir:           target.Replay.Dir,
			Exit:          exit,
			ExitText:      exitText,
			DeadlineHit:   deadlineHit,
			WallSeconds:   elapsed.Round(time.Millisecond).Seconds(),
			LogPath:       filepath.ToSlash(rel),
			OutcomeLines:  outcome,
			OutcomeDigest: digestLines(outcome),
		})
	}

	// Every run must have exited 0, inside the deadline, with an identical
	// normalized outcome. Anything else is not a reproduction.
	for _, record := range result.Runs {
		if record.DeadlineHit {
			result.Failure = fmt.Sprintf("run %d hit the %ds wall-clock deadline",
				record.Run, target.Campaign.LivenessGuard.DeadlineSeconds)
			return result
		}
		if record.Exit != 0 {
			result.Failure = fmt.Sprintf("run %d %s", record.Run, record.ExitText)
			return result
		}
		if len(record.OutcomeLines) == 0 {
			result.Failure = fmt.Sprintf("run %d produced no test outcome lines", record.Run)
			return result
		}
	}
	for _, record := range result.Runs[1:] {
		if record.OutcomeDigest != result.Runs[0].OutcomeDigest {
			result.Failure = fmt.Sprintf(
				"run %d outcome digest %s differs from run 1 %s",
				record.Run, record.OutcomeDigest, result.Runs[0].OutcomeDigest)
			return result
		}
	}
	result.Reproduced = len(result.Runs) >= 2
	if !result.Reproduced {
		result.Failure = "reproduction needs at least two runs"
	}
	return result
}
