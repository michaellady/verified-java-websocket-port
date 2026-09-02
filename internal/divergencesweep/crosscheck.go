package divergencesweep

import (
	"fmt"
	"os"
	"path/filepath"
)

// comparisonCase is one row of the independently produced per-case
// behaviour-class comparison committed with the run.
type comparisonCase struct {
	CaseID                  string `json:"case_id"`
	RustServerBehavior      string `json:"rust_server_behavior"`
	RustServerBehaviorClose string `json:"rust_server_behavior_close"`
	JavaServerBehavior      string `json:"java_server_behavior"`
	JavaServerBehaviorClose string `json:"java_server_behavior_close"`
	RustClientBehavior      string `json:"rust_client_behavior"`
	RustClientBehaviorClose string `json:"rust_client_behavior_close"`
	JavaClientBehavior      string `json:"java_client_behavior"`
	JavaClientBehaviorClose string `json:"java_client_behavior_close"`
}

type comparisonDocument struct {
	CompiledCaseCount int              `json:"compared_case_count"`
	Cases             []comparisonCase `json:"cases"`
}

// CrossCheckBehaviourClasses binds this sweep's leg-to-role mapping to a
// document produced by a different tool from the same run. If the mapping were
// reversed — the fuzzingclient leg read as the subject's client role — every
// row would disagree, so this refuses the one silent error that would make
// every close finding below point at the wrong role.
func CrossCheckBehaviourClasses(root string, legs map[string]*Leg) error {
	data, err := os.ReadFile(filepath.Join(root, ComparisonPath))
	if err != nil {
		return fmt.Errorf("comparison document: %w", err)
	}
	var comparison comparisonDocument
	if err := decodeJSON(data, &comparison); err != nil {
		return fmt.Errorf("comparison document: %w", err)
	}
	if len(comparison.Cases) != comparison.CompiledCaseCount {
		return fmt.Errorf("comparison document declares %d compared cases and lists %d",
			comparison.CompiledCaseCount, len(comparison.Cases))
	}
	if len(comparison.Cases) != ExpectedCaseCount {
		return fmt.Errorf("comparison document lists %d cases, this sweep walked %d",
			len(comparison.Cases), ExpectedCaseCount)
	}
	for _, row := range comparison.Cases {
		checks := []struct {
			legKey string
			field  string
			want   string
		}{
			{"rust/server", "behavior", row.RustServerBehavior},
			{"rust/server", "behaviorClose", row.RustServerBehaviorClose},
			{"java/server", "behavior", row.JavaServerBehavior},
			{"java/server", "behaviorClose", row.JavaServerBehaviorClose},
			{"rust/client", "behavior", row.RustClientBehavior},
			{"rust/client", "behaviorClose", row.RustClientBehaviorClose},
			{"java/client", "behavior", row.JavaClientBehavior},
			{"java/client", "behaviorClose", row.JavaClientBehaviorClose},
		}
		for _, check := range checks {
			leg, ok := legs[check.legKey]
			if !ok {
				return fmt.Errorf("cross-check: no loaded leg %s", check.legKey)
			}
			report, ok := leg.Cases[row.CaseID]
			if !ok {
				return fmt.Errorf("cross-check: leg %s has no case %s", check.legKey, row.CaseID)
			}
			got, _ := report[check.field].(string)
			if got != check.want {
				return fmt.Errorf("cross-check: leg %s case %s field %s: reports say %q, the committed comparison says %q",
					check.legKey, row.CaseID, check.field, got, check.want)
			}
		}
	}
	return nil
}
