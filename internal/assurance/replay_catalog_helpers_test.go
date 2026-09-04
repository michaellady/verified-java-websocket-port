package assurance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

type replayMutationManifest struct {
	Operations []replayMutationOperation `json:"operations"`
}

type replayMutationOperation struct {
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	Pointer string `json:"pointer"`
	Value   any    `json:"value"`
}

func realizeReplayCaseRoot(t *testing.T, fixture replayCase) (string, string) {
	t.Helper()

	root := copiedAssuranceRoot(t)
	lifecyclePath := fixture.LifecyclePath
	if lifecyclePath == "" {
		lifecyclePath = lifecyclePathDefault
	}
	if fixture.MutationManifestPath != "" {
		applyReplayMutationManifest(t, root, fixture.MutationManifestPath)
	}
	return root, lifecyclePath
}

func applyReplayMutationManifest(t *testing.T, root, manifestPath string) {
	t.Helper()

	data := mustReadRepoFile(t, manifestPath)
	var manifest replayMutationManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode mutation manifest %s: %v", manifestPath, err)
	}
	for _, operation := range manifest.Operations {
		switch operation.Kind {
		case "json_set":
			applyJSONSetOperation(t, root, operation)
		case "raw_append":
			applyRawAppendOperation(t, root, operation)
		case "refresh_bindings":
			refreshLifecycleBindingsForRoot(t, root)
		case "checkpoint_eligible":
			makeLifecycleCheckpointEligible(t, root)
		default:
			t.Fatalf("unsupported mutation operation %q in %s", operation.Kind, manifestPath)
		}
	}
}

func applyJSONSetOperation(t *testing.T, root string, operation replayMutationOperation) {
	t.Helper()

	target := filepath.Join(root, filepath.FromSlash(operation.Target))
	value := readGenericJSONFile(t, target)
	updated, err := setJSONPointerValue(value, operation.Pointer, operation.Value)
	if err != nil {
		t.Fatalf("apply json_set %s%s: %v", operation.Target, operation.Pointer, err)
	}
	writeJSONFile(t, target, updated)
}

func applyRawAppendOperation(t *testing.T, root string, operation replayMutationOperation) {
	t.Helper()

	target := filepath.Join(root, filepath.FromSlash(operation.Target))
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read raw target %s: %v", operation.Target, err)
	}
	suffix, ok := operation.Value.(string)
	if !ok {
		t.Fatalf("raw_append %s requires string value, got %T", operation.Target, operation.Value)
	}
	writeRawFile(t, target, append(data, []byte(suffix)...))
}

func setJSONPointerValue(document any, pointer string, value any) (any, error) {
	tokens, err := decodeJSONPointer(pointer)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return value, nil
	}
	return setJSONPointerRecursive(document, tokens, value)
}

func setJSONPointerRecursive(current any, tokens []string, value any) (any, error) {
	if len(tokens) == 0 {
		return value, nil
	}
	switch container := current.(type) {
	case map[string]any:
		key := tokens[0]
		child, ok := container[key]
		if !ok && len(tokens) != 1 {
			return nil, fmt.Errorf("missing object key %q", key)
		}
		if len(tokens) == 1 {
			container[key] = value
			return container, nil
		}
		updated, err := setJSONPointerRecursive(child, tokens[1:], value)
		if err != nil {
			return nil, err
		}
		container[key] = updated
		return container, nil
	case []any:
		index, err := strconv.Atoi(tokens[0])
		if err != nil {
			return nil, fmt.Errorf("invalid array index %q", tokens[0])
		}
		if index < 0 || index >= len(container) {
			return nil, fmt.Errorf("array index %d out of range", index)
		}
		if len(tokens) == 1 {
			container[index] = value
			return container, nil
		}
		updated, err := setJSONPointerRecursive(container[index], tokens[1:], value)
		if err != nil {
			return nil, err
		}
		container[index] = updated
		return container, nil
	default:
		return nil, fmt.Errorf("cannot descend into %T", current)
	}
}

func decodeJSONPointer(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("json pointer %q must start with /", pointer)
	}
	parts := strings.Split(pointer[1:], "/")
	for index, part := range parts {
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")
		parts[index] = part
	}
	return parts, nil
}

func assertReplayDispositionCoverage(t *testing.T, catalog replayCaseCatalog) {
	t.Helper()

	caseByID := make(map[string]replayCase, len(catalog.Cases))
	for _, fixture := range catalog.Cases {
		caseByID[fixture.ID] = fixture
	}

	covered := map[vendorprotocol.Disposition]bool{}
	for _, mapping := range catalog.DispositionCoverage.CaseMapped {
		disposition := vendorprotocol.Disposition(mapping.Disposition)
		if len(mapping.CaseIDs) == 0 {
			t.Fatalf("disposition %s must map at least one retained case", disposition)
		}
		for _, caseID := range mapping.CaseIDs {
			fixture, ok := caseByID[caseID]
			if !ok {
				t.Fatalf("coverage references unknown case %q", caseID)
			}
			if !caseHasDisposition(fixture, disposition) {
				t.Fatalf("case %q does not actually emit disposition %s", caseID, disposition)
			}
		}
		covered[disposition] = true
	}

	registry := readFailureRegistry(t, repoRoot(t))
	registryByDisposition := make(map[vendorprotocol.Disposition][]string, 6)
	for _, entry := range registry.Entries {
		registryByDisposition[entry.Disposition] = append(registryByDisposition[entry.Disposition], entry.Code)
	}
	for _, mapping := range catalog.DispositionCoverage.RegistryOnly {
		disposition := vendorprotocol.Disposition(mapping.Disposition)
		assertExactStringSet(t, mapping.Codes, registryByDisposition[disposition])
		covered[disposition] = true
	}

	for _, disposition := range []vendorprotocol.Disposition{
		vendorprotocol.Retry,
		vendorprotocol.DegradeNonAssurance,
		vendorprotocol.Block,
		vendorprotocol.Invalidate,
		vendorprotocol.Quarantine,
		vendorprotocol.Revoke,
	} {
		if !covered[disposition] {
			t.Fatalf("catalog coverage missing disposition %s", disposition)
		}
	}
}

func caseHasDisposition(fixture replayCase, disposition vendorprotocol.Disposition) bool {
	for _, item := range fixture.VerifyFindings {
		if vendorprotocol.Disposition(item.Disposition) == disposition {
			return true
		}
	}
	for _, item := range fixture.ReplayFindings {
		if vendorprotocol.Disposition(item.Disposition) == disposition {
			return true
		}
	}
	return false
}
