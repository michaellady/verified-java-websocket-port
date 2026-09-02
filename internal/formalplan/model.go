// Package formalplan validates the US-006 formal-plan artifacts. This file is
// Lane B's connection-model validator: structural checks over
// assurance/formal/connection-model.tla and its TLC configuration. All
// identifiers here are lane-scoped (Model*/mp* prefixes) so Lane A files can
// land in this package independently.
package formalplan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ModelFinding is a typed validation finding. Severity is either
// SeverityBlocking (the artifact must not ship) or SeverityAdvisory (a check
// could not run in this environment and says so instead of passing silently).
type ModelFinding struct {
	Code     string `json:"code"`
	Path     string `json:"path"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

const (
	SeverityBlocking = "blocking"
	SeverityAdvisory = "advisory"

	// ModelModuleName is the TLA+ module name. TLA+ module identifiers cannot
	// contain hyphens, so the shipped file connection-model.tla must be staged
	// as ConnectionModel.tla before a TLC run; the artifact carries an explicit
	// staging note that this validator requires.
	ModelModuleName = "ConnectionModel"

	// FrameModelModuleName and CloseModelModuleName are the US-012 AC5 and
	// US-016 AC4 model modules. They are validated by exactly the same
	// structural rules as the connection model (same falsification-note,
	// citation, cfg-coverage, and proof-only-duplicate checks); only the
	// module name and therefore the staging note differ.
	FrameModelModuleName = "FrameModel"
	CloseModelModuleName = "CloseModel"

	mpMaxArtifactBytes = 1 << 20
)

// mpStagingNote is the staging directive a model artifact must carry,
// because TLA+ module identifiers cannot contain the hyphen the shipped
// file names use.
func mpStagingNote(moduleName string) string {
	return "STAGE AS: " + moduleName + ".tla"
}

// mpModuleHeaderPattern builds the module-header matcher for one module.
func mpModuleHeaderPattern(moduleName string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^----+ MODULE ` + regexp.QuoteMeta(moduleName) + ` ----+$`)
}

// ModelValidationLimits documents, honestly, what this static validator does
// NOT establish. String-shape validation was an identified gap in the first-
// finish plane's US-006 attempt; this validator goes as far as is statically
// feasible (cfg coverage, primed/temporal-operator detection in invariant
// bodies, citation resolution against the quarantined Java tree, falsification
// annotations) and the rest is recorded here instead of being claimed.
const ModelValidationLimits = "Static checks only: no SANY parse (grammar and " +
	"level-checking unverified), no TLC execution (reachability, deadlock, " +
	"liveness, and state-space finiteness under the shipped bounds are " +
	"asserted by construction, not machine-checked), and no semantic vacuity " +
	"check (a property could still be unfalsifiable if a guard makes its " +
	"violation unreachable; the seeded-defect table in " +
	"assurance/concurrency/plan.json records the mutations that must produce " +
	"TLC counterexamples once the tool is available). Comment stripping " +
	"handles line comments only; block comments are rejected outright."

var (
	mpDefinitionStart = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_]*)(\([A-Za-z0-9_, ]*\))? ==`)
	mpCitationPattern = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_/]*\.java):([0-9]+)(?:-([0-9]+))?$`)
	mpConstantsLine   = regexp.MustCompile(`^CONSTANTS?\s+(.*)$`)
	mpCfgAssignment   = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.+)$`)
	mpIdentifier      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	mpRustMarkers     = []string{"pub fn", "fn main", "impl ", "use std", "unsafe {", "#["}
)

func mpFinding(code, path, detail string) ModelFinding {
	return ModelFinding{Code: code, Path: path, Detail: detail, Severity: SeverityBlocking}
}

func mpAdvisory(code, path, detail string) ModelFinding {
	return ModelFinding{Code: code, Path: path, Detail: detail, Severity: SeverityAdvisory}
}

func mpReadText(path string) (string, *ModelFinding) {
	info, err := os.Stat(path)
	if err != nil {
		finding := mpFinding("MODEL_FILE_UNREADABLE", path, err.Error())
		return "", &finding
	}
	if info.Size() > mpMaxArtifactBytes {
		finding := mpFinding("MODEL_FILE_UNREADABLE", path, "artifact exceeds the bounded size")
		return "", &finding
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		finding := mpFinding("MODEL_FILE_UNREADABLE", path, err.Error())
		return "", &finding
	}
	text := string(raw)
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || strings.Contains(text, "\r") {
		finding := mpFinding("MODEL_ENCODING_INVALID", path, "artifact must be NUL-free LF-only UTF-8")
		return "", &finding
	}
	return text, nil
}

// mpStripLineComment removes a \* line comment (TLA) from a single line.
func mpStripLineComment(line string) string {
	if index := strings.Index(line, `\*`); index >= 0 {
		return line[:index]
	}
	return line
}

// mpStripStrings removes double-quoted string literals from a line so that
// apostrophes and operator-shaped characters inside strings are not
// misread as primes or temporal operators.
func mpStripStrings(line string) string {
	var builder strings.Builder
	inString := false
	for _, r := range line {
		if r == '"' {
			inString = !inString
			continue
		}
		if !inString {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func mpCleanLine(line string) string {
	return mpStripStrings(mpStripLineComment(line))
}

// mpBlock is one top-level definition block of the module, in raw form.
type mpBlock struct {
	Name      string
	StartLine int
	RawLines  []string
}

func mpDefinitionBlocks(lines []string) []mpBlock {
	var blocks []mpBlock
	var current *mpBlock
	commit := func() {
		if current == nil {
			return
		}
		// Trailing blank and comment-only lines belong to the NEXT
		// definition (they are its preceding comment), not to this block.
		raw := current.RawLines
		for len(raw) > 0 {
			trimmed := strings.TrimSpace(raw[len(raw)-1])
			if trimmed == "" || strings.HasPrefix(trimmed, `\*`) {
				raw = raw[:len(raw)-1]
				continue
			}
			break
		}
		current.RawLines = raw
		blocks = append(blocks, *current)
	}
	for index, line := range lines {
		if match := mpDefinitionStart.FindStringSubmatch(line); match != nil {
			commit()
			current = &mpBlock{Name: match[1], StartLine: index}
		}
		if current != nil {
			current.RawLines = append(current.RawLines, line)
		}
	}
	commit()
	return blocks
}

func (b mpBlock) cleanBody() string {
	var cleaned []string
	for _, line := range b.RawLines {
		cleaned = append(cleaned, mpCleanLine(line))
	}
	return strings.Join(cleaned, "\n")
}

// mpCfg is the parsed TLC configuration.
type mpCfg struct {
	Specification string
	Constants     map[string]string
	Invariants    []string
	Properties    []string
}

func mpParseCfg(text string) (mpCfg, []ModelFinding) {
	cfg := mpCfg{Constants: map[string]string{}}
	var findings []ModelFinding
	section := ""
	for number, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(mpStripLineComment(rawLine))
		if line == "" {
			continue
		}
		location := fmt.Sprintf("cfg:%d", number+1)
		fields := strings.Fields(line)
		switch fields[0] {
		case "SPECIFICATION":
			section = ""
			if len(fields) == 2 {
				cfg.Specification = fields[1]
			} else {
				findings = append(findings, mpFinding("TLA_CFG_MALFORMED", location, "SPECIFICATION takes exactly one operator name"))
			}
		case "CONSTANT", "CONSTANTS":
			section = "constants"
			if len(fields) > 1 {
				findings = append(findings, mpFinding("TLA_CFG_MALFORMED", location, "constant assignments must be on their own lines"))
			}
		case "INVARIANT", "INVARIANTS":
			section = ""
			if len(fields) < 2 {
				findings = append(findings, mpFinding("TLA_CFG_MALFORMED", location, "INVARIANT takes operator names"))
			}
			cfg.Invariants = append(cfg.Invariants, fields[1:]...)
		case "PROPERTY", "PROPERTIES":
			section = ""
			if len(fields) < 2 {
				findings = append(findings, mpFinding("TLA_CFG_MALFORMED", location, "PROPERTY takes operator names"))
			}
			cfg.Properties = append(cfg.Properties, fields[1:]...)
		default:
			if section == "constants" {
				if match := mpCfgAssignment.FindStringSubmatch(line); match != nil {
					cfg.Constants[match[1]] = strings.TrimSpace(match[2])
				} else {
					findings = append(findings, mpFinding("TLA_CFG_MALFORMED", location, "unrecognized constant assignment"))
				}
			} else {
				findings = append(findings, mpFinding("TLA_CFG_MALFORMED", location, "unrecognized configuration directive"))
			}
		}
	}
	return cfg, findings
}

// mpParseCitation validates the File.java:start[-end] format (including line
// ordering) without touching the filesystem.
func mpParseCitation(citation string) (file string, endLine int, err error) {
	match := mpCitationPattern.FindStringSubmatch(citation)
	if match == nil {
		return "", 0, fmt.Errorf("citation %q is not File.java:start[-end]", citation)
	}
	start, err := strconv.Atoi(match[2])
	if err != nil || start < 1 {
		return "", 0, fmt.Errorf("citation %q has an invalid start line", citation)
	}
	end := start
	if match[3] != "" {
		end, err = strconv.Atoi(match[3])
		if err != nil || end < start {
			return "", 0, fmt.Errorf("citation %q has an invalid line range", citation)
		}
	}
	return match[1], end, nil
}

// mpResolveCitation checks one File.java:start[-end] citation against the
// quarantined Java tree rooted at javaRoot (the org/java_websocket package
// root). It returns a human-readable error when the citation does not resolve.
func mpResolveCitation(javaRoot, citation string) error {
	file, end, err := mpParseCitation(citation)
	if err != nil {
		return err
	}
	path := filepath.Join(javaRoot, filepath.FromSlash(file))
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("citation %q does not resolve: %v", citation, err)
	}
	lineCount := strings.Count(string(raw), "\n") + 1
	if end > lineCount {
		return fmt.Errorf("citation %q exceeds %s (%d lines)", citation, file, lineCount)
	}
	return nil
}

// ValidateConnectionModel statically validates the shipped TLA+ connection
// model and its TLC configuration. quarantineJavaRoot is the absolute or
// caller-relative path to the quarantined org/java_websocket package root;
// when empty or absent, citation resolution is reported as an advisory
// finding instead of silently passing.
func ValidateConnectionModel(tlaPath, cfgPath, quarantineJavaRoot string) []ModelFinding {
	return ValidateTLAModel(ModelModuleName, tlaPath, cfgPath, quarantineJavaRoot)
}

// ValidateTLAModel is the module-parameterised form of the connection-model
// validator. The US-012 frame model and the US-016 close model are held to
// the identical structural contract — one shared rule set, no parallel
// validation stack — so a new model artifact cannot ship with weaker
// checking than the incumbent one.
func ValidateTLAModel(moduleName, tlaPath, cfgPath, quarantineJavaRoot string) []ModelFinding {
	var findings []ModelFinding

	tlaText, failure := mpReadText(tlaPath)
	if failure != nil {
		findings = append(findings, *failure)
	}
	cfgText, failure := mpReadText(cfgPath)
	if failure != nil {
		findings = append(findings, *failure)
	}
	if len(findings) > 0 {
		return findings
	}

	if strings.Contains(tlaText, "(*") || strings.Contains(cfgText, "(*") {
		findings = append(findings, mpFinding("TLA_BLOCK_COMMENT_UNSUPPORTED", tlaPath,
			"block comments defeat this validator's line-based comment stripping; use \\* comments only"))
	}
	if !mpModuleHeaderPattern(moduleName).MatchString(tlaText) {
		findings = append(findings, mpFinding("MODEL_HEADER_MISSING", tlaPath,
			"module header ---- MODULE "+moduleName+" ---- not found"))
	}
	stagingNote := mpStagingNote(moduleName)
	if !strings.Contains(tlaText, stagingNote) {
		findings = append(findings, mpFinding("MODEL_STAGING_NOTE_MISSING", tlaPath,
			"the artifact must carry the staging note '"+stagingNote+"' because TLA+ module names cannot contain hyphens"))
	}
	if !strings.Contains(tlaText, `\* MODEL_CHECK:`) {
		findings = append(findings, mpFinding("MODEL_CHECK_STATUS_MISSING", tlaPath,
			"the artifact must record its model-check status (\\* MODEL_CHECK: EXECUTED ... or MODEL_CHECK_PENDING_TOOL with the probes run)"))
	}

	lines := strings.Split(tlaText, "\n")
	blocks := mpDefinitionBlocks(lines)
	blockByName := map[string]mpBlock{}
	for _, block := range blocks {
		blockByName[block.Name] = block
	}

	// Declared constants must all be assigned finite positive integer bounds
	// in the cfg, and the cfg must not assign undeclared constants.
	declaredConstants := map[string]bool{}
	for _, line := range lines {
		clean := strings.TrimSpace(mpCleanLine(line))
		if match := mpConstantsLine.FindStringSubmatch(clean); match != nil {
			for _, name := range strings.Split(match[1], ",") {
				name = strings.TrimSpace(name)
				if mpIdentifier.MatchString(name) {
					declaredConstants[name] = true
				}
			}
		}
	}
	cfg, cfgFindings := mpParseCfg(cfgText)
	findings = append(findings, cfgFindings...)
	for name := range declaredConstants {
		value, assigned := cfg.Constants[name]
		if !assigned {
			findings = append(findings, mpFinding("TLA_CONSTANT_UNCONFIGURED", cfgPath,
				"declared constant "+name+" has no cfg assignment; the model is not executable without concrete finite bounds"))
			continue
		}
		bound, err := strconv.Atoi(value)
		if err != nil || bound < 1 {
			findings = append(findings, mpFinding("TLA_CFG_CONSTANT_NOT_POSITIVE", cfgPath,
				"constant "+name+" must be a concrete positive integer bound, got "+value))
		}
	}
	var extraConstants []string
	for name := range cfg.Constants {
		if !declaredConstants[name] {
			extraConstants = append(extraConstants, name)
		}
	}
	sort.Strings(extraConstants)
	for _, name := range extraConstants {
		findings = append(findings, mpFinding("TLA_CFG_EXTRA_CONSTANT", cfgPath,
			"cfg assigns "+name+" which the module does not declare"))
	}

	if cfg.Specification == "" {
		findings = append(findings, mpFinding("TLA_SPECIFICATION_UNDEFINED", cfgPath, "cfg names no SPECIFICATION"))
	} else if _, defined := blockByName[cfg.Specification]; !defined {
		findings = append(findings, mpFinding("TLA_SPECIFICATION_UNDEFINED", cfgPath,
			"SPECIFICATION "+cfg.Specification+" is not defined in the module"))
	}
	if len(cfg.Invariants) == 0 {
		findings = append(findings, mpFinding("TLA_NO_INVARIANT", cfgPath, "cfg lists no INVARIANT"))
	}
	if len(cfg.Properties) == 0 {
		findings = append(findings, mpFinding("TLA_NO_PROPERTY", cfgPath, "cfg lists no PROPERTY"))
	}

	// Invariants must be genuine state predicates: no primed variables, no
	// temporal or action operators. Tuple brackets are removed before the
	// temporal-operator scan so <<...>> is not misread as <>.
	for _, name := range cfg.Invariants {
		block, defined := blockByName[name]
		if !defined {
			findings = append(findings, mpFinding("TLA_INVARIANT_UNDEFINED", cfgPath,
				"INVARIANT "+name+" is not defined in the module"))
			continue
		}
		body := block.cleanBody()
		if strings.Contains(body, "'") {
			findings = append(findings, mpFinding("TLA_PRIMED_INVARIANT", name,
				"invariant "+name+" references primed variables; it is an action property, not a state invariant"))
		}
		scannable := strings.ReplaceAll(strings.ReplaceAll(body, "<<", ""), ">>", "")
		for _, operator := range []string{"[]", "<>", "~>", "ENABLED", "WF_", "SF_"} {
			if strings.Contains(scannable, operator) {
				findings = append(findings, mpFinding("TLA_TEMPORAL_INVARIANT", name,
					"invariant "+name+" uses temporal operator "+operator+"; declare it under PROPERTY instead"))
			}
		}
	}
	for _, name := range cfg.Properties {
		if _, defined := blockByName[name]; !defined {
			findings = append(findings, mpFinding("TLA_PROPERTY_UNDEFINED", cfgPath,
				"PROPERTY "+name+" is not defined in the module"))
		}
	}

	// Every checked invariant and property must carry a falsification note:
	// the representable mutation that would make TLC report a violation.
	for _, name := range append(append([]string{}, cfg.Invariants...), cfg.Properties...) {
		block, defined := blockByName[name]
		if !defined {
			continue
		}
		if !mpPrecededByAnnotation(lines, block.StartLine, `\* FALSIFIED BY:`) {
			findings = append(findings, mpFinding("TLA_MISSING_FALSIFICATION_NOTE", name,
				"property "+name+" has no \\* FALSIFIED BY: annotation documenting the mutation that violates it"))
		}
	}

	// Every action (any definition that primes a variable or uses UNCHANGED)
	// must cite the quarantined Java source it abstracts.
	citations := map[string][]string{}
	for _, block := range blocks {
		body := block.cleanBody()
		isAction := strings.Contains(body, "'") || strings.Contains(body, "UNCHANGED")
		if !isAction {
			continue
		}
		blockCitations := append(
			mpExtractJavaCitations(mpPrecedingComment(lines, block.StartLine)),
			mpExtractJavaCitations(block.RawLines)...)
		if len(blockCitations) == 0 {
			findings = append(findings, mpFinding("TLA_MISSING_JAVA_CITATION", block.Name,
				"action "+block.Name+" carries no \\* JAVA: citation to the quarantined source it abstracts"))
			continue
		}
		citations[block.Name] = blockCitations
	}

	// Format-check every citation unconditionally, then resolve against the
	// quarantined tree when it is available; otherwise say so out loud
	// instead of passing silently.
	names := make([]string, 0, len(citations))
	for name := range citations {
		names = append(names, name)
	}
	sort.Strings(names)
	quarantinePresent := quarantineJavaRoot != "" && mpDirectoryExists(quarantineJavaRoot)
	for _, name := range names {
		for _, citation := range citations[name] {
			if _, _, err := mpParseCitation(citation); err != nil {
				findings = append(findings, mpFinding("MODEL_CITATION_MALFORMED", name, err.Error()))
				continue
			}
			if quarantinePresent {
				if err := mpResolveCitation(quarantineJavaRoot, citation); err != nil {
					findings = append(findings, mpFinding("MODEL_CITATION_UNRESOLVED", name, err.Error()))
				}
			}
		}
	}
	if !quarantinePresent {
		findings = append(findings, mpAdvisory("MODEL_CITATION_UNVERIFIED", tlaPath,
			"quarantined Java tree unavailable; \\* JAVA: citations were format-checked only"))
	}

	// Proof-only duplicate guard (AC4): the model must be specification
	// language only. This is a marker heuristic and is documented as such in
	// ModelValidationLimits.
	cleanedAll := make([]string, 0, len(lines))
	for _, line := range lines {
		cleanedAll = append(cleanedAll, mpCleanLine(line))
	}
	cleanedText := strings.Join(cleanedAll, "\n")
	for _, marker := range mpRustMarkers {
		if strings.Contains(cleanedText, marker) {
			findings = append(findings, mpFinding("TLA_RUST_DUPLICATE_SUSPECT", tlaPath,
				"model artifact contains the compilable-code marker "+strconv.Quote(marker)+"; a proof-only duplicate implementation is prohibited"))
		}
	}

	return findings
}

// mpPrecededByAnnotation reports whether the comment block immediately above
// line startLine contains the given annotation token.
func mpPrecededByAnnotation(lines []string, startLine int, annotation string) bool {
	for _, line := range mpPrecedingComment(lines, startLine) {
		if strings.Contains(line, annotation) {
			return true
		}
	}
	return false
}

// mpPrecedingComment returns the contiguous \*-comment lines directly above
// the definition at startLine.
func mpPrecedingComment(lines []string, startLine int) []string {
	var comment []string
	for index := startLine - 1; index >= 0; index-- {
		trimmed := strings.TrimSpace(lines[index])
		if strings.HasPrefix(trimmed, `\*`) {
			comment = append(comment, trimmed)
			continue
		}
		break
	}
	return comment
}

// mpExtractJavaCitations pulls the first token after every \* JAVA: marker.
func mpExtractJavaCitations(lines []string) []string {
	var citations []string
	for _, line := range lines {
		index := strings.Index(line, `\* JAVA:`)
		if index < 0 {
			continue
		}
		rest := strings.TrimSpace(line[index+len(`\* JAVA:`):])
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			citations = append(citations, fields[0])
		}
	}
	return citations
}

func mpDirectoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
