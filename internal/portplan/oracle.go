package portplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// OracleOutput is the compiler-derived semantic identity report emitted by java-semantic-oracle.
type OracleOutput struct {
	Tool           string              `json:"tool"`
	ToolVersion    string              `json:"tool_version"`
	IdentitySource string              `json:"identity_source"`
	JDKVersion     string              `json:"jdk_version"`
	JDKVendor      string              `json:"jdk_vendor"`
	JavacOptions   []string            `json:"javac_options"`
	Compilation    OracleCompilation   `json:"compilation"`
	Totals         OracleTotals        `json:"totals"`
	Files          []OracleFile        `json:"files"`
	Declarations   []OracleDeclaration `json:"declarations"`
}

// OracleCompilation records that the analysis was a clean, fully-resolved compiler run.
type OracleCompilation struct {
	DiagnosticErrorCount  int `json:"diagnostic_error_count"`
	AnalyzedTopLevelTypes int `json:"analyzed_top_level_types"`
	CompilationUnitCount  int `json:"compilation_unit_count"`
}

// OracleTotals are the tool's own derived counts.
type OracleTotals struct {
	Files                     int `json:"files"`
	PhysicalLines             int `json:"physical_lines"`
	StudySurfaceFiles         int `json:"study_surface_files"`
	StudySurfacePhysicalLines int `json:"study_surface_physical_lines"`
	Declarations              int `json:"declarations"`
}

// OracleFile is one analyzed source file.
type OracleFile struct {
	Path           string `json:"path"`
	Package        string `json:"package"`
	PhysicalLines  int    `json:"physical_lines"`
	SHA256         string `json:"sha256"`
	InStudySurface bool   `json:"in_study_surface"`
}

// OracleDeclaration is one compiler-derived declaration identity.
type OracleDeclaration struct {
	SemanticKey      string   `json:"semantic_key"`
	Kind             string   `json:"kind"`
	OwnerBinaryName  string   `json:"owner_binary_name"`
	Name             string   `json:"name"`
	Descriptor       string   `json:"descriptor"`
	GenericSignature string   `json:"generic_signature"`
	Modifiers        []string `json:"modifiers"`
	File             string   `json:"file"`
	Line             int      `json:"line"`
	InStudySurface   bool     `json:"in_study_surface"`
}

// IsType reports whether the declaration is a type rather than a member.
func (declaration OracleDeclaration) IsType() bool {
	switch declaration.Kind {
	case "CLASS", "INTERFACE", "ENUM", "ANNOTATION_TYPE", "RECORD":
		return true
	}
	return false
}

// LoadOracle reads the oracle output and returns it with the digest of the exact bytes read.
func LoadOracle(path string) (OracleOutput, string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return OracleOutput{}, "", err
	}
	var output OracleOutput
	if err := json.Unmarshal(content, &output); err != nil {
		return OracleOutput{}, "", err
	}
	if output.Compilation.DiagnosticErrorCount != 0 {
		return OracleOutput{}, "", fmt.Errorf(
			"oracle run had %d compiler errors; semantic identity requires a clean run",
			output.Compilation.DiagnosticErrorCount)
	}
	digest := sha256.Sum256(content)
	return output, "sha256:" + hex.EncodeToString(digest[:]), nil
}

// FileDigest returns the sha256 of a file's exact bytes.
func FileDigest(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
