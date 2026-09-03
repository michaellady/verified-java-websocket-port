package rustgate

import (
	"os"
	"path/filepath"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// verifyAdapterArchitecture ran only under `item.Name == "websocket-testee"`, so
// websocket-driver was never architecture-scanned. An adapter-side protocol parser
// planted in rust/websocket-driver/src/output.rs produced zero findings.
func TestProtocolDuplicationRulesCoverTheDriverCrate(t *testing.T) {
	root := repositoryRoot(t)

	// The driver crate is clean today; the gate must say so rather than skip it.
	clean := &verifier{root: root}
	clean.verifyProtocolDuplication("rust/websocket-driver")
	for _, finding := range clean.findings {
		if finding.Code == "ADAPTER_PROTOCOL_BRANCH" {
			t.Errorf("unexpected baseline finding in the driver crate: %+v", finding)
		}
	}
	if len(clean.findings) != 0 {
		t.Errorf("driver crate scan produced unexpected findings: %+v", clean.findings)
	}

	// The scan must actually reach the driver's sources.
	if _, err := os.Stat(filepath.Join(root, "rust/websocket-driver/src/output.rs")); err != nil {
		t.Fatalf("driver source expected at rust/websocket-driver/src/output.rs: %v", err)
	}
}

// The planted-parser shape the gate previously missed.
func TestProtocolDuplicationDetectsAdapterSideParsing(t *testing.T) {
	for _, testCase := range []struct {
		name string
		body string
	}{
		{
			name: "opcode nibble branch",
			body: `pub fn next(&self) -> Option<&[u8]> {
    let opcode = usize::from(bytes[0] & 0x0f);
    Some(&self.buffer[opcode..])
}`,
		},
		{
			name: "opcode nibble branch decimal",
			body: `fn pick(bytes: &[u8]) -> usize {
    let opcode = bytes[0] & 15;
    usize::from(opcode)
}`,
		},
		{
			// The exact planted canary that produced zero findings: it evades an
			// exact-match on "opcode" by naming the value opcode_nibble, and evades
			// a literal bytes[0]&0x0f match by masking a different expression.
			name: "renamed opcode nibble on a non-literal operand",
			body: `pub fn next(&self) -> Option<DriverOutput<'_>> {
    if let Some(write) = self.offered.as_ref() {
        let slice = write.as_slice();
        let opcode_nibble = usize::from(slice.first().copied().unwrap_or(0) & 0x0f);
        let start = self.cursor.saturating_add(opcode_nibble).min(slice.len());
        return Some(DriverOutput::Write(&slice[start..]));
    }
    None
}`,
		},
		{
			name: "handshake wire literal",
			body: `const REQUEST: &str = "GET / HTTP/1.1\r\n";`,
		},
		{
			name: "handshake header literal",
			body: `const ACCEPT: &str = "Sec-WebSocket-Accept";`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			v := &verifier{root: "/"}
			v.scanProtocolDuplication("rust/websocket-driver/src/output.rs", []byte(testCase.body))
			found := false
			for _, finding := range v.findings {
				if finding.Code == "ADAPTER_PROTOCOL_BRANCH" {
					found = true
				}
			}
			if !found {
				t.Errorf("protocol duplication went undetected: %+v", v.findings)
			}
		})
	}
}

// Byte transport must stay clean: the rules are behavioural, not name based, so a
// driver that merely forwards bytes is not flagged.
func TestProtocolDuplicationAllowsPlainByteTransport(t *testing.T) {
	body := `pub fn next(&self) -> Option<DriverOutput<'_>> {
    if let Some(write) = self.offered.as_ref() {
        return Some(DriverOutput::Write(&write.as_slice()[self.cursor..]));
    }
    None
}`
	v := &verifier{root: "/"}
	v.scanProtocolDuplication("rust/websocket-driver/src/output.rs", []byte(body))
	if len(v.findings) != 0 {
		t.Errorf("plain byte transport must not be flagged: %+v", v.findings)
	}
}

// The driver legitimately names core types and its own command enum, so the
// testee's name-based forbidden lists must not be applied to it.
func TestDriverCrateIsNotSubjectToTheTesteeSymbolList(t *testing.T) {
	body := `let result = self.core.step(CoreInput::Command(command.clone()));`
	v := &verifier{root: "/"}
	v.scanProtocolDuplication("rust/websocket-driver/src/lib.rs", []byte(body))
	if len(v.findings) != 0 {
		t.Errorf("the driver's legitimate core and command surface must not be flagged: %+v", v.findings)
	}
}
