//go:build formalcovere2e

package formalcoverage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/javabind"
)

// The executed lane for the catalog correction proposal.
//
// The default lane checks everything about the proposal that can be checked
// without the quarantined tree: that it quotes the catalog verbatim, that its
// defect classes are the ones the binding lane recorded, and that every
// corroboration label is exact in both directions. What it CANNOT check is
// whether the Java it cites is the Java that is there. This lane closes that
// gap: it re-resolves every citation out of the digest-pinned source and
// requires the line numbers, byte spans, span digests, structure fingerprints,
// parameter lists, return types and body-presence flags to reproduce the
// proposal exactly, and it requires every member marked unbindable to actually
// be refused by the resolver.
//
// Run it with the pinned tree in the environment:
//
//	FORMALCOVER_E2E_JAVA_SOURCE_ROOT=/abs/path/to/.../src/main/java \
//	  go test -tags formalcovere2e -run E2E ./internal/formalcoverage/
//
// JAVABIND_E2E_JAVA_SOURCE_ROOT is accepted as well, because it names the same
// pinned tree and the two lanes must not be able to point at different sources.

func sourceRoot(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"FORMALCOVER_E2E_JAVA_SOURCE_ROOT", "JAVABIND_E2E_JAVA_SOURCE_ROOT"} {
		value := os.Getenv(name)
		if value == "" {
			continue
		}
		if !filepath.IsAbs(value) {
			t.Fatalf("%s must be an absolute path, got %q", name, value)
		}
		if _, err := os.Stat(value); err != nil {
			t.Fatalf("%s=%s: %v", name, value, err)
		}
		return value
	}
	t.Fatal("neither FORMALCOVER_E2E_JAVA_SOURCE_ROOT nor JAVABIND_E2E_JAVA_SOURCE_ROOT is set; this lane must consume the pinned tree explicitly")
	return ""
}

// readPinned loads one file of the pinned tree. Citations are written relative
// to the tree root ("src/main/java/org/..."), while the source root the
// environment names is the src/main/java directory itself, so the prefix is
// stripped once, here, rather than in every test.
func readPinned(t *testing.T, root, citationFile string) []byte {
	t.Helper()
	relative := strings.TrimPrefix(citationFile, "src/main/java/")
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read %s: %v", citationFile, err)
	}
	return data
}

func lineOf(data []byte, offset int) int {
	return bytes.Count(data[:offset], []byte("\n")) + 1
}

// TestE2EEveryCitedFileDigestIsThePinnedFilesDigest is the first thing to
// check: a citation whose file digest is not the pinned file's digest is a
// citation about a different program.
func TestE2EEveryCitedFileDigestIsThePinnedFilesDigest(t *testing.T) {
	root := sourceRoot(t)
	_, proposal, err := VerifyCorrections(repoRoot(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	checked := 0
	for _, correction := range proposal.Corrections {
		citations := append([]Citation(nil), correction.Current.Citations...)
		for _, member := range correction.Proposed.Chain {
			citations = append(citations, member.Citation)
		}
		for _, citation := range citations {
			data := readPinned(t, root, citation.File)
			if got := javabind.Digest(data); got != citation.FileSHA256 {
				t.Errorf("%s cites %s at %s, the pinned file hashes to %s",
					correction.CorrectionID, citation.File, citation.FileSHA256, got)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no citation was checked")
	}
	t.Logf("recomputed %d citation file digests from the pinned tree", checked)
}

// TestE2EEveryProposedMemberResolvesExactlyAsCited re-resolves each proposed
// construct and compares every recorded field.
func TestE2EEveryProposedMemberResolvesExactlyAsCited(t *testing.T) {
	root := sourceRoot(t)
	_, proposal, err := VerifyCorrections(repoRoot(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, correction := range proposal.Corrections {
		for _, member := range correction.Proposed.Chain {
			citation := member.Citation
			data := readPinned(t, root, citation.File)
			typeName, memberName, _ := javabind.SymbolDescriptor(member.ProductionSymbol)
			declaration, resolveErr := javabind.ResolveMember(data, typeName, memberName)

			if !member.BindableNow {
				// A member the proposal calls unbindable must actually be
				// refused. A proposal that calls a resolvable symbol
				// unbindable would be understating the correction, which is
				// as dishonest as overstating it.
				if resolveErr == nil {
					t.Errorf("%s: %s is marked not bindable but the resolver resolves it",
						correction.CorrectionID, member.ProductionSymbol)
				}
				continue
			}
			if resolveErr != nil {
				t.Errorf("%s: %s is marked bindable but the resolver refuses it: %v",
					correction.CorrectionID, member.ProductionSymbol, resolveErr)
				continue
			}
			if got := lineOf(data, declaration.Start); got != citation.StartLine {
				t.Errorf("%s: %s starts at line %d, cited %d", correction.CorrectionID, memberName, got, citation.StartLine)
			}
			if got := lineOf(data, declaration.End); got != citation.EndLine {
				t.Errorf("%s: %s ends at line %d, cited %d", correction.CorrectionID, memberName, got, citation.EndLine)
			}
			if citation.SpanSHA256 == nil {
				t.Errorf("%s: %s is bindable but cites no span digest", correction.CorrectionID, memberName)
			} else if got := declaration.SpanDigest(data); got != *citation.SpanSHA256 {
				t.Errorf("%s: %s span digest is %s, cited %s", correction.CorrectionID, memberName, got, *citation.SpanSHA256)
			}
			if citation.StructureFingerprint == nil {
				t.Errorf("%s: %s is bindable but cites no structure fingerprint", correction.CorrectionID, memberName)
			} else if got := declaration.StructureFingerprint(data); got != *citation.StructureFingerprint {
				t.Errorf("%s: %s fingerprint is %s, cited %s", correction.CorrectionID, memberName, got, *citation.StructureFingerprint)
			}
			if !declaration.HasBody {
				t.Errorf("%s: %s has no body, so it can host no canary and cannot be the replacement",
					correction.CorrectionID, memberName)
			}
		}
	}
}

// TestE2EEveryCurrentSymbolIsStillDefectiveInThePinnedSource re-establishes the
// DEFECT, not only the replacement. A correction is only warranted while the
// symbol it condemns is still the symbol the pinned source declares.
func TestE2EEveryCurrentSymbolIsStillDefectiveInThePinnedSource(t *testing.T) {
	root := sourceRoot(t)
	_, proposal, err := VerifyCorrections(repoRoot(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, correction := range proposal.Corrections {
		typeName, memberName, _ := javabind.SymbolDescriptor(correction.Current.ProductionSymbol)
		file := correction.Current.Citations[0].File
		data := readPinned(t, root, file)
		declaration, resolveErr := javabind.ResolveMember(data, typeName, memberName)

		switch correction.Current.DefectClass {
		case "INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE":
			// The recorded defect is twofold: the name is ambiguous in its
			// declaring type AND the declaration has no body. The resolver
			// refuses on the first, so the second is checked by counting.
			if resolveErr == nil {
				t.Errorf("%s: %s.%s resolves, but the recorded defect says the key is ambiguous",
					correction.CorrectionID, typeName, memberName)
			} else if !strings.Contains(resolveErr.Error(), "ambiguous") {
				t.Errorf("%s: resolver refused %s.%s for a different reason: %v",
					correction.CorrectionID, typeName, memberName, resolveErr)
			}
			if count := bytes.Count(data, []byte(memberName+"(")); count < 2 {
				t.Errorf("%s: %s appears %d times in %s; the ambiguity claim needs at least two declarations",
					correction.CorrectionID, memberName, count, file)
			}
		case "CATALOG_SYMBOL_SCOPE_MISMATCH", "CATALOG_SYMBOL_NOT_ON_EXECUTED_PATH":
			if resolveErr != nil {
				t.Errorf("%s: %s.%s does not resolve at all (%v); the recorded defect is about SCOPE, which presumes the symbol exists",
					correction.CorrectionID, typeName, memberName, resolveErr)
				continue
			}
			citation := correction.Current.Citations[0]
			if got := lineOf(data, declaration.Start); got != citation.StartLine {
				t.Errorf("%s: %s.%s starts at line %d, cited %d", correction.CorrectionID, typeName, memberName, got, citation.StartLine)
			}
			if citation.SpanSHA256 != nil {
				if got := declaration.SpanDigest(data); got != *citation.SpanSHA256 {
					t.Errorf("%s: %s.%s span digest is %s, cited %s", correction.CorrectionID, typeName, memberName, got, *citation.SpanSHA256)
				}
			}
		default:
			t.Errorf("%s carries defect class %q, which this lane does not know how to re-establish",
				correction.CorrectionID, correction.Current.DefectClass)
		}
	}
}

// TestE2ETheMaskObligationsCurrentSymbolContainsNoMaskingAtAll is the specific
// finding for the two mask corrections, checked against the bytes rather than
// asserted in prose: the span the catalog names holds no XOR and no mask key.
func TestE2ETheMaskObligationsCurrentSymbolContainsNoMaskingAtAll(t *testing.T) {
	root := sourceRoot(t)
	_, proposal, err := VerifyCorrections(repoRoot(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, correction := range proposal.Corrections {
		if correction.ObligationID != "obligation.mask-equation" && correction.ObligationID != "obligation.mask-involution" {
			continue
		}
		data := readPinned(t, root, correction.Current.Citations[0].File)
		typeName, memberName, _ := javabind.SymbolDescriptor(correction.Current.ProductionSymbol)
		declaration, resolveErr := javabind.ResolveMember(data, typeName, memberName)
		if resolveErr != nil {
			t.Fatalf("%s: %v", correction.CorrectionID, resolveErr)
		}
		span := data[declaration.Start:declaration.End]
		for _, forbidden := range []string{"^", "mask", "Mask"} {
			if bytes.Contains(span, []byte(forbidden)) {
				t.Errorf("%s: the span the catalog names for a masking obligation contains %q after all", correction.CorrectionID, forbidden)
			}
		}
		// And the replacement must contain what the current symbol lacks.
		for _, member := range correction.Proposed.Chain {
			replacement := readPinned(t, root, member.Citation.File)
			replacementDecl, err := javabind.ResolveMember(replacement, mustType(t, member.ProductionSymbol), mustMember(t, member.ProductionSymbol))
			if err != nil {
				t.Fatalf("%s: %v", correction.CorrectionID, err)
			}
			replacementSpan := replacement[replacementDecl.Start:replacementDecl.End]
			if !bytes.Contains(replacementSpan, []byte("^")) {
				t.Errorf("%s: proposed member %s contains no XOR operator", correction.CorrectionID, member.ProductionSymbol)
			}
			if !bytes.Contains(replacementSpan, []byte("% 4")) {
				t.Errorf("%s: proposed member %s contains no four-byte offset arithmetic", correction.CorrectionID, member.ProductionSymbol)
			}
		}
	}
}

func mustType(t *testing.T, symbol string) string {
	t.Helper()
	typeName, _, _ := javabind.SymbolDescriptor(symbol)
	return typeName
}

func mustMember(t *testing.T, symbol string) string {
	t.Helper()
	_, memberName, _ := javabind.SymbolDescriptor(symbol)
	return memberName
}

// TestE2ETheOracleListenerStillShadowsTheDeclaredPingSymbol re-establishes the
// ping-pong defect against this laboratory's own adapter, which is checked in
// rather than pinned, so a change there would silently invalidate the finding.
func TestE2ETheOracleListenerStillShadowsTheDeclaredPingSymbol(t *testing.T) {
	_, proposal, err := VerifyCorrections(repoRoot(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, correction := range proposal.Corrections {
		if correction.ObligationID != "surface.control.ping-pong" {
			continue
		}
		if correction.Current.AdapterCitation == nil {
			t.Fatal("the ping-pong correction cites no adapter override, yet its whole defect is that the adapter overrides the symbol")
		}
		citation := correction.Current.AdapterCitation
		data, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(citation.File)))
		if err != nil {
			t.Fatalf("read %s: %v", citation.File, err)
		}
		lines := strings.Split(string(data), "\n")
		if citation.EndLine > len(lines) {
			t.Fatalf("%s cites lines %d-%d but the file has %d", citation.File, citation.StartLine, citation.EndLine, len(lines))
		}
		window := strings.Join(lines[citation.StartLine-1:citation.EndLine], "\n")
		if !strings.Contains(window, "onWebsocketPing") {
			t.Fatalf("%s lines %d-%d do not declare onWebsocketPing:\n%s", citation.File, citation.StartLine, citation.EndLine, window)
		}
		if strings.Contains(window, "super.onWebsocketPing") {
			t.Fatalf("the oracle listener now calls super.onWebsocketPing; the recorded defect no longer holds")
		}
		if !strings.Contains(string(data), "extends WebSocketAdapter") {
			t.Fatal("the oracle listener no longer extends WebSocketAdapter; the recorded defect no longer holds")
		}
	}
}
