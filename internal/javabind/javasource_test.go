package javabind

import "testing"

// The resolver is exercised against synthetic Java held in this test, not
// against the quarantined upstream tree, so these cases run everywhere and no
// upstream source enters the repository.
const sampleJava = `package example;

/** A class with a name that also appears in a comment: isValid. */
public final class Sample {

  private static final String NOISE = "class Decoy { void isValid() {} }";

  @Override
  public void isValid() throws Bad {
    if (!isFin()) {
      throw new Bad("not final"); // isValid() again, in a comment
    }
  }

  private int sizeOf(java.nio.ByteBuffer mes) {
    if (mes.remaining() <= 125) {
      return 1;
    }
    return 2;
  }

  public java.util.List<Thing> translate(java.nio.ByteBuffer buffer, boolean strict) {
    return null;
  }
}
`

const sampleInterface = `package example;

public interface Listener {
  void onOne(Socket socket, String text);

  void onOne(Socket socket, java.nio.ByteBuffer data);

  void onTwo(Socket socket);
}
`

func TestResolveMemberFindsTheDeclarationAndItsBounds(t *testing.T) {
	decl, err := ResolveMember([]byte(sampleJava), "Sample", "isValid")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	span := sampleJava[decl.Start:decl.End]
	if got := span[:9]; got != "@Override" {
		t.Fatalf("span starts at %q, expected the annotation", got)
	}
	if span[len(span)-1] != '}' {
		t.Fatalf("span ends at %q, expected the closing brace", span[len(span)-1:])
	}
	if !decl.HasBody || decl.ReturnType != "void" || len(decl.ParameterTypes) != 0 {
		t.Fatalf("unexpected declaration shape: %+v", decl)
	}
	// The comment and the string literal both contain "isValid" and "class"; the
	// resolver must not be fooled by either.
	if got := decl.MemberName; got != "isValid" {
		t.Fatalf("member name %q", got)
	}
}

func TestResolveMemberErasesGenericsAndQualifiers(t *testing.T) {
	decl, err := ResolveMember([]byte(sampleJava), "Sample", "translate")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if decl.ReturnType != "List" {
		t.Fatalf("return type %q, want List", decl.ReturnType)
	}
	if len(decl.ParameterTypes) != 2 || decl.ParameterTypes[0] != "ByteBuffer" || decl.ParameterTypes[1] != "boolean" {
		t.Fatalf("parameter types %v", decl.ParameterTypes)
	}
}

func TestResolveMemberRefusesAnAmbiguousName(t *testing.T) {
	if _, err := ResolveMember([]byte(sampleInterface), "Listener", "onOne"); err == nil {
		t.Fatal("an overload set must be refused: declaringType#name does not identify one construct")
	}
}

func TestResolveMemberReportsABodylessDeclaration(t *testing.T) {
	decl, err := ResolveMember([]byte(sampleInterface), "Listener", "onTwo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if decl.HasBody {
		t.Fatal("an interface method has no body and can host no canary")
	}
	if sampleInterface[decl.End-1] != ';' {
		t.Fatalf("a body-less declaration must end at its semicolon, got %q", sampleInterface[decl.End-1:decl.End])
	}
}

func TestSpanDigestAndFingerprintDiscriminate(t *testing.T) {
	decl, err := ResolveMember([]byte(sampleJava), "Sample", "sizeOf")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	original := decl.SpanDigest([]byte(sampleJava))
	fingerprint := decl.StructureFingerprint([]byte(sampleJava))

	// Deleting the thing the binding describes must change both digests.
	edited := replaceOnce(t, sampleJava, "mes.remaining() <= 125", "false")
	editedDecl, err := ResolveMember([]byte(edited), "Sample", "sizeOf")
	if err != nil {
		t.Fatalf("resolve edited: %v", err)
	}
	if editedDecl.SpanDigest([]byte(edited)) == original {
		t.Fatal("the span digest did not notice an edit inside the span")
	}
	if editedDecl.StructureFingerprint([]byte(edited)) == fingerprint {
		t.Fatal("the structure fingerprint did not notice an edit inside the span")
	}

	// Reformatting alone must move the span digest but not the fingerprint: the
	// fingerprint is what distinguishes layout drift from semantic drift.
	reformatted := replaceOnce(t, sampleJava, "    if (mes.remaining() <= 125) {", "\tif (mes.remaining() <= 125) {")
	reformattedDecl, err := ResolveMember([]byte(reformatted), "Sample", "sizeOf")
	if err != nil {
		t.Fatalf("resolve reformatted: %v", err)
	}
	if reformattedDecl.SpanDigest([]byte(reformatted)) == original {
		t.Fatal("the span digest should be sensitive to layout")
	}
	if reformattedDecl.StructureFingerprint([]byte(reformatted)) != fingerprint {
		t.Fatal("the structure fingerprint should be insensitive to layout alone")
	}
}

func TestDescriptorAgreementReportsDivergenceRatherThanRepairingIt(t *testing.T) {
	decl, err := ResolveMember([]byte(sampleJava), "Sample", "translate")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	cases := map[string]string{
		"(Ljava/nio/ByteBuffer;Z)Ljava/util/List;":  "EXACT",
		"(Ljava/nio/ByteBuffer;Z)Ljava/lang/Thing;": "RETURN_DIVERGENT",
		"(Ljava/nio/ByteBuffer;)Ljava/util/List;":   "PARAMETERS_DIVERGENT",
		"(I)V": "BOTH_DIVERGENT",
	}
	for descriptor, want := range cases {
		if got := DescriptorAgreement(decl, descriptor); got != want {
			t.Fatalf("descriptor %q: agreement %q, want %q", descriptor, got, want)
		}
	}
}

func TestSymbolDescriptorSplitsCatalogSymbols(t *testing.T) {
	typeName, member, descriptor := SymbolDescriptor("org.java_websocket.drafts.Draft_6455.translateSingleFrame(Ljava/nio/ByteBuffer;)Ljava/util/List;")
	if typeName != "Draft_6455" || member != "translateSingleFrame" || descriptor != "(Ljava/nio/ByteBuffer;)Ljava/util/List;" {
		t.Fatalf("got %q %q %q", typeName, member, descriptor)
	}
	typeName, member, descriptor = SymbolDescriptor("org.java_websocket.server.WebSocketServer")
	if typeName != "WebSocketServer" || member != "" || descriptor != "" {
		t.Fatalf("bare type: got %q %q %q", typeName, member, descriptor)
	}
}

func replaceOnce(t *testing.T, text, from, to string) string {
	t.Helper()
	index := indexOf(text, from)
	if index < 0 {
		t.Fatalf("fixture does not contain %q", from)
	}
	if indexOf(text[index+len(from):], from) >= 0 {
		t.Fatalf("fixture contains %q more than once", from)
	}
	return text[:index] + to + text[index+len(from):]
}

func indexOf(text, needle string) int {
	for i := 0; i+len(needle) <= len(text); i++ {
		if text[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
