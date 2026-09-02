// Package javabind binds immutable-catalog semantic obligations to identified
// constructs of the pinned Java-WebSocket 1.6.0 source, to executed observations
// of the pinned runtime, and to exact source mutations that flip those
// observations.
//
// Nothing in this package proves anything about the Java library. See
// docs/java-formal-binding-design.md, section 7, for the claim ceiling.
package javabind

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Digest returns the project-canonical "sha256:<hex>" spelling.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Declaration is one resolved Java construct inside one pinned source file.
type Declaration struct {
	// TypeName is the simple name of the declaring type, e.g. "Draft_6455".
	TypeName string
	// MemberName is the resolved member's simple name, or the type name when the
	// construct is the type declaration itself.
	MemberName string
	// Kind is "TYPE" or "METHOD".
	Kind string
	// Start and End delimit the declaration in the file, as byte offsets. End is
	// exclusive and points one byte past the closing brace (or the terminating
	// semicolon for a body-less declaration).
	Start int
	End   int
	// ParameterTypes holds the erased, generic-stripped simple type names of the
	// declared parameters, in declaration order. Nil for a type declaration.
	ParameterTypes []string
	// ReturnType is the erased, generic-stripped simple return type name, "void"
	// for a void method, and "" for a type declaration or a constructor.
	ReturnType string
	// HasBody is false for interface and abstract declarations, which can host no
	// mutation canary.
	HasBody bool
}

// SpanDigest is the digest of exactly the declaration's bytes.
func (d Declaration) SpanDigest(file []byte) string { return Digest(file[d.Start:d.End]) }

// StructureFingerprint is a formatting-insensitive digest over the declaration:
// the sorted multiset of its identifiers, keywords and numeric literals, with
// comments, string and character literals, and all whitespace removed. Two
// declarations with the same fingerprint differ at most in layout and comments.
func (d Declaration) StructureFingerprint(file []byte) string {
	tokens := codeTokens(file[d.Start:d.End])
	counts := map[string]int{}
	for _, token := range tokens {
		counts[token]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&builder, "%s\x1f%d\x1e", key, counts[key])
	}
	return Digest([]byte(builder.String()))
}

// stripped returns the file with comments, string literals and character
// literals replaced by spaces of equal length, so byte offsets are preserved.
// Brace and parenthesis scanning runs over this view, never over raw source.
func stripped(source []byte) []byte {
	out := make([]byte, len(source))
	copy(out, source)
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	for i := 0; i < len(source); {
		switch {
		case source[i] == '/' && i+1 < len(source) && source[i+1] == '/':
			end := i
			for end < len(source) && source[end] != '\n' {
				end++
			}
			blank(i, end)
			i = end
		case source[i] == '/' && i+1 < len(source) && source[i+1] == '*':
			end := i + 2
			for end+1 < len(source) && !(source[end] == '*' && source[end+1] == '/') {
				end++
			}
			end = min(end+2, len(source))
			blank(i, end)
			i = end
		case source[i] == '"' || source[i] == '\'':
			quote := source[i]
			end := i + 1
			for end < len(source) {
				if source[end] == '\\' {
					end += 2
					continue
				}
				if source[end] == quote {
					end++
					break
				}
				end++
			}
			blank(i, min(end, len(source)))
			i = min(end, len(source))
		default:
			i++
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// codeTokens splits stripped code into identifier, numeric and punctuation
// tokens. Whitespace is dropped.
func codeTokens(source []byte) []string {
	view := stripped(source)
	tokens := []string{}
	for i := 0; i < len(view); {
		switch {
		case unicode.IsSpace(rune(view[i])):
			i++
		case isIdentByte(view[i]):
			start := i
			for i < len(view) && isIdentByte(view[i]) {
				i++
			}
			tokens = append(tokens, string(view[start:i]))
		default:
			tokens = append(tokens, string(view[i]))
			i++
		}
	}
	return tokens
}

// ResolveType finds the declaration of the named top-level or nested type.
func ResolveType(file []byte, typeName string) (Declaration, error) {
	view := stripped(file)
	start, err := typeHeaderStart(view, typeName)
	if err != nil {
		return Declaration{}, err
	}
	open := indexFrom(view, start, '{')
	if open < 0 {
		return Declaration{}, fmt.Errorf("javabind: type %q has no body", typeName)
	}
	end, err := matchBrace(view, open)
	if err != nil {
		return Declaration{}, err
	}
	return Declaration{
		TypeName:   typeName,
		MemberName: typeName,
		Kind:       "TYPE",
		Start:      declarationStart(view, start),
		End:        end + 1,
		HasBody:    true,
	}, nil
}

func typeHeaderStart(view []byte, typeName string) (int, error) {
	found := -1
	for _, keyword := range []string{"class", "interface", "enum"} {
		for i := 0; i+len(keyword) < len(view); i++ {
			if !hasWordAt(view, i, keyword) {
				continue
			}
			j := i + len(keyword)
			for j < len(view) && (view[j] == ' ' || view[j] == '\t' || view[j] == '\n' || view[j] == '\r') {
				j++
			}
			if !hasWordAt(view, j, typeName) {
				continue
			}
			if found >= 0 {
				return 0, fmt.Errorf("javabind: type name %q is declared more than once", typeName)
			}
			found = i
		}
	}
	if found < 0 {
		return 0, fmt.Errorf("javabind: type %q is not declared in this file", typeName)
	}
	return found, nil
}

func hasWordAt(view []byte, index int, word string) bool {
	if index < 0 || index+len(word) > len(view) {
		return false
	}
	if string(view[index:index+len(word)]) != word {
		return false
	}
	if index > 0 && isIdentByte(view[index-1]) {
		return false
	}
	if index+len(word) < len(view) && isIdentByte(view[index+len(word)]) {
		return false
	}
	return true
}

func indexFrom(view []byte, from int, target byte) int {
	for i := from; i < len(view); i++ {
		if view[i] == target {
			return i
		}
	}
	return -1
}

func matchBrace(view []byte, open int) (int, error) {
	depth := 0
	for i := open; i < len(view); i++ {
		switch view[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("javabind: unbalanced braces from offset %d", open)
}

// declarationStart walks back from a header keyword to the first byte of the
// declaration: past modifiers, annotations and the preceding blank line, but not
// past the previous statement, member or block boundary.
func declarationStart(view []byte, header int) int {
	i := header
	for i > 0 {
		j := i - 1
		for j >= 0 && (view[j] == ' ' || view[j] == '\t') {
			j--
		}
		if j < 0 {
			return 0
		}
		if view[j] == ';' || view[j] == '{' || view[j] == '}' {
			// Stop at the previous member boundary; keep the newline out.
			for k := j + 1; k < header; k++ {
				if view[k] != ' ' && view[k] != '\t' && view[k] != '\n' && view[k] != '\r' {
					return k
				}
			}
			return header
		}
		if view[j] == '\n' {
			// A blank-or-annotation line above: keep walking only while the line
			// above is an annotation or modifier continuation.
			lineStart := j
			for lineStart > 0 && view[lineStart-1] != '\n' {
				lineStart--
			}
			trimmed := strings.TrimSpace(string(view[lineStart:j]))
			if strings.HasPrefix(trimmed, "@") {
				i = lineStart
				continue
			}
			for k := j + 1; k < header; k++ {
				if view[k] != ' ' && view[k] != '\t' {
					return k
				}
			}
			return header
		}
		// Modifier or return type on the same line: walk to the line start.
		i = j
	}
	return 0
}

// ResolveMember finds the unique member of typeName named memberName. It is an
// error for the type to declare no such member, or more than one: the binding
// key is declaringType#simpleName and an overload set makes that key ambiguous.
func ResolveMember(file []byte, typeName, memberName string) (Declaration, error) {
	typeDecl, err := ResolveType(file, typeName)
	if err != nil {
		return Declaration{}, err
	}
	view := stripped(file)
	body := view[typeDecl.Start:typeDecl.End]
	offset := typeDecl.Start

	matches := []Declaration{}
	for i := 0; i < len(body); i++ {
		if !hasWordAt(body, i, memberName) {
			continue
		}
		paren := i + len(memberName)
		for paren < len(body) && (body[paren] == ' ' || body[paren] == '\t' || body[paren] == '\n' || body[paren] == '\r') {
			paren++
		}
		if paren >= len(body) || body[paren] != '(' {
			continue
		}
		if !atNestingDepthOne(body, i) {
			continue
		}
		closeParen, err := matchParen(body, paren)
		if err != nil {
			continue
		}
		params := parseParameters(string(file[offset+paren+1 : offset+closeParen]))
		start := declarationStart(body, i)
		returnType, ok := parseReturnType(string(body[start:i]))
		if !ok {
			continue
		}
		tail := closeParen + 1
		for tail < len(body) && body[tail] != '{' && body[tail] != ';' {
			tail++
		}
		if tail >= len(body) {
			continue
		}
		decl := Declaration{
			TypeName:       typeName,
			MemberName:     memberName,
			Kind:           "METHOD",
			Start:          offset + start,
			ParameterTypes: params,
			ReturnType:     returnType,
		}
		if body[tail] == ';' {
			decl.End = offset + tail + 1
			decl.HasBody = false
		} else {
			end, err := matchBrace(body, tail)
			if err != nil {
				continue
			}
			decl.End = offset + end + 1
			decl.HasBody = true
		}
		matches = append(matches, decl)
	}
	if len(matches) == 0 {
		return Declaration{}, fmt.Errorf("javabind: %s declares no member named %q", typeName, memberName)
	}
	if len(matches) > 1 {
		return Declaration{}, fmt.Errorf("javabind: %s declares %d members named %q; the binding key declaringType#name is ambiguous", typeName, len(matches), memberName)
	}
	return matches[0], nil
}

// atNestingDepthOne reports whether index sits directly in the type body rather
// than inside a nested block, initialiser or nested type.
func atNestingDepthOne(body []byte, index int) bool {
	depth := 0
	for i := 0; i < index; i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return depth == 1
}

func matchParen(view []byte, open int) (int, error) {
	depth := 0
	for i := open; i < len(view); i++ {
		switch view[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("javabind: unbalanced parentheses from offset %d", open)
}

// parseReturnType extracts the declared return type from the modifier run that
// precedes the member name. It reports false when the run does not look like a
// method declaration (for instance a call site, or a constructor).
func parseReturnType(prefix string) (string, bool) {
	fields := strings.Fields(strings.ReplaceAll(cleanGenerics(prefix), "\n", " "))
	modifiers := map[string]bool{
		"public": true, "protected": true, "private": true, "static": true,
		"final": true, "abstract": true, "synchronized": true, "native": true,
		"default": true, "strictfp": true, "transient": true, "volatile": true,
	}
	filtered := []string{}
	for _, field := range fields {
		if strings.HasPrefix(field, "@") || modifiers[field] {
			continue
		}
		filtered = append(filtered, field)
	}
	if len(filtered) != 1 {
		return "", false
	}
	return normalizeTypeName(filtered[0]), true
}

// cleanGenerics removes angle-bracket type arguments so that
// "List<Framedata>" reduces to "List".
func cleanGenerics(text string) string {
	var out strings.Builder
	depth := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
				continue
			}
			out.WriteByte(text[i])
		default:
			if depth == 0 {
				out.WriteByte(text[i])
			}
		}
	}
	return out.String()
}

func normalizeTypeName(name string) string {
	name = strings.TrimSpace(cleanGenerics(name))
	if index := strings.LastIndex(name, "."); index >= 0 {
		name = name[index+1:]
	}
	name = strings.ReplaceAll(name, " ", "")
	return name
}

// parseParameters reduces a declared parameter list to erased simple type names.
func parseParameters(list string) []string {
	list = strings.TrimSpace(cleanGenerics(list))
	if list == "" {
		return []string{}
	}
	parts := strings.Split(list, ",")
	types := make([]string, 0, len(parts))
	for _, part := range parts {
		fields := strings.Fields(strings.TrimSpace(part))
		cleaned := []string{}
		for _, field := range fields {
			if strings.HasPrefix(field, "@") || field == "final" {
				continue
			}
			cleaned = append(cleaned, field)
		}
		if len(cleaned) < 2 {
			return nil
		}
		name := normalizeTypeName(strings.Join(cleaned[:len(cleaned)-1], ""))
		// An array suffix may sit on either the type or the parameter name.
		if strings.HasSuffix(cleaned[len(cleaned)-1], "[]") {
			name += "[]"
		}
		types = append(types, name)
	}
	return types
}

// DescriptorAgreement compares the pinned source declaration against the JVM
// descriptor the immutable catalog declares. Divergence is reported, never
// repaired.
func DescriptorAgreement(decl Declaration, descriptor string) string {
	params, ret, ok := parseDescriptor(descriptor)
	if !ok {
		// A catalog entry with no descriptor names a type, not a method.
		if decl.Kind == "TYPE" {
			return "EXACT"
		}
		return "BOTH_DIVERGENT"
	}
	paramsAgree := len(params) == len(decl.ParameterTypes)
	if paramsAgree {
		for i := range params {
			if params[i] != decl.ParameterTypes[i] {
				paramsAgree = false
				break
			}
		}
	}
	returnAgrees := ret == decl.ReturnType
	switch {
	case paramsAgree && returnAgrees:
		return "EXACT"
	case paramsAgree:
		return "RETURN_DIVERGENT"
	case returnAgrees:
		return "PARAMETERS_DIVERGENT"
	default:
		return "BOTH_DIVERGENT"
	}
}

// parseDescriptor turns "(Ljava/nio/ByteBuffer;)Ljava/util/List;" into
// (["ByteBuffer"], "List", true).
func parseDescriptor(descriptor string) ([]string, string, bool) {
	open := strings.Index(descriptor, "(")
	closeIndex := strings.Index(descriptor, ")")
	if open < 0 || closeIndex < open {
		return nil, "", false
	}
	params, ok := parseDescriptorTypes(descriptor[open+1 : closeIndex])
	if !ok {
		return nil, "", false
	}
	ret, rest, ok := parseDescriptorType(descriptor[closeIndex+1:])
	if !ok || rest != "" {
		return nil, "", false
	}
	return params, ret, true
}

func parseDescriptorTypes(text string) ([]string, bool) {
	types := []string{}
	for text != "" {
		one, rest, ok := parseDescriptorType(text)
		if !ok {
			return nil, false
		}
		types = append(types, one)
		text = rest
	}
	return types, true
}

var descriptorPrimitives = map[byte]string{
	'B': "byte", 'C': "char", 'D': "double", 'F': "float",
	'I': "int", 'J': "long", 'S': "short", 'Z': "boolean", 'V': "void",
}

func parseDescriptorType(text string) (string, string, bool) {
	if text == "" {
		return "", "", false
	}
	if text[0] == '[' {
		inner, rest, ok := parseDescriptorType(text[1:])
		if !ok {
			return "", "", false
		}
		return inner + "[]", rest, true
	}
	if text[0] == 'L' {
		end := strings.Index(text, ";")
		if end < 0 {
			return "", "", false
		}
		binary := text[1:end]
		if index := strings.LastIndex(binary, "/"); index >= 0 {
			binary = binary[index+1:]
		}
		return binary, text[end+1:], true
	}
	if name, ok := descriptorPrimitives[text[0]]; ok {
		return name, text[1:], true
	}
	return "", "", false
}
