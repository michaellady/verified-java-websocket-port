package main

// mask.go — reduce Rust source to a form safe for structural scanning.
//
// Every byte of a comment, string literal, raw string literal, byte string or
// character literal is replaced by a space, and every newline is preserved, so
// byte offsets and line numbers in the masked text are the SAME as in the
// original. Structural scanning (brace matching, loop header extraction,
// comparison matching) runs on the masked text; reporting and waiver lookup
// run on the original.
//
// This exists because the class this tool hunts is written in code, and a
// `//` comment quoting `polls < POLL_BUDGET` — there is one, in the very file
// that was fixed — must not be mistaken for the guard itself.

// maskSource returns masked source of exactly len(src) bytes.
func maskSource(src string) string {
	out := []byte(src)
	blank := func(i int) {
		if out[i] != '\n' {
			out[i] = ' '
		}
	}
	n := len(src)
	i := 0
	for i < n {
		c := src[i]
		switch {
		case c == '/' && i+1 < n && src[i+1] == '/':
			for i < n && src[i] != '\n' {
				blank(i)
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			depth := 0
			for i < n {
				if src[i] == '/' && i+1 < n && src[i+1] == '*' {
					depth++
					blank(i)
					blank(i + 1)
					i += 2
					continue
				}
				if src[i] == '*' && i+1 < n && src[i+1] == '/' {
					depth--
					blank(i)
					blank(i + 1)
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				blank(i)
				i++
			}
		case c == 'r' && isRawStringStart(src, i):
			i = maskRawString(src, out, i, blank)
		case c == 'b' && i+1 < n && src[i+1] == 'r' && isRawStringStart(src, i+1):
			blank(i)
			i = maskRawString(src, out, i+1, blank)
		case c == '"':
			blank(i)
			i++
			for i < n {
				if src[i] == '\\' && i+1 < n {
					blank(i)
					blank(i + 1)
					i += 2
					continue
				}
				if src[i] == '"' {
					blank(i)
					i++
					break
				}
				blank(i)
				i++
			}
		case c == '\'':
			// A char literal, or a lifetime / loop label. Masking is only
			// needed for a char literal, which can contain a brace or quote.
			if end, ok := charLiteralEnd(src, i); ok {
				for j := i; j < end; j++ {
					blank(j)
				}
				i = end
				continue
			}
			i++
		default:
			i++
		}
	}
	return string(out)
}

func isRawStringStart(src string, i int) bool {
	// r"..." or r#"..."# or r##"..."## ...
	j := i + 1
	for j < len(src) && src[j] == '#' {
		j++
	}
	return j < len(src) && src[j] == '"'
}

func maskRawString(src string, out []byte, i int, blank func(int)) int {
	n := len(src)
	j := i + 1
	hashes := 0
	for j < n && src[j] == '#' {
		hashes++
		j++
	}
	// src[j] is the opening quote.
	for k := i; k <= j; k++ {
		blank(k)
	}
	j++
	for j < n {
		if src[j] == '"' {
			ok := true
			for h := 1; h <= hashes; h++ {
				if j+h >= n || src[j+h] != '#' {
					ok = false
					break
				}
			}
			if ok {
				for k := j; k <= j+hashes; k++ {
					blank(k)
				}
				return j + hashes + 1
			}
		}
		blank(j)
		j++
	}
	return n
}

// charLiteralEnd reports the byte just past a char literal starting at i, and
// whether src[i:] actually is one. `'a'`, `'\n'`, `'\”`, `'{'` are literals;
// `'static`, `'a,` and a loop label `'outer:` are not.
func charLiteralEnd(src string, i int) (int, bool) {
	n := len(src)
	j := i + 1
	if j >= n {
		return 0, false
	}
	if src[j] == '\\' {
		j += 2
		for j < n && src[j] != '\'' && src[j] != '\n' {
			j++
		}
		if j < n && src[j] == '\'' {
			return j + 1, true
		}
		return 0, false
	}
	// Consume one UTF-8 rune.
	j++
	for j < n && src[j]&0xC0 == 0x80 {
		j++
	}
	if j < n && src[j] == '\'' {
		return j + 1, true
	}
	return 0, false
}
