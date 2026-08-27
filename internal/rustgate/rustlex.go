package rustgate

import "unicode"

func rustCodeTokens(source []byte) []string {
	code := stripRustCommentsAndLiterals(source)
	var tokens []string
	for index := 0; index < len(code); {
		r := rune(code[index])
		if unicode.IsLetter(r) || r == '_' {
			end := index + 1
			for end < len(code) {
				next := rune(code[end])
				if !unicode.IsLetter(next) && !unicode.IsDigit(next) && next != '_' {
					break
				}
				end++
			}
			tokens = append(tokens, string(code[index:end]))
			index = end
			continue
		}
		if index+1 < len(code) && code[index] == ':' && code[index+1] == ':' {
			tokens = append(tokens, "::")
			index += 2
			continue
		}
		switch code[index] {
		case '!', '(', ')', '{', '}', ';':
			tokens = append(tokens, string(code[index]))
		}
		index++
	}
	return tokens
}

func stripRustCommentsAndLiterals(source []byte) []byte {
	result := append([]byte(nil), source...)
	for index := 0; index < len(source); {
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '/' {
			end := index + 2
			for end < len(source) && source[end] != '\n' {
				end++
			}
			blank(result, index, end)
			index = end
			continue
		}
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '*' {
			end, depth := index+2, 1
			for end < len(source) && depth > 0 {
				if end+1 < len(source) && source[end] == '/' && source[end+1] == '*' {
					depth++
					end += 2
				} else if end+1 < len(source) && source[end] == '*' && source[end+1] == '/' {
					depth--
					end += 2
				} else {
					end++
				}
			}
			blank(result, index, end)
			index = end
			continue
		}
		if end, ok := rustRawLiteralEnd(source, index); ok {
			blank(result, index, end)
			index = end
			continue
		}
		start := index
		if source[index] == 'b' && index+1 < len(source) && (source[index+1] == '"' || source[index+1] == '\'') {
			index++
		}
		if source[index] == '"' || (source[index] == '\'' && looksLikeCharLiteral(source, index)) {
			quote := source[index]
			end := index + 1
			for end < len(source) {
				if source[end] == '\\' {
					end += 2
					continue
				}
				end++
				if source[end-1] == quote {
					break
				}
			}
			blank(result, start, end)
			index = end
			continue
		}
		index = start + 1
	}
	return result
}

func rustRawLiteralEnd(source []byte, start int) (int, bool) {
	index := start
	if index < len(source) && (source[index] == 'b' || source[index] == 'c') {
		index++
	}
	if index >= len(source) || source[index] != 'r' {
		return 0, false
	}
	index++
	hashes := 0
	for index < len(source) && source[index] == '#' {
		hashes++
		index++
	}
	if index >= len(source) || source[index] != '"' {
		return 0, false
	}
	index++
	for index < len(source) {
		if source[index] != '"' {
			index++
			continue
		}
		end := index + 1
		matched := true
		for count := 0; count < hashes; count++ {
			if end+count >= len(source) || source[end+count] != '#' {
				matched = false
				break
			}
		}
		if matched {
			return end + hashes, true
		}
		index++
	}
	return len(source), true
}

func looksLikeCharLiteral(source []byte, start int) bool {
	end := start + 1
	if end < len(source) && source[end] == '\\' {
		end += 2
	} else {
		end++
	}
	return end < len(source) && source[end] == '\''
}

func blank(body []byte, start, end int) {
	if end > len(body) {
		end = len(body)
	}
	for index := start; index < end; index++ {
		if body[index] != '\n' {
			body[index] = ' '
		}
	}
}
