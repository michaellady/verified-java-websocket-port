package rustgate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type tomlEntry struct {
	Section  string
	Instance int
	Key      string
	Raw      string
}

type tomlDocument struct {
	entries []tomlEntry
}

func parseTOML(body []byte) (tomlDocument, error) {
	var document tomlDocument
	section := ""
	instance := 0
	instances := make(map[string]int)
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line, err := stripTOMLComment(scanner.Text())
		if err != nil {
			return tomlDocument{}, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			section, err = normalizeTOMLKey(strings.TrimSpace(line[2 : len(line)-2]))
			if err != nil || section == "" {
				return tomlDocument{}, fmt.Errorf("line %d: empty array table", lineNumber)
			}
			instances[section]++
			instance = instances[section]
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section, err = normalizeTOMLKey(strings.TrimSpace(line[1 : len(line)-1]))
			if err != nil || section == "" {
				return tomlDocument{}, fmt.Errorf("line %d: empty table", lineNumber)
			}
			instance = 0
			continue
		}
		separator := indexOutsideTOMLString(line, '=')
		if separator < 1 {
			return tomlDocument{}, fmt.Errorf("line %d: unsupported TOML statement", lineNumber)
		}
		key, err := normalizeTOMLKey(strings.TrimSpace(line[:separator]))
		if err != nil {
			return tomlDocument{}, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		raw := strings.TrimSpace(line[separator+1:])
		if key == "" || raw == "" {
			return tomlDocument{}, fmt.Errorf("line %d: empty key or value", lineNumber)
		}
		identity := fmt.Sprintf("%d\x00%s", instance, tomlFullKey(section, key))
		if seen[identity] {
			return tomlDocument{}, fmt.Errorf("line %d: duplicate key %s", lineNumber, key)
		}
		seen[identity] = true
		document.entries = append(document.entries, tomlEntry{Section: section, Instance: instance, Key: key, Raw: raw})
	}
	if err := scanner.Err(); err != nil {
		return tomlDocument{}, err
	}
	return document, nil
}

// normalizeTOMLKey makes Cargo-equivalent bare, quoted, and dotted keys
// comparable without interpreting their values.
func normalizeTOMLKey(raw string) (string, error) {
	var parts []string
	for index := 0; index < len(raw); {
		for index < len(raw) && (raw[index] == ' ' || raw[index] == '\t') {
			index++
		}
		if index == len(raw) {
			return "", fmt.Errorf("empty TOML key segment")
		}

		var part string
		switch raw[index] {
		case '"':
			start := index
			index++
			end := -1
			for index < len(raw) {
				if raw[index] == '\\' {
					if index+1 >= len(raw) {
						return "", fmt.Errorf("unterminated quoted TOML key")
					}
					index += 2
					continue
				}
				index++
				if raw[index-1] == '"' {
					end = index
					break
				}
			}
			if end < 0 {
				return "", fmt.Errorf("unterminated quoted TOML key")
			}
			value, err := strconv.Unquote(raw[start:end])
			if err != nil {
				return "", fmt.Errorf("invalid quoted TOML key: %w", err)
			}
			part = value
		case '\'':
			relativeEnd := strings.IndexByte(raw[index+1:], '\'')
			if relativeEnd < 0 {
				return "", fmt.Errorf("unterminated literal TOML key")
			}
			end := index + 1 + relativeEnd
			part = raw[index+1 : end]
			index = end + 1
		default:
			start := index
			for index < len(raw) && raw[index] != '.' && raw[index] != ' ' && raw[index] != '\t' {
				char := raw[index]
				if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
					(char >= '0' && char <= '9') || char == '_' || char == '-') {
					return "", fmt.Errorf("invalid bare TOML key")
				}
				index++
			}
			part = raw[start:index]
		}
		if part == "" {
			return "", fmt.Errorf("empty TOML key segment")
		}
		parts = append(parts, part)

		for index < len(raw) && (raw[index] == ' ' || raw[index] == '\t') {
			index++
		}
		if index == len(raw) {
			break
		}
		if raw[index] != '.' {
			return "", fmt.Errorf("invalid TOML key separator")
		}
		index++
	}
	return strings.Join(parts, "."), nil
}

func (d tomlDocument) stringValue(section, key string) (string, bool) {
	return d.stringValueAt(section, 0, key)
}

func (d tomlDocument) stringValueAt(section string, instance int, key string) (string, bool) {
	raw, ok := d.rawValueAt(section, instance, key)
	if !ok || len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	value, err := strconv.Unquote(raw)
	return value, err == nil
}

func (d tomlDocument) boolValue(section, key string) (bool, bool) {
	raw, ok := d.rawValueAt(section, 0, key)
	if !ok {
		return false, false
	}
	switch raw {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func (d tomlDocument) integerValue(section, key string) (int, bool) {
	raw, ok := d.rawValueAt(section, 0, key)
	if !ok {
		return 0, false
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	return value, err == nil
}

func (d tomlDocument) stringArray(section, key string) ([]string, bool) {
	raw, ok := d.rawValueAt(section, 0, key)
	if !ok {
		return nil, false
	}
	var result []string
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, false
	}
	return result, true
}

func (d tomlDocument) rawValueAt(section string, instance int, key string) (string, bool) {
	target := tomlFullKey(section, key)
	for _, entry := range d.entries {
		if entry.Instance == instance && tomlFullKey(entry.Section, entry.Key) == target {
			return entry.Raw, true
		}
	}
	return "", false
}

func tomlFullKey(section, key string) string {
	if section == "" {
		return key
	}
	return section + "." + key
}

func (d tomlDocument) hasSection(section string) bool {
	for _, entry := range d.entries {
		if entry.Section == section {
			return true
		}
	}
	return false
}

func (d tomlDocument) sectionInstances(section string) []int {
	seen := make(map[int]bool)
	for _, entry := range d.entries {
		if entry.Section == section {
			seen[entry.Instance] = true
		}
	}
	instances := make([]int, 0, len(seen))
	for instance := range seen {
		instances = append(instances, instance)
	}
	sort.Ints(instances)
	return instances
}

func (d tomlDocument) packageIdentities() map[string]string {
	result := make(map[string]string)
	for _, instance := range d.sectionInstances("package") {
		name, nameOK := d.stringValueAt("package", instance, "name")
		version, versionOK := d.stringValueAt("package", instance, "version")
		if nameOK && versionOK {
			result[name] = version
		}
	}
	return result
}

func stripTOMLComment(line string) (string, error) {
	inString := false
	escaped := false
	for index, char := range line {
		if inString {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == '"' {
				inString = false
			}
			continue
		}
		if char == '"' {
			inString = true
		} else if char == '#' {
			return line[:index], nil
		}
	}
	if inString {
		return "", fmt.Errorf("unterminated string")
	}
	return line, nil
}

func indexOutsideTOMLString(line string, target byte) int {
	inString := false
	escaped := false
	for index := 0; index < len(line); index++ {
		char := line[index]
		if inString {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == '"' {
				inString = false
			}
			continue
		}
		if char == '"' {
			inString = true
		} else if char == target {
			return index
		}
	}
	return -1
}
