package portplan

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ListJavaSources returns every .java file under root, as forward-slash paths relative to root,
// sorted. It is the single traversal used for both counting and study-surface selection.
func ListJavaSources(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".java") {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

// CountPhysicalLines counts newline bytes in a file, matching wc -l semantics exactly.
func CountPhysicalLines(path string) (int, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, value := range content {
		if value == '\n' {
			count++
		}
	}
	return count, nil
}

// TreeTotals is a derived file/line count over a source tree.
type TreeTotals struct {
	Files int `json:"files"`
	Lines int `json:"physical_lines"`
}

// CountTree derives the file and physical-line totals for the given relative paths under root.
func CountTree(root string, paths []string) (TreeTotals, error) {
	totals := TreeTotals{Files: len(paths)}
	for _, relative := range paths {
		lines, err := CountPhysicalLines(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return TreeTotals{}, err
		}
		totals.Lines += lines
	}
	return totals, nil
}
