// Package manifest walks an extracted manifest bundle directory and concatenates
// all YAML/JSON files to stdout for ArgoCD's generate step.
package manifest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Generate walks baseDir (with optional subPath appended), concatenates all
// *.yaml, *.yml, and *.json files separated by "---\n", and writes them to
// stdout. Returns an error if no manifests are found.
func Generate(baseDir, subPath string) error {
	root := baseDir
	if subPath != "" {
		root = filepath.Join(baseDir, subPath)
	}

	var count, jsonCount int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip hidden files and directories.
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		if ext == ".json" {
			if jsonCount >= 1 {
				return fmt.Errorf("multiple .json files in bundle are not supported; consolidate JSON manifests into a single file or convert them to YAML")
			}
			jsonCount++
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if count > 0 {
			fmt.Print("---\n")
		}
		fmt.Printf("%s\n", data)
		count++
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking %s: %w", root, err)
	}
	if count == 0 {
		return fmt.Errorf("no manifests found in %s", root)
	}
	fmt.Fprintf(os.Stderr, "verify-cmp: generated %d manifest file(s) from %s\n", count, root)
	return nil
}
