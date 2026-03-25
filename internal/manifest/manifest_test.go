package manifest_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Patagia/argocd-verify-cmp/internal/manifest"
)

// captureStdout redirects os.Stdout, calls fn, then returns the captured output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w

	fn()

	if err := w.Close(); err != nil {
		panic(err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r) //nolint:errcheck
	if err := r.Close(); err != nil {
		panic(err)
	}
	return buf.String()
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGenerate_SingleYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")

	var genErr error
	out := captureStdout(t, func() {
		genErr = manifest.Generate(dir, "")
	})
	if genErr != nil {
		t.Fatalf("unexpected error: %v", genErr)
	}
	if !strings.Contains(out, "kind: Deployment") {
		t.Errorf("output missing expected content, got: %q", out)
	}
}

func TestGenerate_MultipleFilesAreSeparated(t *testing.T) {
	dir := t.TempDir()
	// WalkDir visits in lexical order so a_ comes before b_.
	writeFile(t, dir, "a_svc.yaml", "kind: Service\n")
	writeFile(t, dir, "b_deploy.yaml", "kind: Deployment\n")

	var genErr error
	out := captureStdout(t, func() {
		genErr = manifest.Generate(dir, "")
	})
	if genErr != nil {
		t.Fatalf("unexpected error: %v", genErr)
	}
	if !strings.Contains(out, "---") {
		t.Errorf("expected --- separator between files, got: %q", out)
	}
	if idx1, idx2 := strings.Index(out, "Service"), strings.Index(out, "Deployment"); idx1 > idx2 {
		t.Errorf("expected Service before Deployment (lexical order)")
	}
}

func TestGenerate_YMLAndJSONIncluded(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yml", "kind: ConfigMap\n")
	writeFile(t, dir, "b.json", `{"kind":"Secret"}`)

	var genErr error
	out := captureStdout(t, func() {
		genErr = manifest.Generate(dir, "")
	})
	if genErr != nil {
		t.Fatalf("unexpected error: %v", genErr)
	}
	if !strings.Contains(out, "ConfigMap") {
		t.Errorf("output missing .yml file content")
	}
	if !strings.Contains(out, "Secret") {
		t.Errorf("output missing .json file content")
	}
}

func TestGenerate_MultipleJSONFilesRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.json", `{"kind":"Service"}`)
	writeFile(t, dir, "b.json", `{"kind":"Deployment"}`)

	err := manifest.Generate(dir, "")
	if err == nil {
		t.Fatal("expected error for multiple .json files, got nil")
	}
	if !strings.Contains(err.Error(), "multiple .json") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGenerate_NonManifestFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "notes.txt", "this should be ignored")
	writeFile(t, dir, "main.go", "package main")
	writeFile(t, dir, "deploy.yaml", "kind: Deployment\n")

	var genErr error
	out := captureStdout(t, func() {
		genErr = manifest.Generate(dir, "")
	})
	if genErr != nil {
		t.Fatalf("unexpected error: %v", genErr)
	}
	if strings.Contains(out, "ignored") {
		t.Error(".txt file content should not appear in output")
	}
	if strings.Contains(out, "package main") {
		t.Error(".go file content should not appear in output")
	}
}

func TestGenerate_HiddenFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".hidden.yaml", "kind: Hidden\n")
	writeFile(t, dir, "visible.yaml", "kind: Visible\n")

	var genErr error
	out := captureStdout(t, func() {
		genErr = manifest.Generate(dir, "")
	})
	if genErr != nil {
		t.Fatalf("unexpected error: %v", genErr)
	}
	if strings.Contains(out, "Hidden") {
		t.Error("hidden file content should not appear in output")
	}
	if !strings.Contains(out, "Visible") {
		t.Error("visible file should appear in output")
	}
}

func TestGenerate_HiddenDirSkipped(t *testing.T) {
	dir := t.TempDir()
	hiddenDir := filepath.Join(dir, ".git")
	if err := os.Mkdir(hiddenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, hiddenDir, "config.yaml", "kind: ShouldBeSkipped\n")
	writeFile(t, dir, "deploy.yaml", "kind: Deployment\n")

	var genErr error
	out := captureStdout(t, func() {
		genErr = manifest.Generate(dir, "")
	})
	if genErr != nil {
		t.Fatalf("unexpected error: %v", genErr)
	}
	if strings.Contains(out, "ShouldBeSkipped") {
		t.Error("content inside hidden directory should not appear in output")
	}
}

func TestGenerate_WithSubPath(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "overlays", "production")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, sub, "kustomization.yaml", "kind: Kustomization\n")
	// File outside subpath should not appear.
	writeFile(t, base, "root.yaml", "kind: Root\n")

	var genErr error
	out := captureStdout(t, func() {
		genErr = manifest.Generate(base, "overlays/production")
	})
	if genErr != nil {
		t.Fatalf("unexpected error: %v", genErr)
	}
	if !strings.Contains(out, "Kustomization") {
		t.Error("subpath file should appear in output")
	}
	if strings.Contains(out, "Root") {
		t.Error("file outside subpath should not appear in output")
	}
}

func TestGenerate_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := manifest.Generate(dir, "")
	if err == nil {
		t.Fatal("expected error for empty dir, got nil")
	}
	if !strings.Contains(err.Error(), "no manifests found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGenerate_DirNotExist(t *testing.T) {
	err := manifest.Generate("/nonexistent/path", "")
	if err == nil {
		t.Fatal("expected error for non-existent dir, got nil")
	}
}

func TestGenerate_FilesInSubdirsIncluded(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, sub, "nested.yaml", "kind: Nested\n")

	var genErr error
	out := captureStdout(t, func() {
		genErr = manifest.Generate(dir, "")
	})
	if genErr != nil {
		t.Fatalf("unexpected error: %v", genErr)
	}
	if !strings.Contains(out, "Nested") {
		t.Error("nested file should appear in output")
	}
}
