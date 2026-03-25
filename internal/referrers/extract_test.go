package referrers

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildTar writes a tar archive into a buffer from a map of path → content.
func buildTar(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0o644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestExtractTar_RegularFiles(t *testing.T) {
	dir := t.TempDir()
	buf := buildTar(t, map[string]string{
		"deploy.yaml":  "kind: Deployment\n",
		"service.yaml": "kind: Service\n",
	})

	if err := extractTar(buf, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, name := range []string{"deploy.yaml", "service.yaml"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file %s to exist: %v", name, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "deploy.yaml"))
	if string(data) != "kind: Deployment\n" {
		t.Errorf("file content = %q", string(data))
	}
}

func TestExtractTar_NestedPath(t *testing.T) {
	dir := t.TempDir()
	buf := buildTar(t, map[string]string{
		"overlays/prod/kustomization.yaml": "kind: Kustomization\n",
	})

	if err := extractTar(buf, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path := filepath.Join(dir, "overlays", "prod", "kustomization.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected nested file to exist: %v", err)
	}
}

func TestExtractTar_DirectoryEntry(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "mydir/", Mode: 0o755}) //nolint:errcheck
	tw.Close()                                                                       //nolint:errcheck

	if err := extractTar(&buf, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "mydir"))
	if err != nil {
		t.Fatalf("expected directory to be created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected a directory")
	}
}

func TestExtractTar_EmptyTar(t *testing.T) {
	dir := t.TempDir()
	buf := buildTar(t, map[string]string{})

	// Empty tar should not error — just nothing to extract.
	if err := extractTar(buf, dir); err != nil {
		t.Errorf("unexpected error for empty tar: %v", err)
	}
}

func TestExtractTar_PathTraversalNeutralized(t *testing.T) {
	// "../evil.yaml" is neutralized by filepath.Clean("/"+name):
	//   "../evil.yaml" → "/evil.yaml" → destDir/evil.yaml
	// No error is returned; the file is safely remapped inside destDir.
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{ //nolint:errcheck
		Typeflag: tar.TypeReg,
		Name:     "../evil.yaml",
		Size:     5,
		Mode:     0o644,
	})
	tw.Write([]byte("oops!")) //nolint:errcheck
	tw.Close()                //nolint:errcheck

	if err := extractTar(&buf, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File must land inside destDir, not outside it.
	outside := filepath.Join(filepath.Dir(dir), "evil.yaml")
	if _, err := os.Stat(outside); err == nil {
		t.Error("path traversal succeeded — evil.yaml was created outside destDir")
	}
	inside := filepath.Join(dir, "evil.yaml")
	if _, err := os.Stat(inside); err != nil {
		t.Errorf("expected remapped file at destDir/evil.yaml: %v", err)
	}
}

func TestExtractTar_AbsolutePathTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{ //nolint:errcheck
		Typeflag: tar.TypeReg,
		Name:     "/etc/evil",
		Size:     5,
		Mode:     0o644,
	})
	tw.Write([]byte("oops!")) //nolint:errcheck
	tw.Close()                //nolint:errcheck

	// Absolute paths are cleaned to relative by filepath.Clean("/"+name),
	// so /etc/evil → destDir/etc/evil, which is safe.
	if err := extractTar(&buf, dir); err != nil {
		t.Fatalf("unexpected error for absolute path entry: %v", err)
	}
	// File should land inside destDir, not at /etc/evil.
	if _, err := os.Stat("/etc/evil"); err == nil {
		t.Error("absolute path traversal succeeded — /etc/evil was created")
	}
	if _, err := os.Stat(filepath.Join(dir, "etc", "evil")); err != nil {
		t.Errorf("expected file at destDir/etc/evil: %v", err)
	}
}
