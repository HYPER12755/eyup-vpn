package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := readLines(path); !os.IsNotExist(err) {
		t.Fatalf("missing file must return os.IsNotExist, got %v", err)
	}
	if err := os.WriteFile(path, []byte("a\nb\n\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := readLines(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 4 || lines[0] != "a" || lines[1] != "b" || lines[2] != "" || lines[3] != "c" {
		t.Fatalf("beklenmeyen satırlar: %#v", lines)
	}
}

func TestReadUint(t *testing.T) {
	dir := t.TempDir()
	if got := readUint(filepath.Join(dir, "missing")); got != 0 {
		t.Fatalf("missing file must read 0, got %d", got)
	}
	path := filepath.Join(dir, "quota")
	if err := os.WriteFile(path, []byte("  5242880\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readUint(path); got != 5242880 {
		t.Fatalf("readUint = %d, want 5242880", got)
	}
}

func TestWriteUintCreatesParents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "counter")
	if err := writeUint(path, 42); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "42\n") {
		t.Fatalf("writeUint içerik yanlış: %q", data)
	}
}
