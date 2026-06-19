package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareOutputDirectoryCreatesPerRunDirectory(t *testing.T) {
	base := filepath.Join(t.TempDir(), "output")
	now := time.Date(2026, 6, 19, 12, 34, 56, 0, time.Local)

	got, err := prepareOutputDirectory(base, false, now)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "run_20260619_123456")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if info, err := os.Stat(got); err != nil || !info.IsDir() {
		t.Fatalf("run directory was not created: %v", err)
	}
}

func TestPrepareOutputDirectoryAvoidsRunNameCollisions(t *testing.T) {
	base := filepath.Join(t.TempDir(), "output")
	now := time.Date(2026, 6, 19, 12, 34, 56, 0, time.Local)

	first, err := prepareOutputDirectory(base, false, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepareOutputDirectory(base, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("expected unique run directories, both were %q", first)
	}
	if want := filepath.Join(base, "run_20260619_123456_01"); second != want {
		t.Fatalf("got %q, want %q", second, want)
	}
}

func TestPrepareOutputDirectoryUsesExplicitDirectoryExactly(t *testing.T) {
	want := filepath.Join(t.TempDir(), "custom-output")
	got, err := prepareOutputDirectory(want, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
