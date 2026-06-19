package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestSecretPatternDetectsCapturedValueAndRedactsContext(t *testing.T) {
	pattern := &SecretPattern{
		Name:     "Example Token",
		Regex:    regexp.MustCompile(`(?m)example_token\s*=\s*([A-Za-z0-9]{16})`),
		Severity: "HIGH",
	}
	content := "name = demo\nexample_token = abcdefgh12345678\nmode = test"

	detections := pattern.Detect(content)
	if len(detections) != 1 {
		t.Fatalf("expected one detection, got %d", len(detections))
	}
	got := detections[0]
	if got.Secret != "abcdefgh12345678" {
		t.Fatalf("unexpected secret: %q", got.Secret)
	}
	if got.LineNumber != 2 {
		t.Fatalf("expected line 2, got %d", got.LineNumber)
	}
	if got.Context == content {
		t.Fatal("context should redact the detected secret")
	}
	if got.Context != "name = demo\nexample_token = abcdef...345678\nmode = test" {
		t.Fatalf("unexpected redacted context: %q", got.Context)
	}
}

func TestSecretPatternKeywordPrefilter(t *testing.T) {
	pattern := &SecretPattern{
		Name:     "Scoped Token",
		Regex:    regexp.MustCompile(`tok_[A-Za-z0-9]{12}`),
		Severity: "HIGH",
		Keywords: []string{"adobe"},
	}
	if got := pattern.Detect("tok_abcdefghijkl"); len(got) != 0 {
		t.Fatalf("expected keyword prefilter to reject content, got %d matches", len(got))
	}
	if got := pattern.Detect("Adobe token: tok_abcdefghijkl"); len(got) != 1 {
		t.Fatalf("expected keyword prefilter to accept content, got %d matches", len(got))
	}
}

func TestLoadPatternFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	data := []byte(`{
  "rules": [{
    "name": "Industry Token",
    "regex": "industry_[A-Za-z0-9]{12}",
    "severity": "critical",
    "keywords": ["industry", "vendor"]
  }]
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	patterns, err := loadPatternFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 1 || patterns[0].Severity != "CRITICAL" {
		t.Fatalf("unexpected loaded patterns: %#v", patterns)
	}
}

func TestShouldSkipPath(t *testing.T) {
	if !shouldSkipPath("assets/logo.PNG") {
		t.Fatal("expected PNG to be skipped")
	}
	if shouldSkipPath("config/production.env") {
		t.Fatal("expected .env file to be scanned")
	}
}
