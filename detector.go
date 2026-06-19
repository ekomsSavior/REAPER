package main

import (
	"encoding/json"
	"fmt"
	"os"
	pathpkg "path"
	"regexp"
	"strings"
)

// Detector is the Core v2 extension point for secret detection engines.
// Implementations receive complete content so they can detect multi-line values.
type Detector interface {
	Detect(content string) []Detection
}

type Detection struct {
	Type       string
	Secret     string
	Severity   string
	LineNumber int
	Context    string
}

func (pattern *SecretPattern) Detect(content string) []Detection {
	if content == "" {
		return nil
	}
	if len(pattern.Keywords) > 0 && !containsAnyFold(content, pattern.Keywords) {
		return nil
	}

	indices := pattern.Regex.FindAllStringSubmatchIndex(content, -1)
	detections := make([]Detection, 0, len(indices))
	lines := strings.Split(content, "\n")

	for _, match := range indices {
		start, end := match[0], match[1]
		for group := 2; group+1 < len(match); group += 2 {
			if match[group] >= 0 && match[group+1] > match[group] {
				start, end = match[group], match[group+1]
				break
			}
		}

		secret := content[start:end]
		if *entropyCheck && pattern.Entropy && !hasHighEntropy(secret) {
			continue
		}

		lineNumber := strings.Count(content[:start], "\n") + 1
		context := getContext(lines, lineNumber-1, 2)
		context = strings.ReplaceAll(context, secret, maskSecret(secret))

		detections = append(detections, Detection{
			Type:       pattern.Name,
			Secret:     secret,
			Severity:   pattern.Severity,
			LineNumber: lineNumber,
			Context:    context,
		})
	}

	return detections
}

type patternFile struct {
	Rules []patternRule `json:"rules"`
}

type patternRule struct {
	Name     string   `json:"name"`
	Regex    string   `json:"regex"`
	Severity string   `json:"severity"`
	Entropy  bool     `json:"entropy"`
	Keywords []string `json:"keywords,omitempty"`
}

func loadPatternFile(path string) ([]*SecretPattern, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule pack %q: %w", path, err)
	}

	var file patternFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse rule pack %q: %w", path, err)
	}
	if len(file.Rules) == 0 {
		return nil, fmt.Errorf("rule pack %q contains no rules", path)
	}

	patterns := make([]*SecretPattern, 0, len(file.Rules))
	for index, rule := range file.Rules {
		if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Regex) == "" {
			return nil, fmt.Errorf("rule pack %q rule %d requires name and regex", path, index+1)
		}
		compiled, err := regexp.Compile(rule.Regex)
		if err != nil {
			return nil, fmt.Errorf("rule pack %q rule %q: %w", path, rule.Name, err)
		}
		severity := strings.ToUpper(strings.TrimSpace(rule.Severity))
		if severity == "" {
			severity = "HIGH"
		}
		if !validSeverity(severity) {
			return nil, fmt.Errorf("rule pack %q rule %q has invalid severity %q", path, rule.Name, rule.Severity)
		}
		patterns = append(patterns, &SecretPattern{
			Name:     rule.Name,
			Regex:    compiled,
			Severity: severity,
			Entropy:  rule.Entropy,
			Keywords: uniqueKeywords(rule.Keywords),
		})
	}
	return patterns, nil
}

func containsAnyFold(content string, keywords []string) bool {
	lower := strings.ToLower(content)
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func validSeverity(severity string) bool {
	switch severity {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

func detectorsFromPatterns(patterns []*SecretPattern) []Detector {
	detectors := make([]Detector, 0, len(patterns))
	for _, pattern := range patterns {
		detectors = append(detectors, pattern)
	}
	return detectors
}

func shouldSkipPath(path string) bool {
	extension := strings.ToLower(pathpkg.Ext(path))
	return skippedExtensions[extension]
}

var skippedExtensions = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true,
	".mp4": true, ".mp3": true, ".zip": true, ".tar": true, ".gz": true,
	".exe": true, ".dll": true, ".so": true, ".bin": true,
}
