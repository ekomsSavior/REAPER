package main

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-github/v61/github"
)

func TestRateLimitResumeUsesPrimaryResetAndBuffer(t *testing.T) {
	now := time.Date(2026, 6, 19, 11, 35, 30, 0, time.UTC)
	reset := now.Add(20 * time.Minute)
	err := &github.RateLimitError{
		Rate: github.Rate{Reset: github.Timestamp{Time: reset}},
	}

	resume, reason, limited := rateLimitResume(err, now, 5*time.Second)
	if !limited {
		t.Fatal("expected primary rate-limit error to be recognized")
	}
	if reason != "primary rate limit reached" {
		t.Fatalf("unexpected reason: %q", reason)
	}
	if want := reset.Add(5 * time.Second); !resume.Equal(want) {
		t.Fatalf("got resume %s, want %s", resume, want)
	}
}

func TestRateLimitResumeUsesSecondaryRetryAfter(t *testing.T) {
	now := time.Date(2026, 6, 19, 11, 35, 30, 0, time.UTC)
	retryAfter := 90 * time.Second
	err := &github.AbuseRateLimitError{RetryAfter: &retryAfter}

	resume, _, limited := rateLimitResume(err, now, 5*time.Second)
	if !limited {
		t.Fatal("expected secondary rate-limit error to be recognized")
	}
	if want := now.Add(95 * time.Second); !resume.Equal(want) {
		t.Fatalf("got resume %s, want %s", resume, want)
	}
}

func TestRateLimitResumeRejectsOtherErrors(t *testing.T) {
	if _, _, limited := rateLimitResume(errors.New("boom"), time.Now(), 0); limited {
		t.Fatal("ordinary errors must not trigger a shared rate-limit pause")
	}
}
