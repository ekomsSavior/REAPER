package main

import "testing"

func TestUniqueKeywordsPreservesOrder(t *testing.T) {
	got := uniqueKeywords([]string{" Adobe ", "olympics", "adobe", "", "OLYMPICS", "healthcare"})
	want := []string{"Adobe", "olympics", "healthcare"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestQuoteSearchKeyword(t *testing.T) {
	got := quoteSearchKeyword(`Adobe "Experience Cloud"`)
	want := `"Adobe \"Experience Cloud\""`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
