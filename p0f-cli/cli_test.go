package main

import (
	"testing"

	"github.com/gurre/gop0f"
)

func TestBytesToString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte{0, 0, 0, 0}, ""},
		{"simple", append([]byte("Linux"), 0), "Linux"},
		{"no_null", []byte("test"), "test"},
		{"with_trailing", []byte{'a', 'b', 0, 'c', 'd'}, "ab"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToString(tc.input)
			if result != tc.expected {
				t.Errorf("bytesToString(%v) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		status   uint32
		expected string
	}{
		{gop0f.P0F_STATUS_OK, "ok"},
		{gop0f.P0F_STATUS_BADQUERY, "bad_query"},
		{gop0f.P0F_STATUS_NOMATCH, "no_match"},
		{0xFF, "unknown(255)"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			result := statusString(tc.status)
			if result != tc.expected {
				t.Errorf("statusString(0x%02x) = %q, want %q", tc.status, result, tc.expected)
			}
		})
	}
}

func TestMatchQualityString(t *testing.T) {
	tests := []struct {
		quality  byte
		expected string
	}{
		{0, "normal"},
		{gop0f.P0F_MATCH_FUZZY, "fuzzy"},
		{gop0f.P0F_MATCH_GENERIC, "generic"},
		{gop0f.P0F_MATCH_FUZZY | gop0f.P0F_MATCH_GENERIC, "fuzzy"}, // fuzzy takes precedence
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			result := matchQualityString(tc.quality)
			if result != tc.expected {
				t.Errorf("matchQualityString(0x%02x) = %q, want %q", tc.quality, result, tc.expected)
			}
		})
	}
}

func TestFormatTime(t *testing.T) {
	// Zero returns empty
	if result := formatTime(0); result != "" {
		t.Errorf("formatTime(0) = %q, want empty string", result)
	}

	// Non-zero returns RFC3339 formatted string
	result := formatTime(1609459200)
	if result == "" {
		t.Error("formatTime(1609459200) should not be empty")
	}
	// Should contain date portion
	if len(result) < 10 {
		t.Errorf("formatTime result too short: %q", result)
	}
}

func TestFormatTimeOptional(t *testing.T) {
	// Zero returns empty
	if result := formatTimeOptional(0); result != "" {
		t.Errorf("formatTimeOptional(0) = %q, want empty string", result)
	}

	// Non-zero returns RFC3339 formatted string
	result := formatTimeOptional(1609459200)
	if result == "" {
		t.Error("formatTimeOptional(1609459200) should not be empty")
	}
}

func TestConvertResponse(t *testing.T) {
	resp := gop0f.P0fResponse{
		Magic:      0x50304602,
		Status:     gop0f.P0F_STATUS_OK,
		FirstSeen:  1609459200,
		LastSeen:   1609459260,
		TotalCount: 42,
		UptimeMin:  1440,
		UpModDays:  7,
		LastNat:    0,
		LastChg:    0,
		Distance:   5,
		BadSw:      1,
		OsMatchQ:   gop0f.P0F_MATCH_FUZZY,
	}
	copy(resp.OsName[:], "Linux")
	copy(resp.OsFlavor[:], "5.x")
	copy(resp.LinkType[:], "Ethernet")

	out := convertResponse(resp)

	if out.Status != "ok" {
		t.Errorf("Status: got %q, want %q", out.Status, "ok")
	}
	if out.OsName != "Linux" {
		t.Errorf("OsName: got %q, want %q", out.OsName, "Linux")
	}
	if out.OsFlavor != "5.x" {
		t.Errorf("OsFlavor: got %q, want %q", out.OsFlavor, "5.x")
	}
	if out.TotalCount != 42 {
		t.Errorf("TotalCount: got %d, want %d", out.TotalCount, 42)
	}
	if out.Distance != 5 {
		t.Errorf("Distance: got %d, want %d", out.Distance, 5)
	}
	if !out.BadSw {
		t.Error("BadSw: got false, want true")
	}
	if out.OsMatchQ != "fuzzy" {
		t.Errorf("OsMatchQ: got %q, want %q", out.OsMatchQ, "fuzzy")
	}
	if out.LinkType != "Ethernet" {
		t.Errorf("LinkType: got %q, want %q", out.LinkType, "Ethernet")
	}
}

func TestPrintGrep(t *testing.T) {
	// Test with all fields populated
	out := OutputResponse{
		Status:     "ok",
		FirstSeen:  "2021-01-01T00:00:00Z",
		LastSeen:   "2021-01-01T00:01:00Z",
		TotalCount: 42,
		UptimeMin:  1440,
		UpModDays:  7,
		LastNat:    "2021-01-01T00:00:30Z",
		LastChg:    "2021-01-01T00:00:45Z",
		Distance:   5,
		BadSw:      false,
		OsMatchQ:   "normal",
		OsName:     "Linux",
		OsFlavor:   "5.x",
		HttpName:   "nginx",
		HttpFlavor: "1.19",
		LinkType:   "Ethernet",
		Language:   "en-US",
	}

	// printGrep writes to stdout, just verify it doesn't panic
	printGrep(out)

	// Test with minimal fields (empty optional fields)
	outMinimal := OutputResponse{
		Status:     "no_match",
		TotalCount: 0,
		UptimeMin:  0,
		UpModDays:  0,
		Distance:   -1,
		BadSw:      false,
		OsMatchQ:   "normal",
	}
	printGrep(outMinimal)
}
