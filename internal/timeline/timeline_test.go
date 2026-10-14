package timeline

import (
	"testing"
	"time"
)

func day(d int) time.Time { return time.Date(2026, 1, d, 12, 0, 0, 0, time.UTC) }

func TestDate(t *testing.T) {
	r := Date([]Obs{
		{T: day(1), Present: false},
		{T: day(3), Present: false},
		{T: day(5), Present: true, Source: "snapshot"},
		{T: day(7), Present: true},
		{T: day(9), Present: true},
		{T: day(11), Present: false, Source: "snapshot"},
		{T: day(13), Present: false},
		{T: time.Time{}, Present: true}, // ignored
	})
	if !r.Granted.After.Equal(day(3)) || !r.Granted.Before.Equal(day(5)) || r.Granted.Source != "snapshot" {
		t.Errorf("granted = %+v", r.Granted)
	}
	if !r.LastSeen.Equal(day(9)) {
		t.Errorf("last seen = %v", r.LastSeen)
	}
	if !r.RemovedAt.After.Equal(day(9)) || !r.RemovedAt.Before.Equal(day(11)) {
		t.Errorf("removed = %+v", r.RemovedAt)
	}
	// Evidence keeps both bounds of each window: days 1, 3, 5, 9, 11, 13.
	var got []int
	for _, e := range r.Evidence {
		got = append(got, e.Time.Day())
	}
	want := []int{1, 3, 5, 9, 11, 13}
	if len(got) != len(want) {
		t.Fatalf("evidence days = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("evidence days = %v, want %v", got, want)
		}
	}
}

func TestDateNeverPresent(t *testing.T) {
	r := Date([]Obs{{T: day(1)}, {T: day(2)}})
	if !r.Granted.Before.IsZero() || len(r.Evidence) != 0 {
		t.Errorf("want empty result, got %+v", r)
	}
}
