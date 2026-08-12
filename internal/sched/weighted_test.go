package sched

import "testing"

// pickMany runs n picks and returns the count per path id.
func pickMany(w *Weighted, ids []uint8, weights []float64, n int) map[uint8]int {
	counts := make(map[uint8]int)
	for i := 0; i < n; i++ {
		counts[ids[w.Pick(ids, weights)]]++
	}
	return counts
}

func TestProportionalSplit(t *testing.T) {
	w := NewWeighted()
	ids := []uint8{0, 1}
	counts := pickMany(w, ids, []float64{50e6, 30e6}, 8000)
	share0 := float64(counts[0]) / 8000
	if share0 < 0.58 || share0 > 0.67 { // want 50/80 = 0.625
		t.Fatalf("share of path 0 = %.3f, want ~0.625 (counts %v)", share0, counts)
	}
}

func TestUnknownWeightsSplitEqually(t *testing.T) {
	w := NewWeighted()
	ids := []uint8{0, 1, 2}
	counts := pickMany(w, ids, []float64{0, 0, 0}, 9000)
	for id, c := range counts {
		if c < 2800 || c > 3200 {
			t.Fatalf("path %d got %d of 9000, want ~3000", id, c)
		}
	}
}

func TestFloorKeepsWeakPathAlive(t *testing.T) {
	w := NewWeighted()
	ids := []uint8{0, 1}
	counts := pickMany(w, ids, []float64{100e6, 0.1e6}, 10000)
	if counts[1] < 400 { // floor is 5%
		t.Fatalf("weak path starved: %v", counts)
	}
}

func TestInterleaving(t *testing.T) {
	// With equal weights the schedule must alternate, not burst.
	w := NewWeighted()
	ids := []uint8{0, 1}
	prev := -1
	repeats := 0
	for i := 0; i < 100; i++ {
		got := w.Pick(ids, []float64{10, 10})
		if got == prev {
			repeats++
		}
		prev = got
	}
	if repeats > 2 {
		t.Fatalf("bursty schedule: %d consecutive repeats", repeats)
	}
}

func TestSinglePath(t *testing.T) {
	w := NewWeighted()
	if got := w.Pick([]uint8{7}, []float64{1}); got != 0 {
		t.Fatalf("got %d", got)
	}
	if got := w.Pick(nil, nil); got != -1 {
		t.Fatalf("got %d", got)
	}
}
