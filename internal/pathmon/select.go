package pathmon

import "time"

// realtimeScore ranks paths for latency-sensitive traffic: smoothed RTT
// plus jitter margin plus a strong loss penalty (50ms per 100% loss EWMA,
// i.e. 0.5ms per percent).
func realtimeScore(s Snapshot) time.Duration {
	return s.SRTT + 2*s.RTTVar + time.Duration(s.LossEWMA*float64(50*time.Millisecond))
}

// BestLatency returns the index of the up path with the best realtime
// score, or -1.
func BestLatency(snaps []Snapshot) int {
	best := -1
	var bestScore time.Duration
	for i, s := range snaps {
		if !s.Up {
			continue
		}
		sc := realtimeScore(s)
		if best == -1 || sc < bestScore {
			best, bestScore = i, sc
		}
	}
	return best
}

// WeightedLoss aggregates per-path loss EWMA weighted by each path's
// traffic share, for the FEC controller.
func WeightedLoss(snaps []Snapshot) float64 {
	var num, den float64
	for _, s := range snaps {
		if !s.Up {
			continue
		}
		w := s.WeightBps
		if w <= 0 {
			w = 1
		}
		num += s.LossEWMA * w
		den += w
	}
	if den == 0 {
		return 0
	}
	return num / den
}

// BestPair returns the indexes of the two best up paths by realtime score
// (second is -1 when fewer than two are up).
func BestPair(snaps []Snapshot) (int, int) {
	first, second := -1, -1
	var s1, s2 time.Duration
	for i, s := range snaps {
		if !s.Up {
			continue
		}
		sc := realtimeScore(s)
		switch {
		case first == -1 || sc < s1:
			second, s2 = first, s1
			first, s1 = i, sc
		case second == -1 || sc < s2:
			second, s2 = i, sc
		}
	}
	return first, second
}
