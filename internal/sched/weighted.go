// Package sched selects the transmit path for each packet: a smooth
// deficit-weighted round-robin proportional to each path's measured
// delivery capacity, discounted by its recent loss. The inner protocols
// (TCP, QUIC) keep end-to-end congestion control; the scheduler's job is to
// split the aggregate in the right ratios and route around sick paths, and
// the receive-side reorder buffer absorbs the latency spread.
package sched

import "sync"

// Weighted is one direction's scheduler. It keeps a credit balance per
// path so consecutive packets interleave smoothly in proportion to the
// weights (a burst-free WRR), which minimizes reordering pressure.
type Weighted struct {
	mu      sync.Mutex
	credits map[uint8]float64
}

func NewWeighted() *Weighted {
	return &Weighted{credits: make(map[uint8]float64)}
}

// weightFloor guarantees every live path a small share of traffic so its
// capacity keeps being measured (and its weight can recover).
const weightFloor = 0.05

// Pick returns the index of the path that should carry the next packet.
// ids identify the candidate paths (already filtered to usable ones);
// weights are their capacity estimates in any consistent unit, 0 = unknown.
func (w *Weighted) Pick(ids []uint8, weights []float64) int {
	if len(ids) == 0 {
		return -1
	}
	if len(ids) == 1 {
		return 0
	}

	// Normalize: unknown weights get the mean of the known ones (equal
	// split at bootstrap), then everyone is floored to a minimum share.
	total := 0.0
	known := 0
	for _, wt := range weights {
		if wt > 0 {
			total += wt
			known++
		}
	}
	mean := 1.0
	if known > 0 {
		mean = total / float64(known)
	}
	shares := make([]float64, len(ids))
	sum := 0.0
	for i, wt := range weights {
		if wt <= 0 {
			wt = mean
		}
		shares[i] = wt
		sum += wt
	}
	floored := 0.0
	for i := range shares {
		s := shares[i] / sum
		if s < weightFloor {
			s = weightFloor
		}
		shares[i] = s
		floored += s
	}
	// Renormalize after flooring so credits stay conserved (increments sum
	// to exactly the 1 credit the winner pays).
	for i := range shares {
		shares[i] /= floored
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	// Drop credits of paths no longer present.
	if len(w.credits) > len(ids)*2 {
		w.credits = make(map[uint8]float64, len(ids))
	}
	best, bestCredit := -1, 0.0
	for i, id := range ids {
		c := w.credits[id] + shares[i]
		w.credits[id] = c
		if best == -1 || c > bestCredit {
			best, bestCredit = i, c
		}
	}
	w.credits[ids[best]] -= 1
	return best
}
