package engine

import (
	"time"

	"github.com/nitrowolf96/aggregatore-wan/internal/fec"
	"github.com/nitrowolf96/aggregatore-wan/internal/pathmon"
	"github.com/nitrowolf96/aggregatore-wan/internal/reorder"
)

// PathMetrics is the dashboard view of one path.
type PathMetrics struct {
	ID           uint8   `json:"id"`
	Name         string  `json:"name,omitempty"`
	Up           bool    `json:"up"`
	Registered   bool    `json:"registered"`
	SRTTMs       float64 `json:"srtt_ms"`
	RTTVarMs     float64 `json:"rttvar_ms"`
	LossPct      float64 `json:"loss_pct"`
	CapacityMbps float64 `json:"capacity_mbps"`
	WeightMbps   float64 `json:"weight_mbps"`
	OwdAvgMs     float64 `json:"owd_avg_ms"`
	OwdJitterMs  float64 `json:"owd_jitter_ms"`
	TxPackets    uint32  `json:"tx_packets"`
	RxPackets    uint32  `json:"rx_packets"`
	RxBytes      uint64  `json:"rx_bytes"`
}

// FECMetrics summarizes both FEC directions of one tunnel end.
type FECMetrics struct {
	Params    string `json:"params"`
	Groups    uint64 `json:"groups"`
	Parity    uint64 `json:"parity"`
	Recovered uint64 `json:"recovered"`
}

// SessionMetrics is the server-side view of one client session.
type SessionMetrics struct {
	ID      uint32        `json:"id"`
	Paths   []PathMetrics `json:"paths"`
	Reorder reorder.Stats `json:"reorder"`
	FEC     *FECMetrics   `json:"fec,omitempty"`
}

// Metrics is the full dashboard snapshot of one daemon.
type Metrics struct {
	Mode          string `json:"mode"`
	NowMs         int64  `json:"now_ms"`
	Session       uint32 `json:"session,omitempty"`
	TxPackets     uint64 `json:"tx_packets"`
	TxBytes       uint64 `json:"tx_bytes"`
	RxPackets     uint64 `json:"rx_packets"`
	RxBytes       uint64 `json:"rx_bytes"`
	DropNoPath    uint64 `json:"drop_no_path"`
	DropUnknown   uint64 `json:"drop_unknown"`
	DropQueue     uint64 `json:"drop_queue"`
	DropMalformed uint64 `json:"drop_malformed"`
	CorrHits      uint64 `json:"corr_hits"`
	CorrMiss      uint64 `json:"corr_miss"`

	// Client mode.
	Paths   []PathMetrics  `json:"paths,omitempty"`
	Reorder *reorder.Stats `json:"reorder,omitempty"`
	FEC     *FECMetrics    `json:"fec,omitempty"`

	// Server mode.
	Sessions []SessionMetrics `json:"sessions,omitempty"`
}

// Metrics builds a dashboard snapshot.
func (e *Engine) Metrics() Metrics {
	now := time.Now()
	m := Metrics{
		NowMs:         now.UnixMilli(),
		TxPackets:     e.Stats.TxPackets.Load(),
		TxBytes:       e.Stats.TxBytes.Load(),
		RxPackets:     e.Stats.RxPackets.Load(),
		RxBytes:       e.Stats.RxBytes.Load(),
		DropNoPath:    e.Stats.TxDropNoPath.Load(),
		DropUnknown:   e.Stats.RxDropUnknown.Load(),
		DropQueue:     e.Stats.RxDropQueue.Load(),
		DropMalformed: e.Stats.RxDropMalformed.Load(),
	}
	m.CorrHits, m.CorrMiss, _ = e.correlator.Stats()

	if e.mode == ModeClient {
		m.Mode = "client"
		m.Session = e.session
		for _, p := range e.allPaths() {
			pm := pathMetrics(p.Link.Snapshot(), p.Rx, now)
			pm.ID, pm.Name = p.ID, p.Name
			pm.Registered = p.registered.Load()
			pm.TxPackets = p.pathSeq.Load()
			m.Paths = append(m.Paths, pm)
		}
		rs := e.reorderBuf.Snapshot()
		m.Reorder = &rs
		m.FEC = fecMetrics(e.fecEnc, e.fecDec)
		return m
	}

	m.Mode = "server"
	for _, sess := range e.allSessions() {
		sm := SessionMetrics{ID: sess.ID, Reorder: sess.reorder.Snapshot()}
		sm.FEC = fecMetrics(sess.fecEnc, sess.fecDec)
		for _, ps := range sess.alivePaths(now.UnixNano()) {
			pm := pathMetrics(ps.Link.Snapshot(), ps.Rx, now)
			pm.ID = ps.id
			pm.Registered = true
			pm.TxPackets = sess.pathSeq[ps.id].Load()
			sm.Paths = append(sm.Paths, pm)
		}
		m.Sessions = append(m.Sessions, sm)
	}
	return m
}

func pathMetrics(s pathmon.Snapshot, rx *pathmon.RxStats, now time.Time) PathMetrics {
	pm := PathMetrics{
		Up:           s.Up,
		SRTTMs:       float64(s.SRTT.Microseconds()) / 1000,
		RTTVarMs:     float64(s.RTTVar.Microseconds()) / 1000,
		LossPct:      s.LossEWMA * 100,
		CapacityMbps: s.CapacityBps / 1e6,
		WeightMbps:   s.WeightBps / 1e6,
	}
	if ew, j, ok := rx.OwdView(now, 3*time.Second); ok {
		pm.OwdAvgMs = ew / 1000
		pm.OwdJitterMs = j / 1000
	}
	pkts, bytes := rx.Peek()
	pm.RxPackets, pm.RxBytes = pkts, bytes
	return pm
}

func fecMetrics(enc *fec.Encoder, dec *fec.Decoder) *FECMetrics {
	if enc == nil {
		return nil
	}
	groups, parity, params := enc.Stats()
	fm := &FECMetrics{Params: params.String(), Groups: groups, Parity: parity}
	if dec != nil {
		fm.Recovered = dec.RecoveredCount()
	}
	return fm
}
