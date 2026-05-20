package nlquery

import (
	"sync"
	"time"
)

// SessionSpend tracks LLM dollars accrued in this process since startup.
// Single-user POC; no per-user attribution, no persistence — counter resets
// when the binary restarts. The point is to give the user a "where am I
// today" awareness inside one session.
type SessionSpend struct {
	mu              sync.Mutex
	queries         int
	estimatedUSD    float64
	actualUSD       float64
	startedAt       time.Time
	lastQueryAt     time.Time
	lastQueryUSD    float64
	exceededEstCnt  int // queries whose actual cost exceeded the pre-flight estimate by >2x
}

// NewSessionSpend returns a fresh tracker.
func NewSessionSpend() *SessionSpend {
	return &SessionSpend{startedAt: time.Now()}
}

// SessionSpendSnapshot is the read-only view exposed via the API.
type SessionSpendSnapshot struct {
	Queries        int       `json:"queries"`
	EstimatedUSD   float64   `json:"estimated_usd"`
	ActualUSD      float64   `json:"actual_usd"`
	StartedAt      time.Time `json:"started_at"`
	LastQueryAt    time.Time `json:"last_query_at,omitempty"`
	LastQueryUSD   float64   `json:"last_query_usd"`
	ExceededEstCnt int       `json:"exceeded_estimate_count"`
}

// Snapshot returns a copy of the current totals safe to serialize over HTTP.
func (s *SessionSpend) Snapshot() SessionSpendSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionSpendSnapshot{
		Queries:        s.queries,
		EstimatedUSD:   s.estimatedUSD,
		ActualUSD:      s.actualUSD,
		StartedAt:      s.startedAt,
		LastQueryAt:    s.lastQueryAt,
		LastQueryUSD:   s.lastQueryUSD,
		ExceededEstCnt: s.exceededEstCnt,
	}
}

// Record adds one query's pre-flight estimate and post-run actual cost to
// the tracker. Either side can be zero (e.g., when actual is unknown).
func (s *SessionSpend) Record(estimatedUSD, actualUSD float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries++
	s.estimatedUSD += estimatedUSD
	s.actualUSD += actualUSD
	s.lastQueryAt = time.Now()
	s.lastQueryUSD = actualUSD
	if actualUSD > 0 && estimatedUSD > 0 && actualUSD > estimatedUSD*2 {
		s.exceededEstCnt++
	}
}

// Reset zeros the tracker. Exposed for an explicit "reset" UI affordance —
// not used internally; counter naturally resets on app restart.
func (s *SessionSpend) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = 0
	s.estimatedUSD = 0
	s.actualUSD = 0
	s.startedAt = time.Now()
	s.lastQueryAt = time.Time{}
	s.lastQueryUSD = 0
	s.exceededEstCnt = 0
}
