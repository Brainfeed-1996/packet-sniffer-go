package sniffer

import (
	"sort"
	"sync"
	"time"
)

type FlowTracker struct {
	mu         sync.Mutex
	counts     map[string]uint64
	hotEveryN  uint64
	lastHotHit map[string]time.Time
}

func NewFlowTracker(hotEveryN uint64) *FlowTracker {
	if hotEveryN == 0 {
		hotEveryN = 100
	}
	return &FlowTracker{
		counts:     make(map[string]uint64),
		hotEveryN:  hotEveryN,
		lastHotHit: make(map[string]time.Time),
	}
}

func (f *FlowTracker) Track(flow string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[flow]++
}

type FlowTop struct {
	Flow  string
	Count uint64
}

func (f *FlowTracker) TopN(n int) []FlowTop {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FlowTop, 0, len(f.counts))
	for k, v := range f.counts {
		out = append(out, FlowTop{Flow: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if n <= 0 || n >= len(out) {
		return out
	}
	return out[:n]
}
