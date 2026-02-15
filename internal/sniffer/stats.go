package sniffer

import (
	"fmt"
	"sync/atomic"
	"time"
)

type Stats struct {
	start time.Time

	packets uint64
	bytes   uint64
	flows   uint64

	tcp  uint64
	udp  uint64
	icmp uint64
	dns  uint64
	arp  uint64

	// Extended metrics
	http    uint64
	https   uint64
	dropped uint64
	errors  uint64

	topPortSrc uint64 // packed: (count<<16)|port (best-effort)
	topPortDst uint64

	// Bandwidth tracking
	bytesPerSec     float64
	lastByteCount   uint64
	lastSampleTime  time.Time
}

func NewStats() *Stats {
	return &Stats{
		start:         time.Now(),
		lastSampleTime: time.Now(),
	}
}

func (s *Stats) IncPackets() { atomic.AddUint64(&s.packets, 1) }
func (s *Stats) IncBytes(n uint64) { atomic.AddUint64(&s.bytes, n) }
func (s *Stats) IncFlow() { atomic.AddUint64(&s.flows, 1) }
func (s *Stats) IncTCP() { atomic.AddUint64(&s.tcp, 1) }
func (s *Stats) IncUDP() { atomic.AddUint64(&s.udp, 1) }
func (s *Stats) IncICMP() { atomic.AddUint64(&s.icmp, 1) }
func (s *Stats) IncDNS() { atomic.AddUint64(&s.dns, 1) }
func (s *Stats) IncARP() { atomic.AddUint64(&s.arp, 1) }
func (s *Stats) IncHTTP() { atomic.AddUint64(&s.http, 1) }
func (s *Stats) IncHTTPS() { atomic.AddUint64(&s.https, 1) }
func (s *Stats) IncDropped() { atomic.AddUint64(&s.dropped, 1) }
func (s *Stats) IncErrors() { atomic.AddUint64(&s.errors, 1) }

func (s *Stats) ObservePorts(src, dst uint16) {
	atomic.StoreUint64(&s.topPortSrc, uint64(src))
	atomic.StoreUint64(&s.topPortDst, uint64(dst))
}

func (s *Stats) updateBandwidth() {
	now := time.Now()
	currentBytes := atomic.LoadUint64(&s.bytes)
	elapsed := now.Sub(s.lastSampleTime).Seconds()
	
	if elapsed > 0 {
		byteDiff := currentBytes - s.lastByteCount
		atomic.StoreFloat64(&s.bytesPerSec, float64(byteDiff)/elapsed)
	}
	
	s.lastByteCount = currentBytes
	s.lastSampleTime = now
}

func (s *Stats) GetBandwidth() float64 {
	return atomic.LoadFloat64(&s.bytesPerSec)
}

func (s *Stats) GetPacketCount() uint64 {
	return atomic.LoadUint64(&s.packets)
}

func (s *Stats) GetByteCount() uint64 {
	return atomic.LoadUint64(&s.bytes)
}

func (s *Stats) Snapshot(flows *FlowTracker) string {
	s.updateBandwidth()
	
	uptime := time.Since(s.start).Truncate(time.Second)
	p := atomic.LoadUint64(&s.packets)
	b := atomic.LoadUint64(&s.bytes)
	fl := atomic.LoadUint64(&s.flows)
	tcp := atomic.LoadUint64(&s.tcp)
	udp := atomic.LoadUint64(&s.udp)
	icmp := atomic.LoadUint64(&s.icmp)
	dns := atomic.LoadUint64(&s.dns)
	arp := atomic.LoadUint64(&s.arp)
	http := atomic.LoadUint64(&s.http)
	https := atomic.LoadUint64(&s.https)
	dropped := atomic.LoadUint64(&s.dropped)
	srcp := atomic.LoadUint64(&s.topPortSrc)
	dstp := atomic.LoadUint64(&s.topPortDst)
	bps := atomic.LoadFloat64(&s.bytesPerSec)

	top := flows.TopN(5)

	s := fmt.Sprintf("[stats] uptime=%s packets=%d bytes=%d flows=%d tcp=%d udp=%d icmp=%d dns=%d arp=%d http=%d https=%d dropped=%d bw=%.2fKB/s last_ports=%d->%d",
		uptime, p, b, fl, tcp, udp, icmp, dns, arp, http, https, dropped, bps/1024, srcp, dstp,
	)
	if len(top) > 0 {
		s += "\n  top_flows:"
		for _, t := range top {
			s += fmt.Sprintf("\n    %s (%d)", t.Flow, t.Count)
		}
	}
	return s
}

func (s *Stats) Reset() {
	atomic.StoreUint64(&s.packets, 0)
	atomic.StoreUint64(&s.bytes, 0)
	atomic.StoreUint64(&s.flows, 0)
	atomic.StoreUint64(&s.tcp, 0)
	atomic.StoreUint64(&s.udp, 0)
	atomic.StoreUint64(&s.icmp, 0)
	atomic.StoreUint64(&s.dns, 0)
	atomic.StoreUint64(&s.arp, 0)
	atomic.StoreUint64(&s.http, 0)
	atomic.StoreUint64(&s.https, 0)
	atomic.StoreUint64(&s.dropped, 0)
	atomic.StoreUint64(&s.errors, 0)
	s.start = time.Now()
}
