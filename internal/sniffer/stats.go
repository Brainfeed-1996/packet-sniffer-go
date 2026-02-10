package sniffer

import (
	"fmt"
	"sync/atomic"
	"time"
)

type Stats struct {
	start time.Time

	packets uint64
	flows   uint64

tcp  uint64
	udp  uint64
	icmp uint64
	dns  uint64
	arp  uint64

	topPortSrc uint64 // packed: (count<<16)|port (best-effort)
	topPortDst uint64
}

func NewStats() *Stats {
	return &Stats{start: time.Now()}
}

func (s *Stats) IncPackets() { atomic.AddUint64(&s.packets, 1) }
func (s *Stats) IncFlow()    { atomic.AddUint64(&s.flows, 1) }
func (s *Stats) IncTCP()     { atomic.AddUint64(&s.tcp, 1) }
func (s *Stats) IncUDP()     { atomic.AddUint64(&s.udp, 1) }
func (s *Stats) IncICMP()    { atomic.AddUint64(&s.icmp, 1) }
func (s *Stats) IncDNS()     { atomic.AddUint64(&s.dns, 1) }
func (s *Stats) IncARP()     { atomic.AddUint64(&s.arp, 1) }

func (s *Stats) ObservePorts(src, dst uint16) {
	// Very lightweight "top" tracking: keep last observed. (Can be upgraded later.)
	atomic.StoreUint64(&s.topPortSrc, uint64(src))
	atomic.StoreUint64(&s.topPortDst, uint64(dst))
}

func (s *Stats) Snapshot(flows *FlowTracker) string {
	uptime := time.Since(s.start).Truncate(time.Second)
	p := atomic.LoadUint64(&s.packets)
	fl := atomic.LoadUint64(&s.flows)
	tcp := atomic.LoadUint64(&s.tcp)
	udp := atomic.LoadUint64(&s.udp)
	icmp := atomic.LoadUint64(&s.icmp)
	dns := atomic.LoadUint64(&s.dns)
	arp := atomic.LoadUint64(&s.arp)
	srcp := atomic.LoadUint64(&s.topPortSrc)
	dstp := atomic.LoadUint64(&s.topPortDst)

	top := flows.TopN(3)

	s := fmt.Sprintf("[stats] uptime=%s packets=%d flows=%d tcp=%d udp=%d icmp=%d dns=%d arp=%d last_ports=%d->%d",
		uptime, p, fl, tcp, udp, icmp, dns, arp, srcp, dstp,
	)
	if len(top) > 0 {
		s += "\n  top_flows:"
		for _, t := range top {
			s += fmt.Sprintf("\n    %s (%d)", t.Flow, t.Count)
		}
	}
	return s
}
