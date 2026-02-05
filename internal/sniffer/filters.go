package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
)

type FlowTracker struct {
	Connections map[string]int
}

func NewFlowTracker() *FlowTracker {
	return &FlowTracker{Connections: make(map[string]int)}
}

func (f *FlowTracker) Track(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	if netLayer != nil {
		flow := netLayer.NetworkFlow()
		f.Connections[flow.String()]++
		if f.Connections[flow.String()] % 100 == 0 {
			fmt.Printf("[!] High volume flow detected: %s (%d packets)
", flow, f.Connections[flow.String()])
		}
	}
}