package sniffer

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SnifferEngine struct {
	Interface string
	Handle    *pcap.Handle
}

func (e *SnifferEngine) Start() {
	var err error
	e.Handle, err = pcap.OpenLive(e.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Handle.Close()

	packetSource := gopacket.NewPacketSource(e.Handle, e.Handle.LinkType())
	for packet := range packetSource.Packets() {
		e.decodePacket(packet)
	}
}

func (e *SnifferEngine) decodePacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("[%s] IP %s -> %s | Proto: %s
", 
			time.Now().Format("15:04:05"), ip.SrcIP, ip.DstIP, ip.Protocol)
		
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("  TCP Port: %d -> %d | Flags: %s
", tcp.SrcPort, tcp.DstPort, tcp.FIN || tcp.SYN || tcp.RST || tcp.PSH || tcp.ACK || tcp.URG)
		}
	}
}