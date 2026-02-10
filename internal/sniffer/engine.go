package sniffer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Config struct {
	Interface     string
	BPF           string
	SnapLen       int
	Promiscuous   bool
	PCAPOutPath   string
	StatsInterval time.Duration
}

type Engine struct {
	cfg    Config
	handle *pcap.Handle
	w      io.WriteCloser
	pcapw  *pcapgo.Writer

	ifaceName string

	flows *FlowTracker
	stats *Stats

	mu sync.Mutex
}

func New(cfg Config) (*Engine, error) {
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 1600
	}
	if cfg.StatsInterval <= 0 {
		cfg.StatsInterval = 5 * time.Second
	}

	iface := cfg.Interface
	if iface == "" {
		// Heuristic: pick first device that has an IPv4/IPv6 address.
		devs, err := pcap.FindAllDevs()
		if err != nil {
			return nil, fmt.Errorf("pcap find devices: %w", err)
		}
		for _, d := range devs {
			if len(d.Addresses) == 0 {
				continue
			}
			iface = d.Name
			break
		}
		if iface == "" && len(devs) > 0 {
			iface = devs[0].Name
		}
		if iface == "" {
			return nil, errors.New("no capture interfaces found")
		}
	}

	h, err := pcap.OpenLive(iface, int32(cfg.SnapLen), cfg.Promiscuous, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open live (iface=%s): %w", iface, err)
	}

	e := &Engine{
		cfg:       cfg,
		handle:    h,
		ifaceName: iface,
		flows:     NewFlowTracker(100),
		stats:     NewStats(),
	}

	if cfg.BPF != "" {
		if err := e.handle.SetBPFFilter(cfg.BPF); err != nil {
			e.Close()
			return nil, fmt.Errorf("set BPF filter: %w", err)
		}
	}

	if cfg.PCAPOutPath != "" {
		w, pcapw, err := openPCAPWriter(cfg.PCAPOutPath, e.handle.LinkType())
		if err != nil {
			e.Close()
			return nil, err
		}
		e.w = w
		e.pcapw = pcapw
	}

	return e, nil
}

func (e *Engine) InterfaceName() string { return e.ifaceName }

func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle != nil {
		e.handle.Close()
		e.handle = nil
	}
	if e.w != nil {
		_ = e.w.Close()
		e.w = nil
		e.pcapw = nil
	}
}

func (e *Engine) Run(ctx context.Context) error {
	packetSource := gopacket.NewPacketSource(e.handle, e.handle.LinkType())
	packetSource.NoCopy = true

	ticker := time.NewTicker(e.cfg.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			fmt.Println(e.stats.Snapshot(e.flows))
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				// Timeout / EOF conditions vary by platform.
				if errors.Is(err, io.EOF) {
					return nil
				}
				continue
			}
			e.handlePacket(packet)
		}
	}
}

func (e *Engine) handlePacket(packet gopacket.Packet) {
	e.stats.IncPackets()

	if e.pcapw != nil {
		ci := packet.Metadata().CaptureInfo
		_ = e.pcapw.WritePacket(ci, packet.Data())
	}

	// L3
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		src, dst := netLayer.NetworkFlow().Endpoints()
		e.stats.IncFlow()
		e.flows.Track(netLayer.NetworkFlow().String())
		_ = src
		_ = dst
	}

	// Protocol counters + lightweight decode.
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		e.stats.IncTCP()
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			e.stats.ObservePorts(uint16(tcp.SrcPort), uint16(tcp.DstPort))
		}
		return
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		e.stats.IncUDP()
		if udp, ok := udpLayer.(*layers.UDP); ok {
			e.stats.ObservePorts(uint16(udp.SrcPort), uint16(udp.DstPort))
		}
		return
	}

	// ICMP
	if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		e.stats.IncICMP()
		return
	}

	// DNS
	if packet.Layer(layers.LayerTypeDNS) != nil {
		e.stats.IncDNS()
		return
	}

	// ARP
	if packet.Layer(layers.LayerTypeARP) != nil {
		e.stats.IncARP()
		return
	}

	// Fallback: attempt to detect basic IP family.
	if packet.NetworkLayer() != nil {
		switch packet.NetworkLayer().NetworkFlow().EndpointType() {
		case layers.EndpointIPv4, layers.EndpointIPv6:
			// ok
		default:
			_ = net.IP{}
		}
	}
}
