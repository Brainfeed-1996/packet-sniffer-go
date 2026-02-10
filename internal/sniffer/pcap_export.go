package sniffer

import (
	"fmt"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func openPCAPWriter(path string, linkType layers.LinkType) (*os.File, *pcapgo.Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create pcap file: %w", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, linkType); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("pcap header: %w", err)
	}
	return f, w, nil
}
