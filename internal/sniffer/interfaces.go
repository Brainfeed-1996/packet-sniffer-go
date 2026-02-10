package sniffer

import "github.com/google/gopacket/pcap"

type InterfaceInfo struct {
	Name        string
	Description string
}

func ListInterfaces() ([]InterfaceInfo, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceInfo, 0, len(devs))
	for _, d := range devs {
		out = append(out, InterfaceInfo{Name: d.Name, Description: d.Description})
	}
	return out, nil
}
