package main

import (
	"flag"
	"fmt"
	"packet-sniffer-go/internal/sniffer"
)

func main() {
	iface := flag.String("i", "eth0", "interface to sniff on")
	flag.Parse()

	fmt.Printf("[*] Starting Packet Sniffer on %s...
", *iface)
	engine := &sniffer.SnifferEngine{Interface: *iface}
	engine.Start()
}