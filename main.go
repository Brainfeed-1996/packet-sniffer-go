// src/main.go - Enhanced Packet Sniffer with Statistics
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"packet-sniffer-go/internal/sniffer"
)

func main() {
	var (
		iface      = flag.String("i", "", "interface to sniff on (empty = auto / first)")
		listIfs    = flag.Bool("list", false, "list available capture interfaces and exit")
		bpf        = flag.String("f", "", "BPF filter (e.g. 'tcp and port 443')")
		snaplen    = flag.Int("snaplen", 1600, "snapshot length")
		promisc    = flag.Bool("promisc", true, "promiscuous mode")
		pcapOut    = flag.String("pcap", "", "write captured packets to this pcap file")
		statsEach  = flag.Duration("stats-every", 5*time.Second, "stats reporting interval")
		verbose    = flag.Bool("v", false, "verbose output (show packet details)")
		maxPackets = flag.Int("max", 0, "max packets to capture (0 = unlimited)")
	)
	flag.Parse()

	if *listIfs {
		ifs, err := sniffer.ListInterfaces()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%-20s %s\n", "INTERFACE", "DESCRIPTION")
		fmt.Printf("%-20s %s\n", strings.Repeat("─", 20), strings.Repeat("─", 50))
		for _, it := range ifs {
			desc := it.Description
			if desc == "" {
				desc = "No description"
			}
			fmt.Printf("%-20s %s\n", it.Name, desc)
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[*] Shutting down...")
		cancel()
	}()

	cfg := sniffer.Config{
		Interface:     *iface,
		BPF:            *bpf,
		SnapLen:        *snaplen,
		Promiscuous:    *promisc,
		PCAPOutPath:    *pcapOut,
		StatsInterval:  *statsEach,
		Verbose:        *verbose,
		MaxPackets:     *maxPackets,
	}

	engine, err := sniffer.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	fmt.Printf("[*] packet-sniffer-go v2.0 starting\n")
	fmt.Printf("[*] Interface: %q\n", engine.InterfaceName())
	fmt.Printf("[*] Filter: %q\n", cfg.BPF)
	if *pcapOut != "" {
		fmt.Printf("[*] PCAP output: %s\n", *pcapOut)
	}
	fmt.Printf("[*] Stats every: %v\n", *statsEach)
	fmt.Println(strings.Repeat("─", 50))

	if err := engine.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
