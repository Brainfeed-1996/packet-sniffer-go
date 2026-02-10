package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"packet-sniffer-go/internal/sniffer"
)

func main() {
	var (
		iface     = flag.String("i", "", "interface to sniff on (empty = auto / first)")
		listIfs   = flag.Bool("list", false, "list available capture interfaces and exit")
		bpf       = flag.String("f", "", "BPF filter (e.g. 'tcp and port 443')")
		snaplen   = flag.Int("snaplen", 1600, "snapshot length")
		promisc   = flag.Bool("promisc", true, "promiscuous mode")
		pcapOut   = flag.String("pcap", "", "write captured packets to this pcap file")
		statsEach = flag.Duration("stats-every", 5*time.Second, "stats reporting interval")
	)
	flag.Parse()

	if *listIfs {
		ifs, err := sniffer.ListInterfaces()
		if err != nil {
			log.Fatal(err)
		}
		for _, it := range ifs {
			fmt.Printf("%s\t(%s)\n", it.Name, it.Description)
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	cfg := sniffer.Config{
		Interface:     *iface,
		BPF:           *bpf,
		SnapLen:       *snaplen,
		Promiscuous:   *promisc,
		PCAPOutPath:   *pcapOut,
		StatsInterval: *statsEach,
	}

	engine, err := sniffer.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	fmt.Printf("[*] packet-sniffer-go starting (iface=%q, filter=%q)\n", engine.InterfaceName(), cfg.BPF)
	if err := engine.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
