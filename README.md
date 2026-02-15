# Packet Sniffer Go

A high-performance packet sniffer written in Go using the **gopacket** library.

## 🔍 Overview

A lightweight, production-ready packet capture and analysis tool supporting:
- Real-time packet capture on network interfaces
- Protocol analysis (TCP, UDP, ICMP, DNS, ARP)
- Flow tracking and statistics
- PCAP file export
- BPF filtering

## 🚀 Quick Start

```bash
# List available interfaces
./packet-sniffer-go -list

# Capture on interface eth0
./packet-sniffer-go -i eth0

# Capture with BPF filter
./packet-sniffer-go -i eth0 -f "tcp and port 443"

# Export to PCAP
./packet-sniffer-go -i eth0 -pcap output.pcap
```

## 📦 Installation

```bash
git clone https://github.com/Brainfeed-1996/packet-sniffer-go.git
cd packet-sniffer-go
go build -o packet-sniffer-go main.go
```

## ⚙️ Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | auto | Network interface to capture on |
| `-list` | false | List available interfaces |
| `-f` | "" | BPF filter expression |
| `-snaplen` | 1600 | Snapshot length in bytes |
| `-promisc` | true | Promiscuous mode |
| `-pcap` | "" | PCAP output file path |
| `-stats-every` | 5s | Statistics reporting interval |

## 📖 Documentation

- [Architecture](ARCHITECTURE.md) - System design
- [Features](FEATURES.md) - Feature list
- [Usage](USAGE.md) - Detailed usage guide

## 🔧 Building

```bash
# Standard build
go build -o packet-sniffer-go main.go

# With optimization
go build -ldflags="-s -w" -o packet-sniffer-go main.go
```

## 📝 License

MIT License
