# Usage Guide - Packet Sniffer Go

## Installation

### Prerequisites
- Go 1.18+
- libpcap-dev

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# macOS
brew install libpcap

# Build
git clone https://github.com/Brainfeed-1996/packet-sniffer-go.git
cd packet-sniffer-go
go build -o packet-sniffer-go main.go
```

## Basic Usage

### List Available Interfaces

```bash
./packet-sniffer-go -list
```

Output:
```
eth0	(Intel Corporation I210 Gigabit Network Connection)
lo	(Loopback)
wlan0	(Intel Corporation Wireless-AC 9260)
```

### Capture on Default Interface

```bash
sudo ./packet-sniffer-go
```

### Capture on Specific Interface

```bash
sudo ./packet-sniffer-go -i eth0
```

### Apply BPF Filter

```bash
# HTTPS traffic only
sudo ./packet-sniffer-go -i eth0 -f "tcp and port 443"

# Exclude SSH
sudo ./packet-sniffer-go -i eth0 -f "not port 22"

# ICMP only
sudo ./packet-sniffer-go -i eth0 -f "icmp"
```

## Advanced Usage

### Export to PCAP

```bash
sudo ./packet-sniffer-go -i eth0 -pcap capture.pcap
```

### Custom Statistics Interval

```bash
# Report every 10 seconds
sudo ./packet-sniffer-go -i eth0 -stats-every 10s
```

### Combine Options

```bash
sudo ./packet-sniffer-go \
    -i eth0 \
    -f "tcp and port 80" \
    -pcap http_traffic.pcap \
    -stats-every 30s
```

## Integration as Library

### Import as Go Module

```go
import "packet-sniffer-go/internal/sniffer"

func main() {
    cfg := sniffer.Config{
        Interface:   "eth0",
        BPF:         "tcp",
        PCAPOutPath: "output.pcap",
    }
    
    engine, err := sniffer.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()
    
    ctx := context.Background()
    engine.Run(ctx)
}
```

## Troubleshooting

### "Permission Denied"
```bash
# Run with sudo or set capabilities
sudo ./packet-sniffer-go
```

### "No Capture Interfaces Found"
- Check network interfaces: `ip link show`
- Install libpcap: `sudo apt-get install libpcap-dev`

### "BPF Filter Compilation Failed"
- Verify BPF syntax: `tcpdump -i eth0 -f "your filter"`
- Check filter is valid libpcap syntax

## Performance Tips

1. **Increase Snapshot Length**: `-snaplen 65535` for full packets
2. **Disable Promiscuous Mode**: `-promisc=false` for lower CPU
3. **Use Specific Filters**: BPF reduces processed packets
4. **Write to PCAP**: For later analysis, not real-time display
