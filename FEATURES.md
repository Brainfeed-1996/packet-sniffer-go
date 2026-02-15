# Features - Packet Sniffer Go

## Core Features

### Packet Capture
- Real-time capture on any network interface
- Configurable snapshot length
- Promiscuous mode toggle
- Automatic interface selection

### Protocol Analysis
| Protocol | Support | Metrics |
|----------|---------|---------|
| TCP | ✅ | Packet count, port tracking |
| UDP | ✅ | Packet count, port tracking |
| ICMPv4 | ✅ | Packet count |
| ICMPv6 | ✅ | Packet count |
| DNS | ✅ | Query count |
| ARP | ✅ | Request count |

### Flow Tracking
- 5-tuple flow identification (srcIP, dstIP, srcPort, dstPort, protocol)
- Top-N flow statistics
- Real-time flow monitoring

### Export Capabilities
- PCAP file export (libpcap format)
- Real-time streaming to file

## Advanced Features

### BPF Filtering

Support for standard BPF expressions:

```bash
# TCP only on port 443
./packet-sniffer-go -i eth0 -f "tcp and port 443"

# HTTP traffic
./packet-sniffer-go -i eth0 -f "tcp and port 80"

# Exclude SSH
./packet-sniffer-go -i eth0 -f "not port 22"

# IPv6 only
./packet-sniffer-go -i eth0 -f "ip6"
```

### Statistics Reporting

Configurable interval reporting:
```
[stats] uptime=5m30s packets=1247 flows=89 tcp=1102 udp=145 icmp=0 dns=12 arp=0
  top_flows:
    192.168.1.100:54321->10.0.0.1:443 (45)
    192.168.1.100:54322->10.0.0.1:443 (38)
    192.168.1.100:54323->10.0.0.1:443 (31)
```

### Thread Safety
- Atomic counters for lock-free stats
- Mutex-protected flow tracking
- Concurrent packet processing

## Performance

| Metric | Value |
|--------|-------|
| Capture Rate | Up to 10 Gbps (with proper hardware) |
| Memory Usage | ~1MB baseline + flow tracking |
| CPU Usage | <5% on idle system |

## Limitations

- Requires root/administrator privileges
- PCAPng format not yet supported
- No packet payload storage (metadata only)
