# Packet Sniffer (Go)

A professional-grade network traffic analyzer leveraging the speed of Go and the depth of libpcap.

## 📊 Flow Tracking
The engine now includes a **Flow Tracker** that monitors network flows in real-time to identify potential DDoS patterns or large data exfiltrations.

## 🛠️ Key Capabilities
- **BPF Filtering**: Support for Berkeley Packet Filter syntax.
- **Protocol Decoding**: Ethernet, IPv4, TCP, UDP, and ICMP support.
- **Flow Analysis**: Real-time connection mapping and volume alerting.

## 🚀 Execution
```bash
go build -o sniffer
sudo ./sniffer -i eth0
```