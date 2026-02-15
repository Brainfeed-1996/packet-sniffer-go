# Architecture - Packet Sniffer Go

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Packet Sniffer Go                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────┐  │
│  │  Network    │───▶│    Engine     │───▶│   Statistics       │  │
│  │  Interface  │    │  (Capture)    │    │   Tracker          │  │
│  └─────────────┘    └──────────────┘    └────────────────────┘  │
│                           │                                      │
│                           ▼                                      │
│                    ┌──────────────┐                              │
│                    │   Flow       │                              │
│                    │   Tracker    │                              │
│                    └──────────────┘                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### Engine (`internal/sniffer/engine.go`)

**Responsibilities:**
- Open and configure pcap handle
- Capture packets in real-time
- Dispatch to protocol handlers

**Key Methods:**
```go
func New(cfg Config) (*Engine, error)
func (e *Engine) Run(ctx context.Context) error
func (e *Engine) Close()
func (e *Engine) handlePacket(packet gopacket.Packet)
```

### Config

```go
type Config struct {
    Interface     string        // Network interface name
    BPF           string        // BPF filter expression
    SnapLen       int           // Snapshot length
    Promiscuous   bool          // Promiscuous mode
    PCAPOutPath   string        // PCAP output file
    StatsInterval time.Duration // Stats reporting interval
}
```

### Stats (`internal/sniffer/stats.go`)

**Counters:**
- `packets`: Total packets captured
- `flows`: Unique flows detected
- `tcp`, `udp`, `icmp`, `dns`, `arp`: Protocol counters
- `topPortSrc`, `topPortDst`: Last seen ports

### FlowTracker (`internal/sniffer/filters.go`)

Tracks network flows and provides top-N statistics.

```go
type FlowTracker struct {
    counts map[string]uint64
    hotEveryN uint64
}

func (f *FlowTracker) Track(flow string)
func (f *FlowTracker) TopN(n int) []FlowTop
```

## Packet Processing Pipeline

```
1. Capture (pcap)
   ↓
2. Parse (gopacket)
   ↓
3. Protocol Detection
   ├─ TCP → Port tracking
   ├─ UDP → Port tracking
   ├─ ICMP → ICMP counter
   ├─ DNS → DNS counter
   └─ ARP → ARP counter
   ↓
4. Flow Tracking
   ↓
5. Statistics Update
```

## File Structure

```
packet-sniffer-go/
├── main.go                          # CLI entry point
├── internal/sniffer/
│   ├── engine.go                    # Core capture engine
│   ├── stats.go                      # Statistics tracking
│   ├── filters.go                    # Flow tracking
│   ├── interfaces.go                 # Interface listing
│   ├── pcap_export.go               # PCAP file writing
│   └── filters_test.go              # Tests
├── README.md
├── ARCHITECTURE.md
├── FEATURES.md
└── USAGE.md
```
