# packet-sniffer-go

Local-first packet capture utility (defensive / DFIR oriented).

## Features

- Live capture with **gopacket/pcap**
- Optional **BPF filters** (e.g. `tcp and port 443`)
- Periodic **stats** (packets, protocol counters, top flows)
- Optional **PCAP export** (`-pcap out.pcap`)
- Safe defaults; no exfiltration, no remote control

## Quick start

List interfaces:

```bash
go run . -list
```

Capture on an interface with filter:

```bash
go run . -i "<iface>" -f "tcp and port 443" -stats-every 2s
```

Write to PCAP:

```bash
go run . -i "<iface>" -pcap capture.pcap
```

Stop: `Ctrl+C`.

## Notes

- On Windows, you typically need **Npcap** installed.
- Interface names are platform-specific; use `-list`.

## License

MIT
