package main

import (
	"fmt"
	"log"
	"time"
)

// Mock packet structure for demonstration if pcap is not present
type Packet struct {
	SourceIP      string
	DestinationIP string
	Protocol      string
	Payload       string
	Timestamp     time.Time
}

func main() {
	fmt.Println("Starting Packet Sniffer (Simulation Mode)...")
	fmt.Println("Listening on interface eth0...")

	// Simulating packet capture loop
	packets := []Packet{
		{"192.168.1.105", "142.250.184.206", "TCP", "GET / HTTP/1.1", time.Now()},
		{"10.0.0.5", "192.168.1.1", "UDP", "DNS Query", time.Now().Add(100 * time.Millisecond)},
		{"192.168.1.105", "104.21.55.2", "TCP", "ACK", time.Now().Add(200 * time.Millisecond)},
	}

	for _, p := range packets {
		fmt.Printf("[%s] %s -> %s [%s] Length: %d\n", 
			p.Timestamp.Format("15:04:05.000"), 
			p.SourceIP, 
			p.DestinationIP, 
			p.Protocol, 
			len(p.Payload))
		time.Sleep(500 * time.Millisecond)
	}
	
	fmt.Println("Capture stopped.")
}
