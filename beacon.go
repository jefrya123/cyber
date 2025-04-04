package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	iface           = "eth0"            // Network interface to capture packets
	snapshotLen     = int32(1600)       // Snapshot length for packet capture
	promiscuous     = true              // Set promiscuous mode
	timeout         = pcap.BlockForever // Timeout
	dnsPort         = "udp port 53"     // BPF filter for DNS traffic
	beaconInterval  = 10 * time.Second  // Time window to monitor for beaconing
	beaconThreshold = 5                 // Number of queries within the interval to trigger an alert
)

var dnsQueries = make(map[string][]time.Time)

func main() {
	handle, err := pcap.OpenLive(iface, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(dnsPort); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, _ := dnsLayer.(*layers.DNS)
	if dns.QR { // Only process DNS queries
		return
	}

	for _, query := range dns.Questions {
		domain := string(query.Name)

		now := time.Now()
		dnsQueries[domain] = append(dnsQueries[domain], now)

		// Remove timestamps older than the beaconInterval
		var recentQueries []time.Time
		for _, t := range dnsQueries[domain] {
			if now.Sub(t) <= beaconInterval {
				recentQueries = append(recentQueries, t)
			}
		}
		dnsQueries[domain] = recentQueries

		if len(recentQueries) >= beaconThreshold {
			fmt.Printf("[ALERT] Potential DNS beaconing detected to domain: %s\n", domain)
		}
	}
}
