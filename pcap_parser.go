package main

import (
	"fmt"
	"log"
	"math"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	// Setup Input
	// https://pkg.go.dev/github.com/google/gopacket/pcap#OpenOffline
	pcapFileHandle, pcapFileErr := pcap.OpenOffline("test.pcap")
	if pcapFileErr != nil {
		log.Fatal(pcapFileErr)
		return
	}

	// Setup Output
	// https://pkg.go.dev/github.com/google/gopacket/pcap#OpenLive
	pcapOutputHandle, pcapOutputErr := pcap.OpenLive("lo", math.MaxInt32, false, pcap.BlockForever)
	if pcapOutputErr != nil {
		log.Fatal(pcapOutputErr)
		return
	}

	// Loop through all packets in pcapFileHandle
	var previousTimestamp time.Time
	isFirstPacket := true
	for packet := range gopacket.NewPacketSource(pcapFileHandle, pcapFileHandle.LinkType()).Packets() {

		// Sleeps for the duration between this packet's and the previous packet's (Unless its the first packet, then no sleep)
		if isFirstPacket {
			isFirstPacket = false
		} else {
			time.Sleep(packet.Metadata().Timestamp.Sub(previousTimestamp))
		}
		previousTimestamp = packet.Metadata().Timestamp

		// Write packet data to pcapOutputHandle
		if pcapOutputErr = pcapOutputHandle.WritePacketData(packet.Data()); pcapOutputErr != nil {
			fmt.Printf("[-] Error while sending: %s\n", pcapOutputErr.Error())
			return
		}
	}

	// Close handles
	pcapFileHandle.Close()
	pcapOutputHandle.Close()
}
