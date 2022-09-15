package main

import (
	"fmt"
	"log"
	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	// Setup Input
	// https://pkg.go.dev/github.com/google/gopacket/pcap#OpenOffline
	pcapFileHandle, pcapFileErr := pcap.OpenOffline("icmp.pcap")
	if pcapFileErr != nil {
		log.Fatal(pcapFileErr)
		return
	}
	
	// Setup Output
	// https://pkg.go.dev/github.com/google/gopacket/pcap#OpenLive
	pcapOutputHandle, pcapOutputErr := pcap.OpenLive("lo", math.MaxInt32, false, pcap.BlockForever)
	if pcapOutputErr != nil {
		log.Fatal(pcapFileErr)
		return
	}

	// Loop through all packets in pcapFileHandle
	packetSource := gopacket.NewPacketSource(pcapFileHandle, pcapFileHandle.LinkType())
	for packet := range packetSource.Packets() {
	
		fmt.Println(packet)
		
		// Write packet data to pcapOutputHandle
		if pcapOutputErr = pcapOutputHandle.WritePacketData(packet.Data()); pcapOutputErr != nil {
			fmt.Printf("[-] Error while sending: %s\n", pcapOutputErr.Error())
			return
		}
	}
	pcapFileHandle.Close()
	pcapOutputHandle.Close()
}
