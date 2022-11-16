package main

import (
	"log"
	"math"
	"time"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketTime struct {
	packet gopacket.Packet
	time   time.Duration
}

func getInterface(allowLoopback bool) string {

	// Find all the interfaces
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
		return ""
	}
	
	// Loop through them until a non-loopback interface is found, then return it
	for _, iface := range ifaces {
		if (allowLoopback || (iface.Name != "lo" && !strings.Contains(iface.Name, "Loopback"))) {
			return iface.Name
		}
	}
	
	// Somehow no interfaces were found, so return empty
	log.Fatal("No non-loopback interfaces exist!")
	return ""
}

func replayPCAP(filepath string) {

	// Set up array for storing packets, as this with let the packets be stored in memory which will make outputting faster (about 0.1 seconds in test.pcap)
	packetTimes := []PacketTime{}

	// Setup Input
	// https://pkg.go.dev/github.com/google/gopacket/pcap#OpenOffline
	pcapFileHandle, pcapFileErr := pcap.OpenOffline(filepath)
	if pcapFileErr != nil {
		log.Fatal(pcapFileErr)
		return
	}

	// Loop through all packets in pcapFileHandle
	var previousTimestamp time.Time
	isFirstPacket := true
	for packet := range gopacket.NewPacketSource(pcapFileHandle, pcapFileHandle.LinkType()).Packets() {

		// Set duration between this packet's and the previous packet's (Unless its the first packet, then 0)
		var duration time.Duration
		if isFirstPacket {
			isFirstPacket = false
			duration = 0
		} else {
			duration = packet.Metadata().Timestamp.Sub(previousTimestamp)
		}

		packetTimes = append(packetTimes, PacketTime{packet, duration})

		previousTimestamp = packet.Metadata().Timestamp
	}
	pcapFileHandle.Close()

	// Setup Output
	// https://pkg.go.dev/github.com/google/gopacket/pcap#OpenLive
	pcapOutputHandle, pcapOutputErr := pcap.OpenLive(getInterface(false), math.MaxInt32, false, pcap.BlockForever)
	if pcapOutputErr != nil {
		log.Fatal(pcapOutputErr)
		return
	}

	// Write the packets out
	for _, packetTime := range packetTimes {

		// Sleeps for the duration between this packet's and the previous packet's (Unless its the first packet, then no sleep)
		time.Sleep(packetTime.time)

		// Write packet data to pcapOutputHandle
		if pcapOutputErr = pcapOutputHandle.WritePacketData(packetTime.packet.Data()); pcapOutputErr != nil {
			log.Fatal("[-] Error while sending: %s\n", pcapOutputErr.Error())
			return
		}
	}
	pcapOutputHandle.Close()
}

func main() {
	replayPCAP("icmp.pcap")
}
