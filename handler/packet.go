package handler

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

func HandlePacketsLive(device string, snapshotLen int32, promiscuous bool, timeout time.Duration) {
	log.Println("[HandlerDevice]", device)

	// Open device
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Println("[OpenLive]", device, err.Error())
		return
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		handlerPacketInfo(packet)
	}
}

func handlerPacketInfo(packet gopacket.Packet) {
	//
}
