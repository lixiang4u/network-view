package handler

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lixiang4u/network-view/model"
	"github.com/shirou/gopsutil/net"
	"github.com/yusufpapurcu/wmi"
	"log"
	"os"
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
		pkt, err := handlerPacketInfo(packet)
		if err != nil {
			log.Println("[ErrorLayer]", err.Error())
			continue
		}
		showPacketLog(pkt)

	}
}

func handlerPacketInfo(packet gopacket.Packet) (model.Packet, gopacket.ErrorLayer) {
	var parsedPacket = model.Packet{
		Meta: model.Meta{
			Timestamp:      packet.Metadata().Timestamp,
			Length:         packet.Metadata().Length,
			InterfaceIndex: packet.Metadata().InterfaceIndex,
		},
		Ethernet: model.Ethernet{},
		IPv4:     model.IPv4{},
		IPv6:     model.IPv6{},
		TCP:      model.TCP{},
		UDP:      model.UDP{},
	}

	var ethernetLayer = packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		var layer = ethernetLayer.(*layers.Ethernet)
		parsedPacket.IsEthernet = true
		parsedPacket.Ethernet.EthernetType = layer.EthernetType
		parsedPacket.Ethernet.SrcMAC = layer.SrcMAC
		parsedPacket.Ethernet.DstMAC = layer.DstMAC
		parsedPacket.Ethernet.Payload = layer.Payload
	}
	var ipv4Layer = packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		var layer = ipv4Layer.(*layers.IPv4)
		parsedPacket.IsIPv4 = true
		parsedPacket.IPv4.Id = layer.Id
		parsedPacket.IPv4.Version = layer.Version
		parsedPacket.IPv4.DstIP = layer.DstIP
		parsedPacket.IPv4.SrcIP = layer.SrcIP
		parsedPacket.IPv4.Protocol = layer.Protocol
	}
	var ipv6Layer = packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		var layer = ipv6Layer.(*layers.IPv6)
		parsedPacket.IsIPv6 = true
		parsedPacket.IPv6.NextHeader = layer.NextHeader
		parsedPacket.IPv6.Version = layer.Version
		parsedPacket.IPv6.DstIP = layer.DstIP
		parsedPacket.IPv6.SrcIP = layer.SrcIP
	}
	var tcpLayer = packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		var layer = tcpLayer.(*layers.TCP)
		parsedPacket.IsTCP = true
		parsedPacket.TCP.SrcPort = layer.SrcPort
		parsedPacket.TCP.DstPort = layer.DstPort
		parsedPacket.TCP.FIN = layer.FIN
		parsedPacket.TCP.SYN = layer.SYN
		parsedPacket.TCP.RST = layer.RST
		parsedPacket.TCP.PSH = layer.PSH
		parsedPacket.TCP.ACK = layer.ACK
		parsedPacket.TCP.URG = layer.URG
		parsedPacket.TCP.ECE = layer.ECE
		parsedPacket.TCP.CWR = layer.CWR
		parsedPacket.TCP.NS = layer.SYN
	}
	var udpLayer = packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		var layer = udpLayer.(*layers.UDP)
		parsedPacket.IsUDP = true
		parsedPacket.UDP.SrcPort = layer.SrcPort
		parsedPacket.UDP.DstPort = layer.DstPort
		parsedPacket.UDP.Length = layer.Length
	}
	var dnsLayer = packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		var layer = dnsLayer.(*layers.DNS)
		parsedPacket.IsDNS = true
		parsedPacket.DNS.ID = layer.ID
		parsedPacket.DNS.OpCode = layer.OpCode
		parsedPacket.DNS.QR = layer.QR
		parsedPacket.DNS.ResponseCode = layer.ResponseCode
		parsedPacket.DNS.Questions = layer.Questions
		parsedPacket.DNS.Answers = layer.Answers
	}
	var arpLayer = packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		var layer = arpLayer.(*layers.ARP)
		parsedPacket.IsARP = true
		parsedPacket.ARP.AddrType = layer.AddrType
		parsedPacket.ARP.Protocol = layer.Protocol
		parsedPacket.ARP.Operation = layer.Operation
		parsedPacket.ARP.SourceHwAddress = layer.SourceHwAddress
		parsedPacket.ARP.SourceProtAddress = layer.SourceProtAddress
		parsedPacket.ARP.DstHwAddress = layer.DstHwAddress
		parsedPacket.ARP.DstProtAddress = layer.DstProtAddress
	}

	return parsedPacket, packet.ErrorLayer()
}

func showPacketLog(pkt model.Packet) {
	var protocol string
	var src string
	var dst string
	var processName string
	if pkt.IsIPv4 {
		src = fmt.Sprintf("%s:%d", pkt.IPv4.SrcIP.String(), pkt.TCP.SrcPort)
		dst = fmt.Sprintf("%s:%d", pkt.IPv4.DstIP.String(), pkt.TCP.DstPort)
		process, err := findProcessById(findConnectionPid(uint32(pkt.TCP.SrcPort), uint32(pkt.TCP.DstPort)))
		if err == nil {
			processName = fmt.Sprintf("[%s] [%s]", process.Name, pkt.TCP.DstPort.String())
		}
		protocol = pkt.IPv4.Protocol.String()
	}
	if pkt.IsIPv6 {
		src = fmt.Sprintf("%s:%d", pkt.IPv6.SrcIP.String(), pkt.TCP.SrcPort)
		dst = fmt.Sprintf("%s:%d", pkt.IPv6.DstIP.String(), pkt.TCP.DstPort)
		process, err := findProcessById(findConnectionPid(uint32(pkt.TCP.SrcPort), uint32(pkt.TCP.DstPort)))
		if err == nil {
			processName = fmt.Sprintf("[%s] [%s]", process.Name, pkt.TCP.DstPort.String())
		}
		protocol = pkt.IPv6.NextHeader.String()
	}
	if pkt.IsUDP {
		src = fmt.Sprintf("%s:%d", pkt.IPv4.SrcIP.String(), pkt.UDP.SrcPort)
		dst = fmt.Sprintf("%s:%d", pkt.IPv4.DstIP.String(), pkt.UDP.DstPort)
		process, err := findProcessById(findConnectionPid(uint32(pkt.UDP.SrcPort), uint32(pkt.UDP.DstPort)))
		if err == nil {
			processName = fmt.Sprintf("[%s] [%s]", process.Name, pkt.UDP.DstPort.String())
		}
		protocol = "UDP"
	}
	if pkt.IsDNS {
		log.Println("[ResponseCode]", pkt.DNS.ResponseCode.String())
		for _, question := range pkt.DNS.Questions {
			log.Println("[Questions]", string(question.Name), question.Type.String(), question.Class.String())
		}
		for _, answer := range pkt.DNS.Answers {
			log.Println("[Answers]", string(answer.Name), answer.Type.String(), answer.Class.String(), answer.IP.String())
		}
		src = fmt.Sprintf("%s:%d", pkt.IPv4.SrcIP.String(), pkt.UDP.SrcPort)
		dst = fmt.Sprintf("%s:%d", pkt.IPv4.DstIP.String(), pkt.UDP.DstPort)
		process, err := findProcessById(findConnectionPid(uint32(pkt.UDP.SrcPort), uint32(pkt.UDP.DstPort)))
		if err == nil {
			processName = fmt.Sprintf("[%s] [%s]", process.Name, pkt.UDP.DstPort.String())
		}
		protocol = "DNS"
	}
	if len(protocol) == 0 {
		return
	}

	log.Println(fmt.Sprintf(
		"[%s] [%s] %s -> %s %s",
		pkt.Meta.Timestamp.Format("2006-01-02 15:04:05"),
		protocol,
		src,
		dst,
		processName,
	))
}

func getNetConnections() []net.ConnectionStat {
	var conn = make([]net.ConnectionStat, 0)
	conn, _ = net.Connections("inet")
	return conn
}

func findConnectionPid(srcPort, dstPort uint32) (pid int32) {
	if srcPort == 0 && dstPort == 0 {
		return
	}
	for _, conn := range getNetConnections() {
		if conn.Laddr.Port == srcPort && conn.Raddr.Port == dstPort {
			pid = conn.Pid
			break
		}
		if conn.Laddr.Port == dstPort && conn.Raddr.Port == srcPort {
			pid = conn.Pid
			break
		}
	}
	return pid
}

func findProcessById(pid int32) (process model.Win32_Process, err error) {
	if pid == 0 {
		return
	}
	var where = fmt.Sprintf("WHERE ProcessId='%d'", pid)
	var result []model.Win32_Process
	err = wmi.Query(wmi.CreateQuery(&result, where), &result)
	if err != nil {
		return process, err
	}
	return result[0], nil
}

func ToJson(v interface{}) string {
	buf, _ := json.MarshalIndent(v, "", "\t")
	_ = os.WriteFile(fmt.Sprintf("%d.json", time.Now().Unix()), buf, 0777)
	return string(buf)
}
