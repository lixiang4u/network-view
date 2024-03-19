package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lixiang4u/network-view/model"
	"github.com/shirou/gopsutil/net"
	"github.com/yusufpapurcu/wmi"
	"log"
	stdNet "net"
	"os"
	"strings"
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
		stats := getNetConnections()
		go func(packet gopacket.Packet, stats []net.ConnectionStat) {
			// Process packet here
			pkt, err := handlerPacketInfo(packet)
			if err != nil {
				log.Println("[ErrorLayer]", err.Error())
				return
			}
			showPacketLog(pkt, &stats)
		}(packet, stats)

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

func showPacketLog(pkt model.Packet, stats *[]net.ConnectionStat) {
	var protocol string
	var processName string
	var pid int32
	var netRequest string
	if pkt.IsIPv4 {
		netRequest = parseTcpRequestSrcDst(pkt.IPv4.SrcIP, pkt.IPv4.DstIP, pkt.TCP)
		pid = findConnectionPid(uint32(pkt.TCP.SrcPort), uint32(pkt.TCP.DstPort), stats)
		process, _ := findProcessById(pid)
		processName = fmt.Sprintf("[%s,%d] [%s]", process.Name, pid, parsePortName(pkt.TCP.SrcPort, pkt.TCP.DstPort))
		protocol = pkt.IPv4.Protocol.String()
	}
	if pkt.IsIPv6 {
		netRequest = parseTcpRequestSrcDst(pkt.IPv6.SrcIP, pkt.IPv6.DstIP, pkt.TCP)
		pid = findConnectionPid(uint32(pkt.TCP.SrcPort), uint32(pkt.TCP.DstPort), stats)
		process, _ := findProcessById(pid)
		processName = fmt.Sprintf("[%s,%d] [%s]", process.Name, pid, parsePortName(pkt.TCP.SrcPort, pkt.TCP.DstPort))
		protocol = pkt.IPv6.NextHeader.String()
	}
	if pkt.IsUDP {
		netRequest = parseUdpRequestSrcDst(pkt.IPv4.SrcIP, pkt.IPv4.DstIP, pkt.IPv6.SrcIP, pkt.IPv6.DstIP, pkt.UDP)
		pid = findConnectionPid(uint32(pkt.UDP.SrcPort), uint32(pkt.UDP.DstPort), stats)
		process, _ := findProcessById(pid)
		processName = fmt.Sprintf("[%s,%d] [%s]", process.Name, pid, parsePortName(pkt.UDP.DstPort, pkt.UDP.DstPort))
		protocol = "UDP"
	}
	if pkt.IsDNS {
		var extra string
		extra = fmt.Sprintf("%s\tDNS ResponseCode: %s\r\n", extra, pkt.DNS.ResponseCode.String())
		for _, question := range pkt.DNS.Questions {
			//log.Println("[Questions]", string(question.Name), question.Type.String(), question.Class.String())
			extra = fmt.Sprintf("%s\tDNS Question: %s %s %s\r\n", extra, string(question.Name), question.Type.String(), question.Class.String())
		}
		for _, answer := range pkt.DNS.Answers {
			//log.Println("[Answers]", string(answer.Name), answer.Type.String(), answer.Class.String(), answer.IP.String())
			extra = fmt.Sprintf("%s\tDNS Answer:    %s %s %s %s\r\n", extra, string(answer.Name), answer.Type.String(), answer.Class.String(), answer.IP.String())
		}

		netRequest = parseUdpRequestSrcDst(pkt.IPv4.SrcIP, pkt.IPv4.DstIP, pkt.IPv6.SrcIP, pkt.IPv6.DstIP, pkt.UDP)
		pid = findConnectionPid(uint32(pkt.UDP.SrcPort), uint32(pkt.UDP.DstPort), stats)
		process, _ := findProcessById(pid)
		processName = fmt.Sprintf(
			"[%s,%d] [%s]\r\n%s",
			process.Name,
			pid,
			parsePortName(pkt.UDP.DstPort, pkt.UDP.SrcPort),
			strings.TrimRight(extra, "\r\n"),
		)

		protocol = "DNS"
	}
	if len(protocol) == 0 {
		return
	}

	log.Println(fmt.Sprintf(
		"[%s] [%s] %s %s",
		pkt.Meta.Timestamp.Format("2006-01-02 15:04:05"),
		protocol,
		netRequest,
		processName,
	))
}

func getNetConnections() []net.ConnectionStat {
	var conn = make([]net.ConnectionStat, 0)
	conn, _ = net.Connections("inet")
	//ToJson(conn)
	return conn
}

func findConnectionPid(srcPort, dstPort uint32, stats *[]net.ConnectionStat) (pid int32) {
	if srcPort == 0 && dstPort == 0 {
		return
	}
	for _, conn := range *stats {
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
	if len(result) == 0 {
		return process, errors.New("no process found")
	}
	return result[0], nil
}

func parsePortName(port1, port2 interface{}) string {
	switch port1.(type) {
	case layers.TCPPort:
		if name, ok := layers.TCPPortNames[(port1.(layers.TCPPort))]; ok {
			return fmt.Sprintf("%d(%s)", port1, name)
		}
		if name, ok := layers.TCPPortNames[(port2.(layers.TCPPort))]; ok {
			return fmt.Sprintf("%d(%s)", port2, name)
		}
	case layers.UDPPort:
		if name, ok := layers.UDPPortNames[(port1.(layers.UDPPort))]; ok {
			return fmt.Sprintf("%d(%s)", port1, name)
		}
		if name, ok := layers.UDPPortNames[(port2.(layers.UDPPort))]; ok {
			return fmt.Sprintf("%d(%s)", port2, name)
		}
	}
	return ""
}

func parseTcpRequestSrcDst(srcIp, dstIp stdNet.IP, tcp model.TCP) string {
	var src string
	var dst string
	var dir string
	if dstIp.IsPrivate() {
		dst = fmt.Sprintf("%s:%d", srcIp.String(), tcp.SrcPort)
		src = fmt.Sprintf("%s:%d", dstIp.String(), tcp.DstPort)
		dir = "<-"
	} else {
		src = fmt.Sprintf("%s:%d", srcIp.String(), tcp.SrcPort)
		dst = fmt.Sprintf("%s:%d", dstIp.String(), tcp.DstPort)
		dir = "->"
	}
	return fmt.Sprintf("%s %s %s", src, dir, dst)
}

func parseUdpRequestSrcDst(srcIp4, dstIp4, srcIp6, dstIp6 stdNet.IP, udp model.UDP) string {
	var src string
	var dst string
	var dir string
	if len(srcIp4) > 0 {
		if srcIp4.IsPrivate() {
			dir = "->"
			src = fmt.Sprintf("%s:%d", srcIp4.String(), udp.SrcPort)
			dst = fmt.Sprintf("%s:%d", dstIp4.String(), udp.SrcPort)
		} else {
			dir = "<-"
			src = fmt.Sprintf("%s:%d", dstIp4.String(), udp.SrcPort)
			dst = fmt.Sprintf("%s:%d", srcIp4.String(), udp.SrcPort)
		}
	}
	if len(srcIp6) > 0 {
		if srcIp6.IsPrivate() {
			dir = "->"
			src = fmt.Sprintf("%s:%d", srcIp6.String(), udp.SrcPort)
			dst = fmt.Sprintf("%s:%d", dstIp6.String(), udp.SrcPort)
		} else {
			dir = "<-"
			src = fmt.Sprintf("%s:%d", dstIp6.String(), udp.SrcPort)
			dst = fmt.Sprintf("%s:%d", srcIp6.String(), udp.SrcPort)
		}
	}
	return fmt.Sprintf("%s %s %s", src, dir, dst)
}

func ToJson(v interface{}) string {
	buf, _ := json.MarshalIndent(v, "", "\t")
	_ = os.WriteFile(fmt.Sprintf("%d.json", time.Now().Unix()), buf, 0777)
	return string(buf)
}
