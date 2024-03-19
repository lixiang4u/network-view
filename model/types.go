package model

import (
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

type Meta struct {
	// Timestamp is the time the packet was captured, if that is known.
	Timestamp time.Time
	// Length is the size of the original packet.  Should always be >=
	// CaptureLength.
	Length int
	// InterfaceIndex
	InterfaceIndex int
}

// Ethernet 参考：layers.Ethernet
type Ethernet struct {
	SrcMAC       net.HardwareAddr
	DstMAC       net.HardwareAddr
	EthernetType layers.EthernetType
	Payload      []byte
}

// IPv4 参考：layers.IPv4
type IPv4 struct {
	Version  uint8
	Id       uint16
	Protocol layers.IPProtocol // IPProtocol is an enumeration of IP protocol values, and acts as a decoder for any type it supports.
	SrcIP    net.IP
	DstIP    net.IP
}

// IPv6 参考：layers.IPv6
type IPv6 struct {
	Version    uint8
	NextHeader layers.IPProtocol //下一首部字段，指示紧跟在IPv6首部后面的首部的类型，类似于IPv4协议中的Protocol字段。
	SrcIP      net.IP
	DstIP      net.IP
}

// TCP 参考：layers.TCP
type TCP struct {
	SrcPort layers.TCPPort
	DstPort layers.TCPPort

	FIN,
	SYN,
	RST,
	PSH,
	ACK,
	URG,
	ECE,
	CWR,
	NS bool
}

// UDP 参考：layers.UDP
type UDP struct {
	SrcPort layers.UDPPort
	DstPort layers.UDPPort
	Length  uint16
}

// DNS 参考：layers.DNS
type DNS struct {
	ID           uint16
	QR           bool
	OpCode       layers.DNSOpCode
	ResponseCode layers.DNSResponseCode
	// Entries
	Questions []layers.DNSQuestion
	Answers   []layers.DNSResourceRecord
	// buffer for doing name decoding.  We use a single reusable buffer to avoid
	// name decoding on a single object via multiple DecodeFromBytes calls
	// requiring constant allocation of small byte slices.
	buffer []byte
}

type ARP struct {
	AddrType          layers.LinkType
	Protocol          layers.EthernetType
	Operation         uint16
	SourceHwAddress   []byte
	SourceProtAddress []byte
	DstHwAddress      []byte
	DstProtAddress    []byte
}

type Packet struct {
	Meta     Meta
	Ethernet Ethernet
	IPv4     IPv4
	IPv6     IPv6
	TCP      TCP
	UDP      UDP
	DNS      DNS
	ARP      ARP

	IsEthernet bool
	IsIPv4     bool
	IsIPv6     bool
	IsTCP      bool
	IsUDP      bool
	IsDNS      bool
	IsARP      bool
}

type Win32_Process struct {
	Caption             string
	CommandLine         string
	CreationDate        string
	CSName              string
	Description         string
	ExecutablePath      string
	ExecutionState      uint16
	Handle              string
	HandleCount         uint32
	KernelModeTime      uint64
	Name                string
	OSCreationClassName string
	OSName              string
	ParentProcessId     uint32
	Priority            uint32
	ProcessId           uint32
	SessionId           uint32
	Status              string
	TerminationDate     string
	ThreadCount         uint32
	UserModeTime        uint64
	WindowsVersion      string
}
